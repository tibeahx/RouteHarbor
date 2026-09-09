package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/auth"
	"github.com/tibeahx/OpenRHP/internal/config"
	"github.com/tibeahx/OpenRHP/internal/control"
	"github.com/tibeahx/OpenRHP/internal/model"
)

const apiStorageCanary = "API-STORED-PASSWORD-CANARY-PRIVATE"

func securityFixture(t testing.TB) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := config.NewStore(filepath.Join(dir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	c := store.Get()
	c.Sources = []model.Source{
		{
			ID:   "private-source",
			Name: "Private source",
			Type: "socks5",
			Settings: json.RawMessage(
				`{"server":"1.1.1.1","server_port":1080,"username":"test","password":"` + apiStorageCanary + `"}`,
			),
		},
	}
	if _, err = store.Replace(c.Revision, c); err != nil {
		t.Fatal(err)
	}
	tokens, err := auth.Open(filepath.Join(dir, "auth"))
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := tokens.Issue("read")
	if err != nil {
		t.Fatal(err)
	}
	journal, err := control.NewJournal(filepath.Join(dir, "operations"))
	if err != nil {
		t.Fatal(err)
	}
	runtime := control.New(store, adapter.NewManager(filepath.Join(dir, "engines")), journal)
	t.Cleanup(func() {
		runtime.Close()
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return &Server{Runtime: runtime, Tokens: tokens, AllowedHosts: []string{"gateway.test"}}, token
}

func FuzzAPIReadOnlySecurityAndConfigurationParser(f *testing.F) {
	s, token := securityFixture(f)
	handler := s.Handler()
	valid, err := json.Marshal(config.Defaults())
	if err != nil {
		f.Fatal(err)
	}
	for _, payload := range [][]byte{
		valid, []byte(`null`), []byte(`{"role":"gateway","role":"node"}`),
		[]byte(`{"sources":[{"settings":{"exec":"/bin/sh","password":"INPUT-CANARY"}}]}`),
		[]byte(strings.Repeat("[", 65) + strings.Repeat("]", 65)),
		bytes.Repeat([]byte("x"), config.MaxConfigBytes+1),
	} {
		f.Add(uint8(3), payload, "gateway.test", "", true)
	}
	f.Add(uint8(0), []byte(`{}`), "attacker.test", "http://attacker.test", true)
	f.Add(uint8(6), []byte(`{}`), "gateway.test", "null", false)
	routes := [][2]string{
		{"GET", "config"},
		{"GET", "sources"},
		{"GET", "status"},
		{"POST", "config/validate"},
		{"POST", "config/plan"},
		{"POST", "sources"},
		{"PUT", "config"},
		{"POST", "config/export"},
		{"POST", "probes"},
		{"POST", "transactions"},
		{"POST", "nodes/pair"},
		{"DELETE", "sources/private-source"},
		{"GET", "config/backups"},
		{"GET", "config/backups/invalid-id"},
		{"POST", "config/backups"},
		{"POST", "config/backups/invalid-id/restore"},
		{"DELETE", "config/backups/invalid-id"},
	}
	f.Fuzz(
		func(t *testing.T, route uint8, payload []byte, host, origin string, authenticated bool) {
			if len(payload) > config.MaxConfigBytes+1024 || len(host)+len(origin) > 8192 {
				t.Skip()
			}
			// Each input tests admission rather than exhausting a prior input's token bucket.
			s.limitMu.Lock()
			clear(s.limits)
			s.limitMu.Unlock()
			endpoint := routes[int(route)%len(routes)]
			request := httptest.NewRequest(
				endpoint[0],
				"http://gateway.test/api/v1/"+endpoint[1],
				bytes.NewReader(payload),
			)
			request.Host = host
			request.Header.Set("Origin", origin)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("If-Match", `"2"`)
			request.Header.Set("Idempotency-Key", "fuzz-request-key")
			if authenticated {
				request.Header.Set("Authorization", "Bearer "+token)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if bytes.Contains(response.Body.Bytes(), []byte(apiStorageCanary)) ||
				bytes.Contains(response.Body.Bytes(), []byte(token)) {
				t.Fatal("private stored secret escaped through ordinary API output")
			}
			if response.Body.Len() > 128<<10 {
				t.Fatal("small read-only API response exceeded its output budget")
			}
			current := s.Runtime.Store.Get()
			if current.Revision != 2 || len(current.Sources) != 1 ||
				len(s.Runtime.Journal.List()) != 0 {
				t.Fatal("read-only/unauthenticated request mutated configuration or queued work")
			}
		},
	)
}

type blockedDiscovery struct {
	CoverageService
	entered chan struct{}
	release chan struct{}
}

func (c *blockedDiscovery) Discover(ctx context.Context) any {
	c.entered <- struct{}{}
	select {
	case <-c.release:
	case <-ctx.Done():
	}
	return map[string]any{"nodes": []any{}}
}

type observedBody struct{ read atomic.Bool }

func (b *observedBody) Read([]byte) (int, error) {
	b.read.Store(true)
	return 0, io.EOF
}

func (b *observedBody) Close() error { return nil }

func TestRequestSaturationRejectsBeforeReadingBodyAndRecovers(t *testing.T) {
	s, token := securityFixture(t)
	discovery := &blockedDiscovery{entered: make(chan struct{}, 16), release: make(chan struct{})}
	s.Coverage = discovery
	handler := s.Handler()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	var pending sync.WaitGroup
	defer func() {
		cancel()
		pending.Wait()
	}()
	for range 16 {
		pending.Go(func() {
			request := httptest.NewRequest("POST", "http://gateway.test/api/v1/nodes/discover", nil).
				WithContext(ctx)
			request.Header.Set("Authorization", "Bearer "+token)
			handler.ServeHTTP(httptest.NewRecorder(), request)
		})
	}
	for range 16 {
		select {
		case <-discovery.entered:
		case <-ctx.Done():
			t.Fatal("requests did not fill the admission slots")
		}
	}
	body := &observedBody{}
	request := httptest.NewRequest("POST", "http://gateway.test/api/v1/config/validate", body)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests || body.read.Load() {
		t.Fatal("saturated request was admitted or consumed its body")
	}
	close(discovery.release)
	pending.Wait()
	request = httptest.NewRequest("GET", "http://gateway.test/api/v1/config", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatal("released admission slots did not recover")
	}
}

func TestFullJournalRejectsNewMutationButPreservesExistingAPIRetry(t *testing.T) {
	s, _ := securityFixture(t)
	_, token, err := s.Tokens.Issue("admin")
	if err != nil {
		t.Fatal(err)
	}
	handler := s.Handler()
	perform := func(id, revision, key string) *httptest.ResponseRecorder {
		body := `{"id":"` + id + `","name":"Direct candidate","type":"direct","settings":{}}`
		request := httptest.NewRequest(
			"POST",
			"http://gateway.test/api/v1/sources",
			strings.NewReader(body),
		)
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("If-Match", `"`+revision+`"`)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", key)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	first := perform("first-candidate", "2", "original-api-key")
	if first.Code != http.StatusOK {
		t.Fatal("initial mutation failed", first.Code)
	}
	var original control.Operation
	if err = json.Unmarshal(first.Body.Bytes(), &original); err != nil {
		t.Fatal(err)
	}
	for i := range 16 {
		_, _, err = s.Runtime.Journal.Begin("reserved", fmt.Sprint("reserved-key-", i), "hash")
		if errors.Is(err, control.ErrQueueFull) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	count := len(s.Runtime.Journal.List())
	second := perform("second-candidate", "3", "new-api-key")
	if second.Code != http.StatusTooManyRequests ||
		!strings.Contains(second.Body.String(), "operation_limit") {
		t.Fatal("unreserved API mutation was admitted")
	}
	retry := perform("first-candidate", "2", "original-api-key")
	var replay control.Operation
	if retry.Code != http.StatusOK || json.Unmarshal(retry.Body.Bytes(), &replay) != nil ||
		replay.ID != original.ID {
		t.Fatal("full storage discarded an existing API request's retry identity")
	}
	current := s.Runtime.Store.Get()
	if current.Revision != 3 || len(current.Sources) != 2 ||
		len(s.Runtime.Journal.List()) != count {
		t.Fatal("rejected or repeated mutation changed configuration or operation history")
	}
}

type observedStream struct {
	header  http.Header
	written chan struct{}
	once    sync.Once
	secret  string
	leaked  atomic.Bool
}

func (w *observedStream) Header() http.Header { return w.header }

func (w *observedStream) WriteHeader(int) {}

func (w *observedStream) Write(data []byte) (int, error) {
	if bytes.Contains(data, []byte(apiStorageCanary)) || bytes.Contains(data, []byte(w.secret)) {
		w.leaked.Store(true)
	}
	w.once.Do(func() { close(w.written) })
	return len(data), nil
}

func (w *observedStream) Flush() {}

func TestEventStreamsAreRedactedBoundedAndReleasedOnDisconnect(t *testing.T) {
	s, token := securityFixture(t)
	handler := s.Handler()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	var pending sync.WaitGroup
	defer func() {
		cancel()
		pending.Wait()
	}()
	var streams []*observedStream
	for range 8 {
		stream := &observedStream{
			header:  make(http.Header),
			written: make(chan struct{}),
			secret:  token,
		}
		streams = append(streams, stream)
		pending.Go(func() {
			request := httptest.NewRequest("GET", "http://gateway.test/api/v1/events", nil).
				WithContext(ctx)
			request.Header.Set("Authorization", "Bearer "+token)
			handler.ServeHTTP(stream, request)
		})
		select {
		case <-stream.written:
		case <-ctx.Done():
			t.Fatal("event stream did not emit its initial state")
		}
	}
	request := httptest.NewRequest("GET", "http://gateway.test/api/v1/events", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests ||
		!strings.Contains(response.Body.String(), "stream_limit") {
		t.Fatal("event stream capacity was not enforced")
	}
	cancel()
	pending.Wait()
	for _, stream := range streams {
		if stream.leaked.Load() {
			t.Fatal("event stream exposed stored credentials")
		}
	}
	if len(s.streams) != 0 || len(s.requests) != 0 {
		t.Fatal("disconnected streams retained admission slots")
	}
}

func TestEveryCredentialFormatStaysOutOfPublicReadsDiagnosticsAndEvents(t *testing.T) {
	const uuid = "facade00-ca11-4000-8000-0123456789ab"
	proxy := `"server":"1.1.1.1","server_port":1080,"username":"private-user","password":"` + apiStorageCanary + `"`
	endpoint := `"server":"1.1.1.1","server_port":443`
	for _, fixture := range []struct{ name, kind, settings, secret string }{
		{"socks", "socks5", `{` + proxy + `}`, apiStorageCanary},
		{"connect", "http-connect", `{` + proxy + `}`, apiStorageCanary},
		{"sing-socks", "sing-box", `{"type":"socks",` + proxy + `}`, apiStorageCanary},
		{"sing-http", "sing-box", `{"type":"http",` + proxy + `}`, apiStorageCanary},
		{"sing-vless", "sing-box", `{"type":"vless",` + endpoint + `,"uuid":"` + uuid + `","tls":{"enabled":true}}`, uuid},
		{"sing-trojan", "sing-box", `{"type":"trojan",` + endpoint + `,"password":"` + apiStorageCanary + `","tls":{"enabled":true}}`, apiStorageCanary},
		{"sing-shadowsocks", "sing-box", `{"type":"shadowsocks",` + endpoint + `,"method":"aes-128-gcm","password":"` + apiStorageCanary + `"}`, apiStorageCanary},
		{"xray-link", "xray", `{"link":"vless://` + uuid + `@vpn.example:443?security=tls"}`, uuid},
		{"xray-native", "xray", `{"outbound":{"protocol":"vless","settings":{"vnext":[{"address":"1.1.1.1","port":443,"users":[{"id":"` + uuid + `","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{}}}}`, uuid},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			s, token := securityFixture(t)
			c := s.Runtime.Store.Get()
			c.Sources[0].Type = fixture.kind
			c.Sources[0].Settings = json.RawMessage(fixture.settings)
			if _, err := s.Runtime.Store.Replace(c.Revision, c); err != nil {
				t.Fatal("invalid supported credential fixture", err)
			}
			handler := s.Handler()
			for _, path := range []string{"config", "sources", "status", "diagnostics", "engines"} {
				request := httptest.NewRequest("GET", "http://gateway.test/api/v1/"+path, nil)
				request.Header.Set("Authorization", "Bearer "+token)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != http.StatusOK ||
					strings.Contains(response.Body.String(), fixture.secret) ||
					strings.Contains(response.Body.String(), token) {
					t.Fatal("public endpoint failed or exposed credentials", path)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			done := make(chan struct{})
			defer func() {
				cancel()
				<-done
			}()
			stream := &observedStream{
				header:  make(http.Header),
				written: make(chan struct{}),
				secret:  fixture.secret,
			}
			go func() {
				defer close(done)
				request := httptest.NewRequest("GET", "http://gateway.test/api/v1/events", nil).
					WithContext(ctx)
				request.Header.Set("Authorization", "Bearer "+token)
				handler.ServeHTTP(stream, request)
			}()
			select {
			case <-stream.written:
			case <-ctx.Done():
				t.Fatal("event stream did not emit its initial state")
			}
			if stream.leaked.Load() {
				t.Fatal("credential escaped through SSE")
			}
		})
	}
}
