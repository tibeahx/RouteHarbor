package api

import (
	"encoding/json"
	"strings"
	"testing"

	contract "github.com/tibeahx/RouteHarbor/api"
)

// Both directions matter: an undocumented write endpoint is an operational and
// security gap, while a documented endpoint without a handler misleads agents.
func TestPublicContractMatchesRegisteredRoutes(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(contract.OpenAPI, &doc); err != nil {
		t.Fatal(err)
	}
	routes := (&Server{}).routes()
	for path, methods := range doc.Paths {
		for method := range methods {
			switch method {
			case "get", "post", "put", "patch", "delete", "head", "options":
			default:
				continue
			}
			pattern := strings.ToUpper(method) + " /api/v1" + path
			if _, ok := routes[pattern]; !ok {
				t.Errorf("documented route has no handler: %s", pattern)
			}
			delete(routes, pattern)
		}
	}
	for pattern := range routes {
		t.Errorf("registered route is missing from OpenAPI: %s", pattern)
	}
}
