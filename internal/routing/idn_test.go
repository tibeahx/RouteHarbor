package routing

import (
	"strings"
	"testing"
)

func TestRegistryIDNEncodingAndBoundedMalformedRows(t *testing.T) {
	for _, tc := range []struct{ unicode, ascii string }{{"пример.рф", "xn--e1afmkfd.xn--p1ai"}, {"BÜCHER.example", "xn--bcher-kva.example"}, {"россия.рф", "xn--h1alffa9f.xn--p1ai"}, {"a_1.example", "a_1.example"}, {"mañana.example", "xn--maana-pta.example"}, {"faß.example", "xn--fa-hia.example"}} {
		d, e := registryDomain(tc.unicode)
		if e != nil || d != tc.ascii {
			t.Fatalf("%s => %s (%v), want %s", tc.unicode, d, e, tc.ascii)
		}
	}
	for _, d := range []string{"*.пример.рф", "example.com/path", "https://пример.рф", "e\u0301.example", "🙂.example", "a\u200d.example", "bad%20.example", "İ.example", "-пример.рф"} {
		if _, e := registryDomain(d); e == nil {
			t.Fatal("unsafe registry name accepted", d)
		}
	}
	feed := strings.Repeat("пример.рф\n", 2000) + "\"malformed.example\n"
	values, rejected, e := ParseRegistryDomains(strings.NewReader(feed))
	if e != nil || rejected != 1 || len(values) != 1 || values[0] != "xn--e1afmkfd.xn--p1ai" {
		t.Fatal(values, rejected, e)
	}
	if _, _, e := ParseRegistryDomains(
		strings.NewReader("example.com\nmalformed%20.example\n"),
	); e == nil {
		t.Fatal("excessive malformed proportion accepted")
	}
}
