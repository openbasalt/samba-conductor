package i18n

import (
	"net/http/httptest"
	"slices"
	"testing"
)

func TestCatalogsMatch(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	en, pt := c.Keys("en"), c.Keys("pt-BR")
	if !slices.Equal(en, pt) {
		t.Fatalf("catalogs differ: %d en keys, %d pt-BR keys", len(en), len(pt))
	}
	for _, k := range en {
		if c.Raw("pt-BR", k) == "" || c.Raw("en", k) == "" {
			t.Errorf("%s: empty message", k)
		}
		if !slices.Equal(Placeholders(c.Raw("en", k)), Placeholders(c.Raw("pt-BR", k))) {
			t.Errorf("%s: placeholders differ between languages", k)
		}
	}
	if got := c.T("en", "pager.page", 3); got != "Page 3" {
		t.Errorf("substitution: %q", got)
	}
	if got := c.T("pt-BR", "no.such.key"); got != "[no.such.key]" {
		t.Errorf("missing key: %q", got)
	}
}

func TestNegotiate(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Language", "pt-BR,pt;q=0.9,en;q=0.8")
	if Negotiate(r, "", "en") != "pt-BR" {
		t.Error("Accept-Language pt")
	}
	if Negotiate(r, "en", "en") != "en" {
		t.Error("cookie wins")
	}
	r.Header.Set("Accept-Language", "de-DE")
	if Negotiate(r, "xx", "en") != "en" {
		t.Error("default")
	}
}
