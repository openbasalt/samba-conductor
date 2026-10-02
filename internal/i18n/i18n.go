// Package i18n holds the UI message catalogs (English and Brazilian
// Portuguese). Every user-facing string comes from here; templates call
// {{t "key"}}. Placeholders are {0}, {1}… in the order of the arguments.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

//go:embed locales/*.json
var files embed.FS

// Languages supported, the first is the fallback.
var Languages = []string{"en", "pt-BR"}

// Catalog maps language → key → message.
type Catalog struct {
	msgs map[string]map[string]string
}

// Load reads the embedded catalogs.
func Load() (*Catalog, error) {
	c := &Catalog{msgs: map[string]map[string]string{}}
	for _, lang := range Languages {
		b, err := files.ReadFile("locales/" + lang + ".json")
		if err != nil {
			return nil, err
		}
		m := map[string]string{}
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("i18n: %s: %w", lang, err)
		}
		c.msgs[lang] = m
	}
	return c, nil
}

// MustLoad panics on an invalid embedded catalog (a build defect).
func MustLoad() *Catalog {
	c, err := Load()
	if err != nil {
		panic(err)
	}
	return c
}

var placeholderRE = regexp.MustCompile(`\{(\d)\}`)

// T translates key into lang. A missing key renders as the key itself in
// brackets, so it is visible in tests and screenshots.
func (c *Catalog) T(lang, key string, args ...any) string {
	m, ok := c.msgs[lang]
	if !ok {
		m = c.msgs[Languages[0]]
	}
	s, ok := m[key]
	if !ok {
		s, ok = c.msgs[Languages[0]][key]
		if !ok {
			return "[" + key + "]"
		}
	}
	if len(args) == 0 {
		return s
	}
	return placeholderRE.ReplaceAllStringFunc(s, func(p string) string {
		i := int(p[1] - '0')
		if i < len(args) {
			return fmt.Sprint(args[i])
		}
		return p
	})
}

// Has reports whether key exists in the fallback language.
func (c *Catalog) Has(key string) bool {
	_, ok := c.msgs[Languages[0]][key]
	return ok
}

// Keys returns the keys of a language, sorted.
func (c *Catalog) Keys(lang string) []string {
	out := make([]string, 0, len(c.msgs[lang]))
	for k := range c.msgs[lang] {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Placeholders returns the placeholder indexes used by a message.
func Placeholders(s string) []string {
	m := placeholderRE.FindAllString(s, -1)
	sort.Strings(m)
	return m
}

// Raw returns a message without substitution (tests).
func (c *Catalog) Raw(lang, key string) string { return c.msgs[lang][key] }

// Valid reports whether lang is supported.
func Valid(lang string) bool {
	for _, l := range Languages {
		if l == lang {
			return true
		}
	}
	return false
}

// Negotiate picks a language from a preference cookie value, then the
// Accept-Language header, then def.
func Negotiate(r *http.Request, cookie, def string) string {
	if Valid(cookie) {
		return cookie
	}
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		tag := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
		switch {
		case strings.HasPrefix(tag, "pt"):
			return "pt-BR"
		case strings.HasPrefix(tag, "en"):
			return "en"
		}
	}
	return def
}
