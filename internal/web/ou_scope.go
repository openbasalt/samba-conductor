package web

import (
	"context"
	"errors"
	"iter"
	"strings"

	"github.com/go-ldap/ldap/v3"
	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
)

// dirReader is the part of *ad.Conn the Users, Groups and Computers lists
// read through, so tests can serve them from an in-memory directory.
type dirReader interface {
	BaseDN() string
	SearchWindow(ctx context.Context, req ad.SearchRequest, skip, n int) ([]*ldap.Entry, bool, error)
	Get(ctx context.Context, dn string, attributes ...string) (*ldap.Entry, error)
	OUs(ctx context.Context, base string, extra escape.Filter) iter.Seq2[ad.OU, error]
}

var _ dirReader = (*ad.Conn)(nil)

// viewDir is rc.view for read-only pages that only need a dirReader. Tests
// set Server.listDir to serve the page without a DC.
func (rc *reqCtx) viewDir(fn func(ctx context.Context, d dirReader) error) {
	if rc.s.listDir == nil {
		rc.view(func(ctx context.Context, conn *ad.Conn) error { return fn(ctx, conn) })
		return
	}
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	if err := fn(ctx, rc.s.listDir); err != nil {
		rc.failed(err)
	}
}

// maxScopeDNLen bounds the ?ou= value before it is parsed.
const maxScopeDNLen = 2048

// scopeIndent is one tree level in the container picker. A <select> cannot
// hold markup, so the tree is drawn with no-break spaces.
const scopeIndent = "   "

// scopeOption is one container of the list scope picker.
type scopeOption struct {
	DN    string
	Label string // name, indented by its depth in the tree
	Depth int
}

// ouScope is the subtree a list is limited to.
type ouScope struct {
	Options []scopeOption
	// Selected is the chosen container's DN as the directory spells it,
	// "" for the entire domain.
	Selected string
	// Rejected is set when ?ou= named something that is not a selectable
	// container; the list then shows the entire domain.
	Rejected bool
}

// loadOUScope lists the selectable containers (every OU the signed-in user
// can read, plus the named default containers that exist, such as
// CN=Users) as a tree, and validates the requested one against them. The
// requested DN is only ever used as a search base, never inside a filter,
// and only after it matched one of the containers read from the directory.
func loadOUScope(ctx context.Context, d dirReader, requested string, containers ...string) (ouScope, error) {
	base := d.BaseDN()
	byDN := map[string]*ouNode{}
	var all []*ouNode
	add := func(o ad.OU) {
		key := escape.NormalizeDN(o.DN)
		if _, dup := byDN[key]; dup {
			return
		}
		n := &ouNode{OU: o}
		byDN[key] = n
		all = append(all, n)
	}
	for _, cn := range containers {
		dn, err := escape.ChildDN("CN", cn, base)
		if err != nil {
			return ouScope{}, err
		}
		e, err := d.Get(ctx, dn, "cn")
		if errors.Is(err, ad.ErrNotFound) {
			continue
		}
		if err != nil {
			return ouScope{}, err
		}
		name := e.GetAttributeValue("cn")
		if name == "" {
			name = cn
		}
		add(ad.OU{DN: e.DN, Name: name})
	}
	n := 0
	for o, err := range d.OUs(ctx, "", nil) {
		if err != nil {
			return ouScope{}, err
		}
		n++
		if n > maxOUOptions {
			break
		}
		add(o)
	}
	var roots []*ouNode
	for _, node := range all {
		parent, _, err := escape.ParentDN(node.OU.DN)
		if p, ok := byDN[escape.NormalizeDN(parent)]; err == nil && ok {
			p.Children = append(p.Children, node)
		} else {
			roots = append(roots, node)
		}
	}
	var flat []*ouNode
	flatten(roots, 0, &flat)
	sc := ouScope{Options: make([]scopeOption, len(flat))}
	for i, node := range flat {
		sc.Options[i] = scopeOption{DN: node.OU.DN, Label: strings.Repeat(scopeIndent, node.Depth) + node.OU.Name, Depth: node.Depth}
	}
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return sc, nil
	}
	if dn, ok := sc.match(requested, base); ok {
		sc.Selected = dn
	} else {
		sc.Rejected = true
	}
	return sc, nil
}

// match returns the option equal to dn (compared as parsed DNs), provided
// dn parses and lies strictly below the domain base.
func (sc ouScope) match(dn, base string) (string, bool) {
	if len(dn) > maxScopeDNLen {
		return "", false
	}
	parsed, err := escape.ParseDN(dn)
	if err != nil || len(parsed.RDNs) == 0 {
		return "", false
	}
	parsedBase, err := escape.ParseDN(base)
	if err != nil || !parsedBase.AncestorOfFold(parsed) {
		return "", false
	}
	for _, o := range sc.Options {
		if p, err := escape.ParseDN(o.DN); err == nil && p.EqualFold(parsed) {
			return o.DN, true
		}
	}
	return "", false
}
