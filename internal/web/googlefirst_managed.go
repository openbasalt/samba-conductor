package web

import (
	"context"
	"slices"
	"strings"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// "Managed by Google" (premise P2): an account whose marker attribute
// starts with "google-first:" has fields Google owns. conductor shows them
// read only and refuses to write them on the edit page, in bulk CSV
// updates and in the self-service profile; changes made around conductor
// are corrected by the next run anyway.
//
// Google owns, for every Google-first account, the names and the primary
// address (givenName, sn, displayName, mail, proxyAddresses), and the
// optional fields its scope lists (title, department, employeeID,
// telephoneNumber, mobile). Without a scope containing the account (the
// scope was removed), its fields are AD-managed again. When the settings
// cannot be read, every field Google may own is treated as owned.

// gfAlwaysAttrs are the attributes Google owns on every Google-first
// account.
var gfAlwaysAttrs = []string{"givenName", "sn", "displayName", "mail", "proxyAddresses"}

// gfManaged is the Google-first state of one account.
type gfManaged struct {
	Managed  bool
	GoogleID string
	Scope    string
	// Unverified: the settings could not be read, so every field Google
	// may own is read only.
	Unverified bool
	// Orphan: the account carries a marker but no scope contains it now.
	Orphan bool
	attrs  map[string]bool
}

// Owns reports whether Google owns an attribute of the account.
func (m gfManaged) Owns(attr string) bool { return m.Managed && m.attrs[attr] }

// gfManagedOf computes the state of an account from its marker value, its
// DN and the settings (known is false when they could not be read).
func gfManagedOf(marker, dn string, gf syncapi.GoogleFirstSettings, known bool) gfManaged {
	if !strings.HasPrefix(marker, syncapi.G2AMarkerPrefix) {
		return gfManaged{}
	}
	m := gfManaged{GoogleID: strings.TrimPrefix(marker, syncapi.G2AMarkerPrefix), attrs: map[string]bool{}}
	for _, a := range gfAlwaysAttrs {
		m.attrs[a] = true
	}
	if !known {
		m.Managed, m.Unverified = true, true
		for _, fa := range gfFieldAttrs {
			m.attrs[fa.Attr] = true
		}
		return m
	}
	for _, sc := range gf.Scopes {
		if sc.ManagedOU == "" || !dnWithin(dn, sc.ManagedOU) {
			continue
		}
		m.Managed, m.Scope = true, sc.Name
		for _, fa := range gfFieldAttrs {
			if slices.Contains(sc.Fields, fa.Field) {
				m.attrs[fa.Attr] = true
			}
		}
		return m
	}
	m.Orphan = true
	return m
}

// gfManagedFor computes the state of an account whose marker value is
// known (the settings are read only for a marked account).
func (s *Server) gfManagedFor(ctx context.Context, rc *reqCtx, marker, dn string) gfManaged {
	if !strings.HasPrefix(marker, syncapi.G2AMarkerPrefix) {
		return gfManaged{}
	}
	gf, err := s.googleFirst(ctx, rc, false)
	if err != nil {
		s.log.Warn("reading the Google-first settings for a marked account", "dn", dn, "err", err)
	}
	return gfManagedOf(marker, dn, gf, err == nil)
}

// gfManagedUser reads an account's marker with the given connection and
// computes its state.
func (s *Server) gfManagedUser(ctx context.Context, rc *reqCtx, conn *ad.Conn, dn string) (gfManaged, error) {
	e, err := conn.Get(ctx, dn, syncapi.G2AMarkerAttribute)
	if err != nil {
		return gfManaged{}, err
	}
	return s.gfManagedFor(ctx, rc, e.GetAttributeValue(syncapi.G2AMarkerAttribute), dn), nil
}

// gfFieldViews are the fields of a form with the ones Google owns marked.
func gfFieldViews(fields []selfField, u ad.User, m gfManaged) []fieldView {
	out := fieldViews(fields, u)
	for i := range out {
		out[i].Managed = m.Owns(out[i].Attr)
	}
	return out
}

// changedAttrs lists the attributes a form changes (as updateFromForm
// counts them).
func changedAttrs(rc *reqCtx, fields []selfField, u ad.User) []string {
	var out []string
	for _, f := range fields {
		if _, present := rc.r.PostForm[f.Attr]; !present {
			continue
		}
		if rc.form(f.Attr) != f.get(u) {
			out = append(out, f.Attr)
		}
	}
	return out
}

// gfRefused returns the attributes of attrs Google owns.
func gfRefused(m gfManaged, attrs []string) []string {
	var out []string
	for _, a := range attrs {
		if m.Owns(a) {
			out = append(out, a)
		}
	}
	return out
}

// gfBulkAttrs maps the bulk update columns to the attributes they write.
var gfBulkAttrs = map[string]string{"display_name": "displayName", "email": "mail", "title": "title", "department": "department",
	"telephone": "telephoneNumber", "mobile": "mobile"}
