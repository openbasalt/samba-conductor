package web

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// Advanced attributes of a user (the Attributes tab).
//
//   - GET /admin/users/{guid}/attributes (users.attributes: administrators
//     and auditors) lists every attribute the signed-in user may read,
//     through ad.RawEntry: secrets hidden, binary values reduced to their
//     length, values bounded. Read with the signed-in user's own identity
//     like every other page.
//   - /admin/users/{guid}/attributes/edit (users.write) is the restricted
//     editor of ad.EditableUserAttributes, offered only when
//     [ui] advanced_attribute_edit is on (404 otherwise). Only the
//     allowlisted names are read from the form; every value is checked by
//     ad.ValidateUserAttribute, a duplicate uidNumber is refused, and the
//     change goes through the usual preview and confirmation, conditional on
//     the values read, with old and new values in the audit.

// attrsEditOn reports whether the attribute editor is enabled.
func (s *Server) attrsEditOn() bool { return s.cfg.UI.AdvancedAttributeEdit }

// attrField is one input of the attribute editor.
type attrField struct {
	Name    string
	Multi   bool
	Numeric bool
	// Value is the input's value (several values one per line).
	Value   string
	Managed bool
	Error   string
}

func attrsBack(u ad.User) string { return "/admin/users/" + u.GUID.String() + "/attributes" }

func (s *Server) handleUserAttrs(rc *reqCtx) {
	g, err := rc.guidParam()
	if err != nil {
		rc.failed(err)
		return
	}
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		u, err := userByGUID(ctx, conn, g)
		if err != nil {
			return err
		}
		raw, err := conn.RawEntry(ctx, u.DN)
		if err != nil {
			return err
		}
		rc.render(http.StatusOK, "user_attrs", map[string]any{"U": u, "Raw": raw,
			"Edit": s.attrsEditOn() && rc.roles.Has(PermUsersWrite)})
		return nil
	})
}

// editableNames lists the allowlisted attribute names.
func editableNames() []string {
	var out []string
	for _, a := range ad.EditableUserAttributes() {
		out = append(out, a.Name)
	}
	return out
}

// currentAttrs reads the allowlisted attributes of a user.
func currentAttrs(ctx context.Context, conn *ad.Conn, dn string) (map[string][]string, error) {
	e, err := conn.Get(ctx, dn, editableNames()...)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, n := range editableNames() {
		out[n] = e.GetEqualFoldAttributeValues(n)
	}
	return out, nil
}

// attrFields builds the editor's inputs from the given values.
func attrFields(values map[string][]string, m gfManaged, errs map[string]string) []attrField {
	var out []attrField
	for _, a := range ad.EditableUserAttributes() {
		out = append(out, attrField{Name: a.Name, Multi: a.Multi, Numeric: a.Name == "uidNumber" || a.Name == "gidNumber",
			Value: strings.Join(values[a.Name], "\n"), Managed: m.Owns(a.Name), Error: errs[a.Name]})
	}
	return out
}

func (s *Server) handleUserAttrsEditPage(rc *reqCtx) {
	if !s.attrsEditOn() {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	g, err := rc.guidParam()
	if err != nil {
		rc.failed(err)
		return
	}
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		u, err := userByGUID(ctx, conn, g)
		if err != nil {
			return err
		}
		cur, err := currentAttrs(ctx, conn, u.DN)
		if err != nil {
			return err
		}
		m, err := s.gfManagedUser(ctx, rc, conn, u.DN)
		if err != nil {
			return err
		}
		rc.render(http.StatusOK, "user_attrs_edit", map[string]any{"U": u, "Fields": attrFields(cur, m, nil)})
		return nil
	})
}

// attrsFromForm reads the wanted values of the allowlisted attributes only
// (any other form field is ignored). An attribute missing from the form
// keeps its current values.
func attrsFromForm(rc *reqCtx, cur map[string][]string) map[string][]string {
	out := map[string][]string{}
	for _, a := range ad.EditableUserAttributes() {
		if _, present := rc.r.PostForm[a.Name]; !present {
			out[a.Name] = cur[a.Name]
			continue
		}
		var vals []string
		if a.Multi {
			for line := range strings.SplitSeq(rc.rawForm(a.Name), "\n") {
				if v := strings.TrimSpace(line); v != "" {
					vals = append(vals, v)
				}
			}
		} else if v := rc.form(a.Name); v != "" {
			vals = []string{v}
		}
		out[a.Name] = vals
	}
	return out
}

// sameSet compares value lists ignoring order.
func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

func (s *Server) handleUserAttrsEdit(rc *reqCtx) {
	if !s.attrsEditOn() {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	s.userAction(rc, PermUsersWrite, func(ctx context.Context, conn *ad.Conn, u ad.User) (*pendingOp, error) {
		cur, err := currentAttrs(ctx, conn, u.DN)
		if err != nil {
			return nil, err
		}
		m, err := s.gfManagedUser(ctx, rc, conn, u.DN)
		if err != nil {
			return nil, err
		}
		want := attrsFromForm(rc, cur)
		errs := map[string]string{}
		var edits []ad.AttrReplace
		var changed []string
		for _, a := range ad.EditableUserAttributes() {
			if sameSet(cur[a.Name], want[a.Name]) {
				continue
			}
			changed = append(changed, a.Name)
			if err := ad.ValidateUserAttribute(a.Name, want[a.Name]); err != nil {
				errs[a.Name] = attrErrText(rc, err)
				continue
			}
			edits = append(edits, ad.AttrReplace{Name: a.Name, Before: cur[a.Name], After: want[a.Name]})
		}
		fail := func(msg string) (*pendingOp, error) {
			rc.render(http.StatusBadRequest, "user_attrs_edit", map[string]any{"U": u, "Fields": attrFields(want, m, errs), "Error": msg})
			return nil, nil
		}
		if refused := gfRefused(m, changed); len(refused) > 0 {
			// Google owns these attributes; the next run would revert them.
			s.audit(ctx, rc, "user.attributes_update", u.DN, "refused: managed by Google: "+strings.Join(refused, ", "), store.ResultDenied)
			return fail(rc.T("err.managed_by_google", strings.Join(refused, ", ")))
		}
		if len(errs) == 0 {
			if uid := want["uidNumber"]; len(uid) == 1 && !sameSet(cur["uidNumber"], uid) {
				inUse, err := conn.UIDNumberInUse(ctx, uid[0], u.DN)
				if err != nil {
					return nil, err
				}
				if inUse {
					errs["uidNumber"] = rc.T("attrs.err.uid_in_use", uid[0])
				}
			}
		}
		if len(errs) > 0 {
			return fail(rc.T("form.invalid"))
		}
		op, err := ad.UpdateUserAttributes(u.DN, edits)
		if errors.Is(err, ad.ErrNoChange) {
			rc.flashOK("form.no_change")
			rc.redirect(attrsBack(u))
			return nil, nil
		}
		var ae *ad.AttrError
		if errors.As(err, &ae) {
			errs[ae.Attr] = attrErrText(rc, err)
			return fail(rc.T("form.invalid"))
		}
		if err != nil {
			return fail(rc.T("form.invalid"))
		}
		// Re-authentication: always on a protected account (userAction),
		// otherwise when the second factor is not recent.
		_, fresh := s.secondFactor(rc)
		return &pendingOp{action: "user.attributes_update", op: op, title: rc.T("attrs.edit.title", u.SAMAccountName),
			summary: rc.T("attrs.edit.summary", strings.Join(changedNames(edits), ", "), u.SAMAccountName), done: rc.T("op.done"),
			back: attrsBack(u), reauth: !fresh}, nil
	})
}

func changedNames(edits []ad.AttrReplace) []string {
	out := make([]string, 0, len(edits))
	for _, e := range edits {
		out = append(out, e.Name)
	}
	return out
}

// attrErrText translates an ad.AttrError (a generic message otherwise).
func attrErrText(rc *reqCtx, err error) string {
	var ae *ad.AttrError
	if errors.As(err, &ae) && rc.s.cat.Has("attrs.err."+ae.Reason) {
		return rc.T("attrs.err." + ae.Reason)
	}
	return rc.T("form.invalid")
}
