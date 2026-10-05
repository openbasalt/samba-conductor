package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-idp/idpapi"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// Single sign-on (P4b): conductor-idp's applications, keys, settings and
// activity, managed from conductor. conductor never signs anything or
// sees a signing key: it drives conductor-idp's local management API
// (idpapi) as the signed-in administrator. Reads need PermSSORead,
// changes PermSSOWrite (administrators only); every change is previewed
// and confirmed with the password and a fresh second factor, and audited
// here and in conductor-idp's own hash-chained log. A client secret
// comes back once, is shown once, and is kept nowhere.

// IDPClient calls conductor-idp's management API.
type IDPClient interface {
	Call(ctx context.Context, req idpapi.Request) (idpapi.Response, error)
}

var errIDPDisabled = errors.New("web: the single sign-on section is not enabled ([idp] in conductor.toml)")

func idpActor(rc *reqCtx) idpapi.Actor {
	rc.sess.mu.Lock()
	defer rc.sess.mu.Unlock()
	return idpapi.Actor{User: rc.sess.sam, SID: rc.sess.userSID.String(), Session: rc.sess.hash[:16], IP: rc.ip}
}

// idpCall runs one API operation as the signed-in user.
func (s *Server) idpCall(ctx context.Context, rc *reqCtx, op idpapi.Op, params idpapi.Params, out any) error {
	if s.idp == nil {
		return errIDPDisabled
	}
	req, err := idpapi.NewRequest(newToken()[:24], op, idpActor(rc), params)
	if err != nil {
		return err
	}
	resp, err := s.idp.Call(ctx, req)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return idpapi.DecodeResult(resp, out)
}

// idpErr renders an API error for the user (translated), with
// conductor-idp's validation details where they help.
func (s *Server) idpErr(rc *reqCtx, err error) string {
	var e *idpapi.Error
	switch {
	case errors.Is(err, errIDPDisabled):
		return rc.T("sso.err.disabled")
	case errors.As(err, &e):
		msg := rc.T("sso.err." + string(e.Code))
		if strings.HasPrefix(msg, "[") {
			msg = rc.T("sso.err.failed")
		}
		if e.Code == idpapi.CodeUnavailable {
			return msg
		}
		detail := e.Message
		if len(e.Details) > 0 {
			detail = strings.Join(e.Details, "; ")
		}
		return msg + " " + detail
	case errors.Is(err, context.DeadlineExceeded):
		return rc.T("sso.err.unavailable")
	}
	s.log.Warn("idp API call failed", "err", err)
	return rc.T("sso.err.failed")
}

func idpTimeout(rc *reqCtx) (context.Context, context.CancelFunc) {
	return context.WithTimeout(rc.ctx(), requestTimeout)
}

// ssoSecret is a client secret waiting to be shown once.
type ssoSecret struct {
	ClientID, Name, Secret string
	Created                bool
	at                     time.Time
}

// keepSecret stores a secret in the session and returns its reference.
func (rc *reqCtx) keepSecret(v ssoSecret) string {
	ref := newToken()[:22]
	v.at = rc.s.now()
	rc.sess.mu.Lock()
	defer rc.sess.mu.Unlock()
	if rc.sess.ssoSecrets == nil {
		rc.sess.ssoSecrets = map[string]ssoSecret{}
	}
	for k, old := range rc.sess.ssoSecrets {
		if rc.s.now().Sub(old.at) > pendingTTL {
			delete(rc.sess.ssoSecrets, k)
		}
	}
	rc.sess.ssoSecrets[ref] = v
	return ref
}

// handleSSOSecret shows a client secret once.
func (s *Server) handleSSOSecret(rc *reqCtx) {
	ref := rc.r.PathValue("ref")
	rc.sess.mu.Lock()
	v, ok := rc.sess.ssoSecrets[ref]
	delete(rc.sess.ssoSecrets, ref)
	rc.sess.mu.Unlock()
	if !ok || s.now().Sub(v.at) > pendingTTL {
		rc.errorPage(http.StatusNotFound, "sso.secret.gone")
		return
	}
	rc.w.Header().Set("Cache-Control", "no-store")
	rc.render(http.StatusOK, "sso_secret", map[string]any{"S": v})
}

// ---- overview ----

func (s *Server) handleSSO(rc *reqCtx) {
	d := map[string]any{"CanWrite": rc.roles.Has(PermSSOWrite)}
	if s.idp == nil {
		d["Disabled"] = true
		rc.render(http.StatusOK, "sso", d)
		return
	}
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	var st idpapi.Status
	if err := s.idpCall(ctx, rc, idpapi.OpStatus, nil, &st); err != nil {
		d["Error"] = s.idpErr(rc, err)
		rc.render(http.StatusOK, "sso", d)
		return
	}
	d["S"] = st
	var a idpapi.Activity
	if err := s.idpCall(ctx, rc, idpapi.OpActivity, idpapi.ActivityParams{Days: 7}, &a); err == nil {
		d["A"] = a
	}
	var k idpapi.Keys
	if err := s.idpCall(ctx, rc, idpapi.OpKeysList, nil, &k); err == nil {
		d["K"] = k
	}
	rc.render(http.StatusOK, "sso", d)
}

// ---- group picker (shared by the client and SP forms) ----

// groupPick is the state of a form's group lists: SIDs in hidden fields,
// a search box, and buttons that add or remove one SID.
type groupPick struct {
	Groups []string
	Filter []string
	Q      string
}

func (rc *reqCtx) groupPick() groupPick {
	g := groupPick{Q: rc.form("q")}
	for _, v := range rc.r.PostForm["group"] {
		if validSID(v) && !slices.Contains(g.Groups, v) {
			g.Groups = append(g.Groups, v)
		}
	}
	for _, v := range rc.r.PostForm["filter"] {
		if validSID(v) && !slices.Contains(g.Filter, v) {
			g.Filter = append(g.Filter, v)
		}
	}
	if v := rc.form("add_group"); validSID(v) && !slices.Contains(g.Groups, v) {
		g.Groups = append(g.Groups, v)
	}
	if v := rc.form("add_filter"); validSID(v) && !slices.Contains(g.Filter, v) {
		g.Filter = append(g.Filter, v)
	}
	if v := rc.form("remove_group"); v != "" {
		g.Groups = slices.DeleteFunc(g.Groups, func(x string) bool { return x == v })
	}
	if v := rc.form("remove_filter"); v != "" {
		g.Filter = slices.DeleteFunc(g.Filter, func(x string) bool { return x == v })
	}
	return g
}

// groupData resolves the picked SIDs to names and runs the search, with
// the administrator's own connection.
func (s *Server) groupData(ctx context.Context, rc *reqCtx, g groupPick, d map[string]any) {
	names := map[string]groupInfo{}
	err := rc.withConn(ctx, func(conn *ad.Conn) error {
		for _, ref := range append(slices.Clone(g.Groups), g.Filter...) {
			if _, done := names[ref]; !done {
				names[ref] = lookupGroupRef(ctx, conn, ref)
			}
		}
		if g.Q == "" {
			return nil
		}
		var hits []groupHit
		for e, err := range conn.Search(ctx, ad.SearchRequest{Filter: andFilters(groupFilter, searchFilter(g.Q, "sAMAccountName", "cn", "description")),
			Attributes: ad.GroupAttributes, SortBy: "cn", Limit: 20}) {
			if err != nil {
				return err
			}
			gr := ad.GroupFromEntry(e)
			hits = append(hits, groupHit{Name: gr.Name, DN: gr.DN, SID: gr.SID.String(), Description: gr.Description})
		}
		d["Hits"] = hits
		return nil
	})
	if err != nil {
		d["DirError"] = rc.T(s.adErrorKey(err))
	}
	d["GroupNames"] = names
}

// groupLabel names a SID for previews ("Name (SID)").
func groupLabel(names map[string]groupInfo, ref string) string {
	if g, ok := names[ref]; ok && g.Found {
		return g.Name + " (" + ref + ")"
	}
	return ref
}

func (s *Server) groupNames(ctx context.Context, rc *reqCtx, refs []string) map[string]groupInfo {
	d := map[string]any{}
	s.groupData(ctx, rc, groupPick{Groups: refs}, d)
	m, _ := d["GroupNames"].(map[string]groupInfo)
	return m
}

// ---- OIDC clients ----

func (s *Server) handleSSOClients(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	d := map[string]any{"CanWrite": rc.roles.Has(PermSSOWrite)}
	var list []idpapi.Client
	if err := s.idpCall(ctx, rc, idpapi.OpClientList, nil, &list); err != nil {
		d["Error"] = s.idpErr(rc, err)
	} else {
		d["Clients"] = list
	}
	rc.render(http.StatusOK, "sso_clients", d)
}

// clientForm is the OIDC client form, posted back whole on every action.
type clientForm struct {
	ID                                       string
	Name, Kind, Redirects, PostLogout, Claim string
	Scopes                                   []string
	AllowAll, FirstParty, RequireMFA         bool
	PreviewUser                              string
	Preset                                   string
	groupPick
}

func formLines(v string) []string {
	var out []string
	for _, l := range strings.Split(v, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (rc *reqCtx) clientForm() clientForm {
	_ = rc.r.ParseForm()
	return clientForm{ID: rc.form("id"), Name: rc.form("name"), Kind: rc.form("kind"), Redirects: rc.form("redirect_uris"),
		PostLogout: rc.form("post_logout_uris"), Claim: rc.form("groups_claim"), Scopes: rc.r.PostForm["scopes"],
		AllowAll: rc.form("allow_all") == "1", FirstParty: rc.form("first_party") == "1", RequireMFA: rc.form("require_mfa") == "1",
		PreviewUser: rc.form("preview_user"), Preset: rc.form("preset"), groupPick: rc.groupPick()}
}

func (f clientForm) input() idpapi.ClientInput {
	return idpapi.ClientInput{Name: f.Name, Kind: f.Kind, RedirectURIs: formLines(f.Redirects), PostLogoutURIs: formLines(f.PostLogout),
		Scopes: f.Scopes, Groups: f.Groups, AllowAllUsers: f.AllowAll, FirstParty: f.FirstParty, GroupsClaim: f.Claim,
		GroupsFilter: f.Filter, RequireMFA: f.RequireMFA}
}

func clientFormFrom(c idpapi.ClientInput) clientForm {
	return clientForm{Name: c.Name, Kind: c.Kind, Redirects: strings.Join(c.RedirectURIs, "\n"), PostLogout: strings.Join(c.PostLogoutURIs, "\n"),
		Claim: c.GroupsClaim, Scopes: c.Scopes, AllowAll: c.AllowAllUsers, FirstParty: c.FirstParty, RequireMFA: c.RequireMFA,
		groupPick: groupPick{Groups: slices.Clone(c.Groups), Filter: slices.Clone(c.GroupsFilter)}}
}

// renderClientForm shows the form (new or edit) with the group names, the
// search hits and an optional preview.
func (s *Server) renderClientForm(ctx context.Context, rc *reqCtx, status int, f clientForm, d map[string]any) {
	if d == nil {
		d = map[string]any{}
	}
	if f.Kind == "" {
		f.Kind = "confidential"
	}
	if f.Claim == "" {
		f.Claim = "none"
	}
	d["F"], d["Scopes"], d["Claims"], d["Kinds"] = f, idpapi.Scopes[1:], idpapi.GroupsClaims, idpapi.ClientKinds
	if f.ID != "" {
		var c idpapi.Client
		if err := s.idpCall(ctx, rc, idpapi.OpClientGet, idpapi.ClientRef{ID: f.ID}, &c); err == nil {
			d["Client"] = c
		}
	}
	s.groupData(ctx, rc, f.groupPick, d)
	rc.render(status, "sso_client_form", d)
}

func (s *Server) handleSSOClientNew(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	s.renderClientForm(ctx, rc, http.StatusOK, clientForm{Kind: "confidential", Claim: "none", Scopes: []string{"profile", "email"}}, nil)
}

// handleSSOClientForm handles every button of the client form: group
// search and picking, a claims preview, and review (which validates with
// conductor-idp and proposes the change).
func (s *Server) handleSSOClientForm(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	f := rc.clientForm()
	action := rc.form("action")
	if action != "preview" && action != "review" {
		s.renderClientForm(ctx, rc, http.StatusOK, f, nil)
		return
	}
	in := f.input()
	user := f.PreviewUser
	if user == "" {
		rc.sess.mu.Lock()
		user = rc.sess.sam
		rc.sess.mu.Unlock()
	}
	// The preview validates the whole input with conductor-idp's rules.
	var pv idpapi.Preview
	if err := s.idpCall(ctx, rc, idpapi.OpClientPreview, idpapi.ClientPreviewParams{Input: &in, Username: user}, &pv); err != nil {
		s.renderClientForm(ctx, rc, http.StatusBadRequest, f, map[string]any{"Error": s.idpErr(rc, err)})
		return
	}
	if action == "preview" {
		s.renderClientForm(ctx, rc, http.StatusOK, f, map[string]any{"Preview": pv})
		return
	}
	s.proposeClient(ctx, rc, f, in)
}

func (s *Server) proposeClient(ctx context.Context, rc *reqCtx, f clientForm, in idpapi.ClientInput) {
	names := s.groupNames(ctx, rc, append(slices.Clone(in.Groups), in.GroupsFilter...))
	labels := func(refs []string) string {
		var out []string
		for _, r := range refs {
			out = append(out, groupLabel(names, r))
		}
		if len(out) == 0 {
			return "-"
		}
		return strings.Join(out, ", ")
	}
	op, action, title := idpapi.OpClientCreate, "sso.client_create", rc.T("sso.client.create_title", in.Name)
	if f.ID != "" {
		op, action, title = idpapi.OpClientUpdate, "sso.client_update", rc.T("sso.client.update_title", in.Name)
	}
	lines := []string{"conductor-idp " + string(op)}
	if f.ID != "" {
		lines = append(lines, "client_id: "+f.ID)
	}
	lines = append(lines, "name: "+in.Name, "kind: "+in.Kind, "redirect_uris: "+strings.Join(in.RedirectURIs, " "),
		"post_logout_uris: "+strings.Join(in.PostLogoutURIs, " "), "scopes: "+strings.Join(in.Scopes, " "),
		"allowed_groups: "+labels(in.Groups), fmt.Sprintf("allow_all_users: %v", in.AllowAllUsers),
		"groups_claim: "+in.GroupsClaim, "groups_filter: "+labels(in.GroupsFilter),
		fmt.Sprintf("first_party: %v", in.FirstParty), fmt.Sprintf("require_mfa: %v", in.RequireMFA))
	warning := ""
	if in.AllowAllUsers {
		warning = rc.T("sso.warn.all_users")
	}
	p := &pendingOp{perm: PermSSOWrite, action: action, target: in.Name, reauth: true, title: title,
		summary: rc.T("sso.client.summary"), warning: warning, preview: strings.Join(lines, "\n"), back: "/admin/sso/oidc",
		done: rc.T("sso.saved")}
	p.run = func(ctx context.Context, rc *reqCtx) error {
		if f.ID != "" {
			var c idpapi.Client
			if err := s.idpCall(ctx, rc, idpapi.OpClientUpdate, idpapi.ClientUpdateParams{ID: f.ID, Input: in}, &c); err != nil {
				return err
			}
			p.back = "/admin/sso/oidc/" + c.ID
			return nil
		}
		var cs idpapi.ClientSecret
		if err := s.idpCall(ctx, rc, idpapi.OpClientCreate, idpapi.ClientCreateParams{Input: in}, &cs); err != nil {
			return err
		}
		p.target = cs.Client.ID
		p.back = "/admin/sso/secret/" + rc.keepSecret(ssoSecret{ClientID: cs.Client.ID, Name: cs.Client.Name, Secret: cs.Secret, Created: true})
		return nil
	}
	rc.propose(p)
}

func (s *Server) ssoClient(ctx context.Context, rc *reqCtx) (idpapi.Client, bool) {
	var c idpapi.Client
	if err := s.idpCall(ctx, rc, idpapi.OpClientGet, idpapi.ClientRef{ID: rc.r.PathValue("id")}, &c); err != nil {
		var e *idpapi.Error
		if errors.As(err, &e) && (e.Code == idpapi.CodeNotFound || e.Code == idpapi.CodeBadRequest) {
			rc.errorPage(http.StatusNotFound, "err.not_found")
		} else {
			rc.render(http.StatusOK, "sso_client", map[string]any{"Error": s.idpErr(rc, err)})
		}
		return c, false
	}
	return c, true
}

func (s *Server) handleSSOClient(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	c, ok := s.ssoClient(ctx, rc)
	if !ok {
		return
	}
	d := map[string]any{"C": c, "CanWrite": rc.roles.Has(PermSSOWrite)}
	var st idpapi.Status
	if err := s.idpCall(ctx, rc, idpapi.OpStatus, nil, &st); err == nil {
		d["S"] = st
	}
	d["GroupNames"] = s.groupNames(ctx, rc, append(slices.Clone(c.Groups), c.GroupsFilter...))
	if u := strings.TrimSpace(rc.r.URL.Query().Get("preview_user")); u != "" {
		var pv idpapi.Preview
		if err := s.idpCall(ctx, rc, idpapi.OpClientPreview, idpapi.ClientPreviewParams{ID: c.ID, Username: u}, &pv); err != nil {
			d["PreviewError"] = s.idpErr(rc, err)
		} else {
			d["Preview"] = pv
		}
		d["PreviewUser"] = u
	}
	rc.render(http.StatusOK, "sso_client", d)
}

func (s *Server) handleSSOClientEdit(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	c, ok := s.ssoClient(ctx, rc)
	if !ok {
		return
	}
	f := clientFormFrom(c.ClientInput)
	f.ID = c.ID
	s.renderClientForm(ctx, rc, http.StatusOK, f, nil)
}

func (s *Server) handleSSOClientRotate(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	c, ok := s.ssoClient(ctx, rc)
	if !ok {
		return
	}
	back := "/admin/sso/oidc/" + c.ID
	if !c.HasSecret {
		rc.flashErr("sso.client.public_no_secret")
		rc.redirect(back)
		return
	}
	p := &pendingOp{perm: PermSSOWrite, action: "sso.client_rotate", target: c.ID, reauth: true,
		title: rc.T("sso.client.rotate_title", c.Name), summary: rc.T("sso.client.rotate_summary"),
		warning: rc.T("sso.client.rotate_warning"), preview: "conductor-idp client.rotate\nclient_id: " + c.ID, back: back}
	p.run = func(ctx context.Context, rc *reqCtx) error {
		var cs idpapi.ClientSecret
		if err := s.idpCall(ctx, rc, idpapi.OpClientRotate, idpapi.ClientRef{ID: c.ID}, &cs); err != nil {
			return err
		}
		p.back = "/admin/sso/secret/" + rc.keepSecret(ssoSecret{ClientID: c.ID, Name: c.Name, Secret: cs.Secret})
		return nil
	}
	rc.propose(p)
}

func (s *Server) handleSSOClientEnabled(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	c, ok := s.ssoClient(ctx, rc)
	if !ok {
		return
	}
	enable := rc.form("enabled") == "1"
	key := "sso.disable"
	if enable {
		key = "sso.enable"
	}
	rc.propose(&pendingOp{perm: PermSSOWrite, action: "sso.client_enabled", target: c.ID, reauth: true,
		title: rc.T(key+"_title", c.Name), summary: rc.T(key + "_summary"),
		preview: fmt.Sprintf("conductor-idp client.set_enabled\nclient_id: %s\nenabled: %v", c.ID, enable),
		run: func(ctx context.Context, rc *reqCtx) error {
			return s.idpCall(ctx, rc, idpapi.OpClientEnable, idpapi.ClientEnableParams{ID: c.ID, Enabled: enable}, &idpapi.Client{})
		}, back: "/admin/sso/oidc/" + c.ID, done: rc.T("sso.saved")})
}

func (s *Server) handleSSOClientDelete(rc *reqCtx) {
	ctx, cancel := idpTimeout(rc)
	defer cancel()
	c, ok := s.ssoClient(ctx, rc)
	if !ok {
		return
	}
	if rc.form("confirm") != c.ID {
		s.audit(ctx, rc, "sso.client_delete", c.ID, "typed confirmation did not match", store.ResultDenied)
		rc.flashErr("sso.confirm_mismatch", c.ID)
		rc.redirect("/admin/sso/oidc/" + c.ID)
		return
	}
	rc.propose(&pendingOp{perm: PermSSOWrite, action: "sso.client_delete", target: c.ID, reauth: true,
		title: rc.T("sso.delete_title", c.Name), summary: rc.T("sso.client.delete_summary"), warning: rc.T("sso.client.delete_warning"),
		preview: "conductor-idp client.delete\nclient_id: " + c.ID + "\nname: " + c.Name,
		run: func(ctx context.Context, rc *reqCtx) error {
			return s.idpCall(ctx, rc, idpapi.OpClientDelete, idpapi.ClientRef{ID: c.ID}, nil)
		}, back: "/admin/sso/oidc", done: rc.T("sso.deleted")})
}
