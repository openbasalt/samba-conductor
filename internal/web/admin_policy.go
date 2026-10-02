package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/samba-conductor/ad"
	"github.com/samba-conductor/ad/sid"
)

// Password and lockout policy: the domain's default policy and the
// fine-grained policies (PSOs). Every change is previewed and needs
// re-authentication.

// Recommended lockout settings shown when the domain has none (Samba
// provisions a threshold of 0: accounts never lock).
const (
	recommendedThreshold = 10
	recommendedMinutes   = 15
)

// policyForm is the policy as the forms carry it (days and minutes).
type policyForm struct {
	MinLength, History                 string
	Complexity, Reversible             bool
	MinAgeDays, MaxAgeDays             string
	Threshold, DurationMins, WindowMin string
	Precedence, Name                   string
}

func formFromPolicy(p ad.PasswordPolicy) policyForm {
	d := func(x time.Duration) string { return strconv.FormatInt(int64(x/(24*time.Hour)), 10) }
	m := func(x time.Duration) string { return strconv.FormatInt(int64(x/time.Minute), 10) }
	return policyForm{MinLength: strconv.Itoa(p.MinLength), History: strconv.Itoa(p.History), Complexity: p.Complexity,
		Reversible: p.ReversibleEncryption, MinAgeDays: d(p.MinAge), MaxAgeDays: d(p.MaxAge),
		Threshold: strconv.Itoa(p.LockoutThreshold), DurationMins: m(p.LockoutDuration), WindowMin: m(p.ObservationWindow)}
}

func readPolicyForm(rc *reqCtx) policyForm {
	return policyForm{MinLength: rc.form("min_length"), History: rc.form("history"), Complexity: rc.form("complexity") == "1",
		Reversible: rc.form("reversible") == "1", MinAgeDays: rc.form("min_age"), MaxAgeDays: rc.form("max_age"),
		Threshold: rc.form("threshold"), DurationMins: rc.form("duration"), WindowMin: rc.form("window"),
		Precedence: rc.form("precedence"), Name: rc.form("name")}
}

var errBadNumber = errors.New("web: not a number")

func (f policyForm) policy() (ad.PasswordPolicy, error) {
	num := func(s string) (int, error) {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 || n > 1_000_000 {
			return 0, errBadNumber
		}
		return n, nil
	}
	var p ad.PasswordPolicy
	var err error
	vals := []struct {
		s   string
		set func(int)
	}{
		{f.MinLength, func(n int) { p.MinLength = n }},
		{f.History, func(n int) { p.History = n }},
		{f.MinAgeDays, func(n int) { p.MinAge = time.Duration(n) * 24 * time.Hour }},
		{f.MaxAgeDays, func(n int) { p.MaxAge = time.Duration(n) * 24 * time.Hour }},
		{f.Threshold, func(n int) { p.LockoutThreshold = n }},
		{f.DurationMins, func(n int) { p.LockoutDuration = time.Duration(n) * time.Minute }},
		{f.WindowMin, func(n int) { p.ObservationWindow = time.Duration(n) * time.Minute }},
	}
	for _, v := range vals {
		n, nerr := num(v.s)
		if nerr != nil {
			err = nerr
			continue
		}
		v.set(n)
	}
	p.Complexity, p.ReversibleEncryption = f.Complexity, f.Reversible
	if err != nil {
		return p, err
	}
	return p, p.Validate()
}

func (s *Server) handlePolicy(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		d, err := conn.DomainPasswordPolicy(ctx)
		if err != nil {
			return err
		}
		psos, perr := conn.PSOs(ctx)
		data := map[string]any{"P": d.Policy, "PSOs": psos, "Threshold": recommendedThreshold, "Minutes": recommendedMinutes}
		if perr != nil {
			if !errors.Is(perr, ad.ErrAccessDenied) && !errors.Is(perr, ad.ErrNotFound) {
				return perr
			}
			data["PSOHidden"] = true
		}
		rc.render(http.StatusOK, "policy", data)
		return nil
	})
}

func (s *Server) handlePolicyEditPage(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		d, err := conn.DomainPasswordPolicy(ctx)
		if err != nil {
			return err
		}
		f := formFromPolicy(d.Policy)
		if d.Policy.LockoutDisabled() {
			// Offer the recommendation pre-filled; nothing changes until
			// the preview is confirmed.
			f.Threshold = strconv.Itoa(recommendedThreshold)
			f.DurationMins, f.WindowMin = strconv.Itoa(recommendedMinutes), strconv.Itoa(recommendedMinutes)
		}
		rc.render(http.StatusOK, "policy_edit", map[string]any{"F": f, "Domain": true, "Action": "/admin/policy/edit", "Back": "/admin/policy",
			"Recommend": d.Policy.LockoutDisabled()})
		return nil
	})
}

func (s *Server) handlePolicyEdit(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		d, err := conn.DomainPasswordPolicy(ctx)
		if err != nil {
			return err
		}
		f := readPolicyForm(rc)
		p, err := f.policy()
		if err == nil {
			var op *ad.Operation
			op, err = ad.UpdateDomainPasswordPolicy(d, p)
			if err == nil {
				warn := ""
				if p.LockoutDisabled() {
					warn = rc.T("policy.warn.no_lockout", recommendedThreshold, recommendedMinutes)
				}
				rc.propose(&pendingOp{perm: PermPolicyWrite, action: "policy.domain_update", target: d.DN, op: op, reauth: true,
					title: rc.T("policy.edit.title"), summary: rc.T("policy.summary.domain"), warning: warn,
					back: "/admin/policy", done: rc.T("op.done")})
				return nil
			}
		}
		key := "policy.err.values"
		if errors.Is(err, ad.ErrNoChange) {
			rc.flashOK("form.no_change")
			rc.redirect("/admin/policy")
			return nil
		}
		rc.render(http.StatusBadRequest, "policy_edit", map[string]any{"F": f, "Domain": true, "Action": "/admin/policy/edit",
			"Back": "/admin/policy", "Error": rc.T(key)})
		return nil
	})
}

// psoByGUID finds a PSO by objectGUID.
func psoByGUID(ctx context.Context, conn *ad.Conn, g sid.GUID) (ad.PSO, error) {
	entries, err := conn.SearchAll(ctx, ad.SearchRequest{BaseDN: conn.PSOContainerDN(), Scope: ad.ScopeOneLevel, Filter: byGUID(g),
		Attributes: []string{"1.1"}, Limit: 1})
	if err != nil {
		return ad.PSO{}, err
	}
	if len(entries) == 0 {
		return ad.PSO{}, errNotFoundPage
	}
	return conn.PSOByDN(ctx, entries[0].DN)
}

func (s *Server) handlePSONewPage(rc *reqCtx) {
	f := formFromPolicy(ad.PasswordPolicy{MinLength: 12, History: 24, Complexity: true, MaxAge: 90 * 24 * time.Hour,
		LockoutThreshold: recommendedThreshold, LockoutDuration: recommendedMinutes * time.Minute, ObservationWindow: recommendedMinutes * time.Minute})
	f.Precedence = "10"
	rc.render(http.StatusOK, "policy_edit", map[string]any{"F": f, "New": true, "Action": "/admin/policy/pso/new", "Back": "/admin/policy"})
}

func (s *Server) handlePSONew(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		f := readPolicyForm(rc)
		fail := func(key string) error {
			rc.render(http.StatusBadRequest, "policy_edit", map[string]any{"F": f, "New": true, "Action": "/admin/policy/pso/new",
				"Back": "/admin/policy", "Error": rc.T(key)})
			return nil
		}
		p, err := f.policy()
		if err != nil {
			return fail("policy.err.values")
		}
		prec, err := strconv.Atoi(f.Precedence)
		if err != nil {
			return fail("policy.err.values")
		}
		op, err := ad.CreatePSO(conn.PSOContainerDN(), f.Name, prec, p, nil)
		if err != nil {
			return fail("policy.err.values")
		}
		rc.propose(&pendingOp{perm: PermPolicyWrite, action: "policy.pso_create", target: op.Preview().Changes[0].DN, op: op, reauth: true,
			title: rc.T("policy.pso_new.title"), summary: rc.T("policy.summary.pso_create", f.Name, prec),
			back: "/admin/policy", done: rc.T("policy.pso_new.done")})
		return nil
	})
}

func (s *Server) psoPage(rc *reqCtx, status int, extra map[string]any) {
	g, err := rc.guidParam()
	if err != nil {
		rc.failed(err)
		return
	}
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		pso, err := psoByGUID(ctx, conn, g)
		if err != nil {
			return err
		}
		targets, err := describeMembers(ctx, conn, pso.AppliesTo)
		if err != nil {
			return err
		}
		f := formFromPolicy(pso.Policy)
		f.Precedence, f.Name = strconv.Itoa(pso.Precedence), pso.Name
		d := map[string]any{"PSO": pso, "Targets": targets, "F": f, "Link": "/admin/policy/pso/" + g.String()}
		for k, v := range extra {
			d[k] = v
		}
		rc.render(status, "pso", d)
		return nil
	})
}

func (s *Server) handlePSO(rc *reqCtx) { s.psoPage(rc, http.StatusOK, nil) }

// psoAction loads the PSO of the {guid} path and proposes what build makes.
func (s *Server) psoAction(rc *reqCtx, build func(ctx context.Context, conn *ad.Conn, pso ad.PSO, back string) (*pendingOp, error)) {
	g, err := rc.guidParam()
	if err != nil {
		rc.failed(err)
		return
	}
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		pso, err := psoByGUID(ctx, conn, g)
		if err != nil {
			return err
		}
		back := "/admin/policy/pso/" + g.String()
		p, err := build(ctx, conn, pso, back)
		if err != nil {
			rc.flashErr(s.adErrorKey(err))
			rc.redirect(back)
			return nil
		}
		if p == nil {
			return nil
		}
		p.perm, p.reauth, p.target = PermPolicyWrite, true, pso.DN
		if p.back == "" {
			p.back = back
		}
		rc.propose(p)
		return nil
	})
}

func (s *Server) handlePSOEdit(rc *reqCtx) {
	s.psoAction(rc, func(ctx context.Context, conn *ad.Conn, pso ad.PSO, back string) (*pendingOp, error) {
		f := readPolicyForm(rc)
		p, err := f.policy()
		prec, perr := strconv.Atoi(f.Precedence)
		if err != nil || perr != nil {
			return nil, ad.ErrInvalid
		}
		op, err := ad.UpdatePSO(pso, prec, p)
		if err != nil {
			return nil, err
		}
		return &pendingOp{action: "policy.pso_update", op: op, title: rc.T("policy.pso_edit.title", pso.Name),
			summary: rc.T("policy.summary.pso_update", pso.Name), done: rc.T("op.done")}, nil
	})
}

func (s *Server) handlePSODelete(rc *reqCtx) {
	s.psoAction(rc, func(ctx context.Context, conn *ad.Conn, pso ad.PSO, back string) (*pendingOp, error) {
		op, err := ad.DeleteObject(pso.DN)
		if err != nil {
			return nil, err
		}
		return &pendingOp{action: "policy.pso_delete", op: op, title: rc.T("policy.pso_delete.title", pso.Name),
			summary: rc.T("policy.summary.pso_delete", pso.Name, len(pso.AppliesTo)), warning: rc.T("confirm.warn.delete"),
			back: "/admin/policy", done: rc.T("op.deleted")}, nil
	})
}

func (s *Server) handlePSOApply(rc *reqCtx) {
	s.psoAction(rc, func(ctx context.Context, conn *ad.Conn, pso ad.PSO, back string) (*pendingOp, error) {
		dn, err := objectBySAM(ctx, conn, rc.form("target"))
		if err != nil {
			rc.flashErr("policy.err.target")
			rc.redirect(back)
			return nil, nil
		}
		op, err := ad.ApplyPSO(pso, dn)
		if err != nil {
			return nil, err
		}
		return &pendingOp{action: "policy.pso_apply", op: op, title: rc.T("policy.pso_apply.title", pso.Name),
			summary: rc.T("policy.summary.pso_apply", pso.Name, rdnOf(dn)), done: rc.T("op.done")}, nil
	})
}

func (s *Server) handlePSOUnapply(rc *reqCtx) {
	s.psoAction(rc, func(ctx context.Context, conn *ad.Conn, pso ad.PSO, back string) (*pendingOp, error) {
		op, err := ad.UnapplyPSO(pso, rc.form("dn"))
		if err != nil {
			return nil, err
		}
		return &pendingOp{action: "policy.pso_unapply", op: op, title: rc.T("policy.pso_unapply.title", pso.Name),
			summary: rc.T("policy.summary.pso_unapply", pso.Name, rdnOf(rc.form("dn"))), done: rc.T("op.done")}, nil
	})
}

// handleUserPolicy shows the password policy that applies to a user.
func (s *Server) handleUserPolicy(rc *reqCtx) {
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
		ep, err := conn.EffectivePasswordPolicy(ctx, u.DN)
		if err != nil {
			return err
		}
		var psoGUID string
		if ep.PSO != nil {
			psoGUID = ep.PSO.GUID
		}
		rc.render(http.StatusOK, "user_policy", map[string]any{"U": u, "E": ep, "PSOGUID": psoGUID, "Now": s.now()})
		return nil
	})
}
