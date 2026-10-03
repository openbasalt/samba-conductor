package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/openbasalt/samba-conductor-files/filesapi"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// File servers (P2b). conductor never writes to a file server itself: the
// conductor-files agent on each domain-member server does, over TLS with
// both keys pinned (enrolled from this UI with a one-time code made on the
// server). conductor decides who may do what (files.read: administrators
// and auditors; files.write: administrators), every change is previewed
// with the agent's exact plan and confirmed with a fresh second factor, and
// it is audited here and in the agent's own hash-chained log, both with the
// signed-in user.

// FilesClient reaches conductor-files agents.
type FilesClient interface {
	// Call sends one request to the agent at addr, pinning its key.
	Call(ctx context.Context, addr, agentPin string, req filesapi.Request) (filesapi.Response, error)
	// Pin is conductor's own key pin (the agents pin it at enrollment).
	Pin() string
	// Name labels conductor's key on the agents.
	Name() string
}

var errFilesDisabled = errors.New("web: the File servers section is not enabled ([files] in conductor.toml)")

// filesStatusTTL bounds how long a server's status is reused.
const filesStatusTTL = 20 * time.Second

// filesCache keeps the last status of each server (list, dashboard).
type filesCache struct {
	mu sync.Mutex
	m  map[string]filesCached
}

type filesCached struct {
	st  *filesapi.Status
	err string
	at  time.Time
}

func filesActor(rc *reqCtx) filesapi.Actor {
	rc.sess.mu.Lock()
	defer rc.sess.mu.Unlock()
	return filesapi.Actor{User: rc.sess.sam, SID: rc.sess.userSID.String(), Session: rc.sess.hash[:16], IP: rc.ip}
}

// filesCallPin runs one operation on the agent at addr as the signed-in
// user. out must be a fresh value.
func (s *Server) filesCallPin(ctx context.Context, rc *reqCtx, addr, pin string, op filesapi.Op, params filesapi.Params, out any) error {
	if s.files == nil {
		return errFilesDisabled
	}
	req, err := filesapi.NewRequest(newToken()[:24], op, filesActor(rc), params)
	if err != nil {
		return err
	}
	resp, err := s.files.Call(ctx, addr, pin, req)
	if err != nil {
		return &filesTransportError{err: err}
	}
	return filesapi.DecodeResult(resp, out)
}

func (s *Server) filesCall(ctx context.Context, rc *reqCtx, srv store.FileServer, op filesapi.Op, params filesapi.Params, out any) error {
	return s.filesCallPin(ctx, rc, srv.Address, srv.AgentPin, op, params, out)
}

// filesErr renders an error for the user: a translated sentence plus the
// agent's own detail (validation problems, the reason a plan is refused).
func (s *Server) filesErr(rc *reqCtx, err error) string { return s.filesErrT(rc.T, err) }

func (s *Server) filesErrT(t func(string, ...any) string, err error) string {
	var e *filesapi.Error
	var pm *filesapi.PinMismatchError
	switch {
	case errors.Is(err, errFilesDisabled):
		return t("files.err.disabled")
	case errors.As(err, &pm):
		return t("files.err.pin")
	case errors.As(err, &e):
		msg := t("files.err." + string(e.Code))
		if strings.HasPrefix(msg, "[") {
			msg = t("files.err.failed")
		}
		detail := e.Message
		if len(e.Details) > 0 {
			detail = strings.Join(e.Details, "; ")
		}
		return msg + " " + detail
	case err != nil && strings.Contains(err.Error(), "bad certificate"):
		return t("files.err.rejected")
	}
	var ne net.Error
	if errors.As(err, &ne) || errors.Is(err, context.DeadlineExceeded) {
		return t("files.err.unreachable")
	}
	s.log.Warn("file server call failed", "err", err)
	return t("files.err.unreachable")
}

// filesTransportError is a call that did not get an answer from the
// agent (unreachable, TLS refused, wrong key).
type filesTransportError struct{ err error }

func (e *filesTransportError) Error() string { return "file server: " + e.err.Error() }
func (e *filesTransportError) Unwrap() error { return e.err }

// isFilesErr reports whether err came from a file server call.
func (s *Server) isFilesErr(err error) bool {
	var e *filesapi.Error
	var te *filesTransportError
	var pm *filesapi.PinMismatchError
	return errors.As(err, &e) || errors.As(err, &te) || errors.As(err, &pm) || errors.Is(err, errFilesDisabled)
}

func filesTimeout(rc *reqCtx) (context.Context, context.CancelFunc) {
	return context.WithTimeout(rc.ctx(), 2*time.Minute)
}

var serverIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// fileServer loads the server named by the {id} path value, or renders 404.
func (s *Server) fileServer(rc *reqCtx) (store.FileServer, bool) {
	id := rc.r.PathValue("id")
	if !serverIDRE.MatchString(id) {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return store.FileServer{}, false
	}
	srv, err := s.store.FileServer(rc.ctx(), id)
	if err != nil {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return srv, false
	}
	return srv, true
}

func serverURL(srv store.FileServer) string { return "/admin/files/" + srv.ID }

func shareURL(srv store.FileServer, name string) string {
	return serverURL(srv) + "/shares/" + url.PathEscape(name)
}

// statusOf reads (or reuses) a server's status.
func (s *Server) statusOf(ctx context.Context, rc *reqCtx, srv store.FileServer, fresh bool) (*filesapi.Status, string) {
	s.filesStatus.mu.Lock()
	c, ok := s.filesStatus.m[srv.ID]
	s.filesStatus.mu.Unlock()
	if ok && !fresh && s.now().Sub(c.at) < filesStatusTTL {
		return c.st, c.err
	}
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var st filesapi.Status
	c = filesCached{at: s.now()}
	if err := s.filesCall(cctx, rc, srv, filesapi.OpStatus, nil, &st); err != nil {
		c.err = s.filesErr(rc, err)
	} else {
		c.st = &st
	}
	s.filesStatus.mu.Lock()
	if s.filesStatus.m == nil {
		s.filesStatus.m = map[string]filesCached{}
	}
	s.filesStatus.m[srv.ID] = c
	s.filesStatus.mu.Unlock()
	return c.st, c.err
}

func (s *Server) forgetStatus(id string) {
	s.filesStatus.mu.Lock()
	delete(s.filesStatus.m, id)
	s.filesStatus.mu.Unlock()
}

// serverRow is one line of the servers list.
type serverRow struct {
	S   store.FileServer
	St  *filesapi.Status
	Err string
}

// serverRows reads every server's status in parallel.
func (s *Server) serverRows(ctx context.Context, rc *reqCtx, fresh bool) ([]serverRow, error) {
	servers, err := s.store.FileServers(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]serverRow, len(servers))
	var wg sync.WaitGroup
	for i, srv := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, e := s.statusOf(ctx, rc, srv, fresh)
			rows[i] = serverRow{S: srv, St: st, Err: e}
		}()
	}
	wg.Wait()
	return rows, nil
}

// filesDashboard counts the servers and the reachable, ready ones.
func (s *Server) filesDashboard(ctx context.Context, rc *reqCtx) (total, ready int, ok bool) {
	rows, err := s.serverRows(ctx, rc, false)
	if err != nil {
		return 0, 0, false
	}
	for _, r := range rows {
		if r.St != nil && r.St.Ready() {
			ready++
		}
	}
	return len(rows), ready, true
}

// ---- servers ----

func (s *Server) handleFiles(rc *reqCtx) {
	d := map[string]any{"CanWrite": rc.roles.Has(PermFilesWrite)}
	if s.files == nil {
		d["Disabled"] = true
		rc.render(http.StatusOK, "files", d)
		return
	}
	d["Pin"], d["Name"] = s.files.Pin(), s.files.Name()
	rows, err := s.serverRows(rc.ctx(), rc, rc.r.URL.Query().Get("refresh") == "1")
	if err != nil {
		d["Error"] = rc.T("files.err.store")
	}
	d["Rows"] = rows
	rc.render(http.StatusOK, "files", d)
}

func (s *Server) handleFilesNewPage(rc *reqCtx) {
	if s.files == nil {
		rc.errorPage(http.StatusNotFound, "files.err.disabled")
		return
	}
	rc.render(http.StatusOK, "files_new", map[string]any{"Pin": s.files.Pin(), "Name": s.files.Name(), "Address": rc.r.URL.Query().Get("address")})
}

func (s *Server) handleFilesNew(rc *reqCtx) {
	if s.files == nil {
		rc.errorPage(http.StatusNotFound, "files.err.disabled")
		return
	}
	render := func(key string, args ...any) {
		rc.render(http.StatusUnprocessableEntity, "files_new", map[string]any{"Pin": s.files.Pin(), "Name": s.files.Name(),
			"Address": rc.form("address"), "Error": rc.T(key, args...)})
	}
	addr, err := filesapi.NormalizeAddress(rc.form("address"))
	if err != nil {
		render("files.new.err.address")
		return
	}
	token, pin, err := filesapi.ParseEnrollmentCode(rc.rawForm("code"))
	if err != nil {
		render("files.new.err.code")
		return
	}
	servers, err := s.store.FileServers(rc.ctx())
	if err != nil {
		render("files.err.store")
		return
	}
	for _, f := range servers {
		if strings.EqualFold(f.Address, addr) {
			render("files.new.err.exists", f.Name)
			return
		}
		if f.AgentPin == pin {
			render("files.new.err.same_key", f.Name)
			return
		}
	}
	preview := strings.Join([]string{
		"conductor-files " + string(filesapi.OpEnroll),
		"address: " + addr,
		"agent key (pinned by conductor, from the code): " + pin,
		"conductor key (pinned by the agent): " + s.files.Pin(),
		"conductor name: " + s.files.Name(),
	}, "\n")
	p := &pendingOp{perm: PermFilesWrite, action: "files.enroll", target: addr, reauth: true, reauthKey: "files.reauth",
		title: rc.T("files.new.confirm_title"), summary: rc.T("files.new.confirm_summary", addr), preview: preview,
		back: "/admin/files", done: rc.T("files.new.done")}
	p.run = func(ctx context.Context, rc *reqCtx) error {
		var res filesapi.EnrollResult
		if err := s.filesCallPin(ctx, rc, addr, pin, filesapi.OpEnroll, filesapi.EnrollParams{Token: token, Name: s.files.Name()}, &res); err != nil {
			return err
		}
		if res.AgentPin != pin {
			return &filesTransportError{err: &filesapi.PinMismatchError{Want: pin, Got: res.AgentPin}}
		}
		name := res.Hostname
		if name == "" {
			name, _, _ = net.SplitHostPort(addr)
		}
		srv := store.FileServer{ID: newToken()[:16], Name: name, Address: addr, AgentPin: pin, EnrolledAt: s.now(),
			EnrolledBy: rc.sess.sam, AgentVersion: res.Version}
		if err := s.store.AddFileServer(ctx, srv); err != nil {
			return err
		}
		p.back = serverURL(srv)
		p.done = rc.T("files.new.done_name", name)
		return nil
	}
	rc.propose(p)
}

func (s *Server) handleFileServer(rc *reqCtx) {
	srv, ok := s.fileServer(rc)
	if !ok {
		return
	}
	ctx, cancel := filesTimeout(rc)
	defer cancel()
	d := map[string]any{"S": srv, "CanWrite": rc.roles.Has(PermFilesWrite)}
	if s.files != nil {
		d["Pin"] = s.files.Pin()
	}
	st, e := s.statusOf(ctx, rc, srv, true)
	d["St"], d["StErr"] = st, e
	if st != nil {
		var shares []filesapi.ShareSummary
		if err := s.filesCall(ctx, rc, srv, filesapi.OpSharesList, nil, &shares); err != nil {
			d["Error"] = s.filesErr(rc, err)
		}
		d["Shares"] = shares
	}
	rc.render(http.StatusOK, "files_server", d)
}

func (s *Server) handleFileServerRemove(rc *reqCtx) {
	srv, ok := s.fileServer(rc)
	if !ok {
		return
	}
	preview := strings.Join([]string{
		"conductor-files " + string(filesapi.OpUnenroll),
		"server: " + srv.Name + " (" + srv.Address + ")",
		"agent key: " + srv.AgentPin,
		"# the agent drops conductor's key; conductor forgets the server and its key",
		"# shares on the server are not changed",
	}, "\n")
	p := &pendingOp{perm: PermFilesWrite, action: "files.remove_server", target: srv.Name, reauth: true, reauthKey: "files.reauth",
		title: rc.T("files.remove.title", srv.Name), summary: rc.T("files.remove.summary"), preview: preview,
		back: "/admin/files", done: rc.T("files.remove.done", srv.Name)}
	p.run = func(ctx context.Context, rc *reqCtx) error {
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := s.filesCall(cctx, rc, srv, filesapi.OpUnenroll, nil, nil)
		cancel()
		if err != nil {
			// The server may be gone; conductor still forgets it, and says
			// how to revoke on the server.
			s.log.Warn("unenroll failed; removing the server anyway", "server", srv.Name, "err", err)
			p.done = rc.T("files.remove.done_unreachable", srv.Name, conductorPinHint(s))
		}
		s.forgetStatus(srv.ID)
		return s.store.RemoveFileServer(ctx, srv.ID)
	}
	rc.propose(p)
}

func conductorPinHint(s *Server) string {
	if s.files == nil {
		return ""
	}
	return s.files.Pin()
}

func (s *Server) handleFileSessions(rc *reqCtx) {
	srv, ok := s.fileServer(rc)
	if !ok {
		return
	}
	ctx, cancel := filesTimeout(rc)
	defer cancel()
	d := map[string]any{"S": srv}
	var ss filesapi.Sessions
	if err := s.filesCall(ctx, rc, srv, filesapi.OpSessionsList, nil, &ss); err != nil {
		d["Error"] = s.filesErr(rc, err)
	} else {
		d["X"] = ss
	}
	rc.render(http.StatusOK, "files_sessions", d)
}

// shareName reads and checks the {name} path value.
func shareName(rc *reqCtx) (string, bool) {
	n := rc.r.PathValue("name")
	if (filesapi.ShareNameParams{Name: n}).Validate() != nil {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return "", false
	}
	return n, true
}

func (s *Server) handleFileShare(rc *reqCtx) {
	srv, ok := s.fileServer(rc)
	if !ok {
		return
	}
	name, ok := shareName(rc)
	if !ok {
		return
	}
	ctx, cancel := filesTimeout(rc)
	defer cancel()
	d := map[string]any{"S": srv, "CanWrite": rc.roles.Has(PermFilesWrite)}
	var sd filesapi.ShareDetail
	if err := s.filesCall(ctx, rc, srv, filesapi.OpShareGet, filesapi.ShareNameParams{Name: name}, &sd); err != nil {
		if filesapi.ErrorCodeOf(err) == filesapi.CodeNotFound {
			rc.errorPage(http.StatusNotFound, "err.not_found")
			return
		}
		d["Error"] = s.filesErr(rc, err)
		sd = filesapi.ShareDetail{}
	}
	d["X"] = sd
	rc.render(http.StatusOK, "files_share", d)
}

func (s *Server) handleFileShareRemove(rc *reqCtx) {
	srv, ok := s.fileServer(rc)
	if !ok {
		return
	}
	name, ok := shareName(rc)
	if !ok {
		return
	}
	ctx, cancel := filesTimeout(rc)
	defer cancel()
	var pl filesapi.Plan
	if err := s.filesCall(ctx, rc, srv, filesapi.OpShareRemovePlan, filesapi.ShareNameParams{Name: name}, &pl); err != nil {
		rc.sess.addFlash("error", s.filesErr(rc, err))
		rc.redirect(shareURL(srv, name))
		return
	}
	digest := pl.Digest
	p := &pendingOp{perm: PermFilesWrite, action: "files.share_remove", target: srv.Name + "/" + pl.Name, reauth: true, reauthKey: "files.reauth",
		title: rc.T("files.share.remove_title", pl.Name), summary: rc.T("files.share.remove_summary", pl.Name, srv.Name),
		warning: s.planWarnings(rc, pl), preview: planText(pl, srv), files: planView(pl), back: serverURL(srv),
		done: rc.T("files.share.removed", pl.Name)}
	p.run = func(ctx context.Context, rc *reqCtx) error {
		var ar filesapi.ApplyResult
		return s.filesCall(ctx, rc, srv, filesapi.OpShareRemove, filesapi.ShareNameParams{Name: pl.Name, Digest: digest}, &ar)
	}
	rc.propose(p)
}

// ---- plan rendering ----

// aclLine is one entry of an ACL diff.
type aclLine struct {
	Mark string // "+", "-" or " "
	ACE  filesapi.ACE
}

func aceKey(a filesapi.ACE) string { return fmt.Sprintf("%s|%s|%d|%s", a.Type, a.SID, a.Mask, a.Flags) }

// aclDiff lists removed entries first, then the new ACL marking additions.
func aclDiff(before, after []filesapi.ACE) []aclLine {
	in := func(list []filesapi.ACE, a filesapi.ACE) bool {
		for _, x := range list {
			if aceKey(x) == aceKey(a) {
				return true
			}
		}
		return false
	}
	var out []aclLine
	for _, b := range before {
		if !in(after, b) {
			out = append(out, aclLine{"-", b})
		}
	}
	for _, a := range after {
		mark := "+"
		if in(before, a) {
			mark = " "
		}
		out = append(out, aclLine{mark, a})
	}
	return out
}

// filesPlanView is the structured preview of a plan (confirm page).
type filesPlanView struct {
	P        filesapi.Plan
	ShareACL []aclLine
	NTACL    []aclLine
}

func planView(pl filesapi.Plan) *filesPlanView {
	v := &filesPlanView{P: pl, ShareACL: aclDiff(pl.ShareACL.Before, pl.ShareACL.After)}
	if pl.Kind != "remove" {
		v.NTACL = aclDiff(pl.NTACL.Before, pl.NTACL.After)
	}
	return v
}

// planText is the exact change as text: shown, and kept in the audit log.
func planText(pl filesapi.Plan, srv store.FileServer) string {
	var b strings.Builder
	op := filesapi.OpShareApply
	if pl.Kind == "remove" {
		op = filesapi.OpShareRemove
	}
	fmt.Fprintf(&b, "conductor-files %s (%s)\nserver: %s (%s)\nshare: %s\nfolder: %s", op, pl.Kind, srv.Name, srv.Address, pl.Name, pl.Path)
	if pl.CreateDir {
		b.WriteString(" (new)")
	}
	fmt.Fprintf(&b, "\ndigest: %s\n", pl.Digest)
	if pl.Kind == "remove" {
		b.WriteString("\n# registry configuration removed\n" + pl.SectionBefore)
	} else {
		if pl.SectionBefore != "" && pl.SectionBefore != pl.Section {
			b.WriteString("\n# registry configuration before\n" + pl.SectionBefore)
		}
		b.WriteString("\n# registry configuration (net conf import replaces the section)\n" + pl.Section)
	}
	b.WriteString("\n# share permissions (sharesec)\n")
	for _, l := range aclDiff(pl.ShareACL.Before, pl.ShareACL.After) {
		b.WriteString(l.Mark + " " + l.ACE.String() + "\n")
	}
	if pl.Kind != "remove" {
		fmt.Fprintf(&b, "\n# NT ACL of %s (protected; inherited by new files and folders)\n", pl.Path)
		for _, l := range aclDiff(pl.NTACL.Before, pl.NTACL.After) {
			b.WriteString(l.Mark + " " + l.ACE.String() + "\n")
		}
	}
	b.WriteString("\n# commands, in order\n" + strings.Join(pl.Commands, "\n"))
	return b.String()
}

// planWarnings translates the agent's warnings.
func (s *Server) planWarnings(rc *reqCtx, pl filesapi.Plan) string {
	var out []string
	for _, w := range pl.Warnings {
		msg := rc.T("files.warn."+w.Code, w.Arg)
		if strings.HasPrefix(msg, "[") {
			msg = w.Code + " " + w.Arg
		}
		out = append(out, msg)
	}
	return strings.Join(out, " ")
}
