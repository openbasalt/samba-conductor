package web

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor/internal/directory"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// Bulk jobs: a CSV import or an action on selected accounts becomes a job.
// Every row is validated and built into ad.Operations first; any invalid
// row stops the whole job before anything is written (never a silent
// partial apply). The full preview of every row is shown, then the job is
// applied in the background with the user's own credentials, row by row,
// each row audited and its result stored (SQLite), so the report survives
// a restart and failed or unattempted rows can be validated and applied
// again ("retry").

// bulkRow is one row of a job.
type bulkRow struct {
	No     int
	Label  string
	Target string
	Input  map[string]string
	ops    []*ad.Operation
	// Preview is the LDIF of every operation of the row (secrets redacted).
	Preview string
	Status  string
	Error   string
	// password generated for the row (create, reset), memory only.
	password string
}

// bulkJob is a job held in memory while it can still be applied, run or
// show its generated passwords.
type bulkJob struct {
	mu       sync.Mutex
	ID       string
	Kind     string
	Title    string
	ownerSID string
	owner    string
	session  string // hash of the creating session (passwords are shown there only)
	perm     Perm
	Reauth   bool
	Rows     []*bulkRow
	Status   string
	created  time.Time
	// Passwords are shown and downloadable until dismissed.
	passwordsLeft bool
}

// rowError is a validation error of one input row.
type rowError struct {
	No    int
	Label string
	Msg   string
}

// jobs is the in-memory part of bulk jobs (SQLite keeps the reports).
type jobs struct {
	mu   sync.Mutex
	byID map[string]*bulkJob
}

const (
	maxJobsInMemory = 50
	jobMemoryTTL    = 24 * time.Hour
)

func (j *jobs) put(job *bulkJob, now time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.byID == nil {
		j.byID = map[string]*bulkJob{}
	}
	for id, old := range j.byID {
		old.mu.Lock()
		stale := now.Sub(old.created) > jobMemoryTTL && old.Status != store.JobRunning
		old.mu.Unlock()
		if stale {
			delete(j.byID, id)
		}
	}
	if len(j.byID) >= maxJobsInMemory {
		var oldest *bulkJob
		for _, o := range j.byID {
			if o.Status != store.JobRunning && (oldest == nil || o.created.Before(oldest.created)) {
				oldest = o
			}
		}
		if oldest != nil {
			delete(j.byID, oldest.ID)
		}
	}
	j.byID[job.ID] = job
}

func (j *jobs) get(id string) *bulkJob {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.byID[id]
}

// newPassword generates a random password that satisfies AD complexity
// (upper, lower, digit and symbol; 20 characters).
func newPassword() string {
	const (
		upper  = "ABCDEFGHJKLMNPQRSTUVWXYZ"
		lower  = "abcdefghijkmnopqrstuvwxyz"
		digits = "23456789"
		symb   = "!#%+-=?@"
	)
	pick := func(set string) byte {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			panic(err)
		}
		return set[n.Int64()]
	}
	all := upper + lower + digits + symb
	b := []byte{pick(upper), pick(lower), pick(digits), pick(symb)}
	for len(b) < 20 {
		b = append(b, pick(all))
	}
	for i := len(b) - 1; i > 0; i-- {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		j := int(n.Int64())
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

// rowPreview renders the operations of a row.
func rowPreview(ops []*ad.Operation) string {
	parts := make([]string, 0, len(ops))
	for _, op := range ops {
		parts = append(parts, op.Preview().String())
	}
	return strings.Join(parts, "\n")
}

// jobBuilder turns stored inputs into rows; the same builder serves the
// first preview and a retry of failed rows.
type jobBuilder func(ctx context.Context, rc *reqCtx, conn *ad.Conn, inputs []map[string]string) ([]*bulkRow, []rowError, bool, error)

func (s *Server) builderFor(kind string) (jobBuilder, Perm) {
	switch {
	case kind == "import-create":
		return s.buildImportCreate, PermBulk
	case kind == "import-update":
		return s.buildImportUpdate, PermBulk
	case strings.HasPrefix(kind, "selected-"):
		action := strings.TrimPrefix(kind, "selected-")
		return func(ctx context.Context, rc *reqCtx, conn *ad.Conn, inputs []map[string]string) ([]*bulkRow, []rowError, bool, error) {
			return s.buildSelected(ctx, rc, conn, action, inputs)
		}, selectedPerm(action)
	}
	return nil, ""
}

// createJob validates every input, then stores the job and sends the
// browser to its preview. With errors, nothing is stored and the errors
// are rendered by fail.
func (s *Server) createJob(rc *reqCtx, kind, title string, inputs []map[string]string, fail func(errs []rowError)) {
	build, perm := s.builderFor(kind)
	if build == nil {
		rc.errorPage(http.StatusBadRequest, "form.invalid")
		return
	}
	if !rc.roles.Has(perm) {
		s.audit(rc.ctx(), rc, "access.denied", kind, "requires "+string(perm), store.ResultDenied)
		rc.errorPage(http.StatusForbidden, "err.forbidden")
		return
	}
	if len(inputs) == 0 {
		fail([]rowError{{Msg: rc.T("bulk.err.no_rows")}})
		return
	}
	if len(inputs) > s.cfg.Bulk.MaxRows {
		fail([]rowError{{Msg: rc.T("bulk.err.too_many", s.cfg.Bulk.MaxRows)}})
		return
	}
	ctx, cancel := context.WithTimeout(rc.ctx(), 5*requestTimeout)
	defer cancel()
	var rows []*bulkRow
	var errs []rowError
	var reauth bool
	err := rc.withConn(ctx, func(conn *ad.Conn) error {
		var err error
		rows, errs, reauth, err = build(ctx, rc, conn, inputs)
		return err
	})
	if err != nil {
		rc.failed(err)
		return
	}
	if len(errs) > 0 {
		fail(errs)
		return
	}
	rc.sess.mu.Lock()
	job := &bulkJob{ID: newToken()[:22], Kind: kind, Title: title, ownerSID: rc.sess.userSID.String(), owner: rc.sess.sam,
		session: rc.sess.hash, perm: perm, Reauth: reauth || strings.HasPrefix(kind, "import-") || kind == "selected-delete",
		Rows: rows, Status: store.JobPreviewed, created: s.now()}
	rc.sess.mu.Unlock()
	stored := make([]store.BulkRow, len(rows))
	for i, r := range rows {
		in, _ := json.Marshal(r.Input)
		if len(r.ops) == 0 {
			r.Status = store.RowSkipped
		} else {
			r.Status = store.RowPending
		}
		stored[i] = store.BulkRow{No: r.No, Label: r.Label, Target: r.Target, Input: string(in), Preview: r.Preview}
	}
	if err := s.store.CreateBulkJob(rc.ctx(), store.BulkJob{ID: job.ID, Kind: kind, OwnerSID: job.ownerSID, OwnerName: job.owner}, stored); err != nil {
		s.log.Error("storing bulk job", "err", err)
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	for _, r := range rows {
		if r.Status == store.RowSkipped {
			_ = s.store.SetBulkRowResult(rc.ctx(), job.ID, r.No, store.RowSkipped, "no change")
		}
	}
	s.jobs.put(job, s.now())
	s.audit(rc.ctx(), rc, "bulk.preview", job.ID, fmt.Sprintf("kind=%s rows=%d", kind, len(rows)), store.ResultPending)
	rc.redirect("/admin/bulk/" + job.ID)
}

// jobForOwner returns a job only to its owner (administrators may read any
// job's stored report).
func (s *Server) jobForOwner(rc *reqCtx) (*bulkJob, store.BulkJob, bool) {
	id := rc.r.PathValue("id")
	if len(id) != 22 {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return nil, store.BulkJob{}, false
	}
	stored, err := s.store.GetBulkJob(rc.ctx(), id)
	if err != nil {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return nil, stored, false
	}
	rc.sess.mu.Lock()
	me := rc.sess.userSID.String()
	rc.sess.mu.Unlock()
	if stored.OwnerSID != me && !rc.roles.Admin {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return nil, stored, false
	}
	job := s.jobs.get(id)
	if job != nil && job.ownerSID != me {
		job = nil // others see the stored report only
	}
	return job, stored, true
}

func (s *Server) handleBulkJob(rc *reqCtx) {
	job, stored, ok := s.jobForOwner(rc)
	if !ok {
		return
	}
	rows, err := s.store.BulkRows(rc.ctx(), stored.ID)
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	counts := map[string]int{}
	for _, r := range rows {
		counts[r.Status]++
	}
	d := map[string]any{"Job": stored, "Rows": rows, "Counts": counts, "Live": job != nil}
	if job != nil {
		job.mu.Lock()
		d["Reauth"] = job.Reauth && job.Status == store.JobPreviewed
		d["Title"] = job.Title
		if job.passwordsLeft && job.Status == store.JobDone {
			rc.sess.mu.Lock()
			same := rc.sess.hash == job.session
			rc.sess.mu.Unlock()
			if same {
				var pws [][2]string
				for _, r := range job.Rows {
					if r.password != "" && r.Status == store.RowOK {
						pws = append(pws, [2]string{r.Label, r.password})
					}
				}
				d["Passwords"] = pws
			}
		}
		job.mu.Unlock()
	}
	if stored.Status == store.JobRunning {
		d["Refresh"] = true
	}
	d["Retry"] = stored.Status == store.JobDone && (counts[store.RowFailed] > 0 || counts[store.RowPending] > 0) ||
		stored.Status == store.JobInterrupted
	d["CanApply"] = job != nil && stored.Status == store.JobPreviewed
	d["HasKeys"] = s.hasKeys(rc)
	rc.render(http.StatusOK, "bulk_job", d)
}

func (s *Server) handleBulkCancel(rc *reqCtx) {
	job, stored, ok := s.jobForOwner(rc)
	if !ok {
		return
	}
	if job == nil || stored.Status != store.JobPreviewed {
		rc.redirect("/admin/bulk/" + stored.ID)
		return
	}
	job.mu.Lock()
	job.Status = store.JobCancelled
	job.mu.Unlock()
	_ = s.store.SetBulkJobStatus(rc.ctx(), stored.ID, store.JobCancelled)
	s.audit(rc.ctx(), rc, "bulk.cancel", stored.ID, stored.Kind, store.ResultOK)
	rc.flashOK("confirm.cancelled")
	rc.redirect("/admin/bulk/" + stored.ID)
}

func (s *Server) handleBulkApply(rc *reqCtx) {
	job, stored, ok := s.jobForOwner(rc)
	if !ok {
		return
	}
	if job == nil || stored.Status != store.JobPreviewed {
		rc.errorPage(http.StatusConflict, "bulk.err.not_pending")
		return
	}
	// The permission is checked again (roles may have changed).
	roles, err := s.rolesFor(rc.ctx(), rc.sess)
	if err != nil || !roles.Has(job.perm) {
		s.audit(rc.ctx(), rc, "access.denied", stored.ID, "bulk apply requires "+string(job.perm), store.ResultDenied)
		rc.errorPage(http.StatusForbidden, "err.forbidden")
		return
	}
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	if job.Reauth {
		if key := s.reauthenticate(ctx, rc); key != "" {
			s.audit(ctx, rc, "bulk.apply", stored.ID, "re-authentication failed", store.ResultDenied)
			rc.flashErr(key)
			rc.redirect("/admin/bulk/" + stored.ID)
			return
		}
	}
	job.mu.Lock()
	if job.Status != store.JobPreviewed {
		job.mu.Unlock()
		rc.errorPage(http.StatusConflict, "bulk.err.not_pending")
		return
	}
	job.Status = store.JobRunning
	job.mu.Unlock()
	if err := s.store.SetBulkJobStatus(rc.ctx(), stored.ID, store.JobRunning); err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	rc.sess.mu.Lock()
	cred := rc.sess.cred
	rc.sess.mu.Unlock()
	// The audit of each row keeps the actor, address and agent of this
	// request.
	actx := &reqCtx{s: s, r: rc.r.Clone(context.Background()), sess: rc.sess, ip: rc.ip}
	s.audit(ctx, rc, "bulk.apply", stored.ID, fmt.Sprintf("kind=%s rows=%d", stored.Kind, len(job.Rows)), store.ResultPending)
	s.bgJobs.Add(1)
	go func() {
		defer s.bgJobs.Done()
		s.runJob(job, cred, actx)
	}()
	rc.redirect("/admin/bulk/" + stored.ID)
}

// rowTimeout bounds one row's writes.
const rowTimeout = time.Minute

// runJob applies a job's rows in order with the owner's credential. A
// failed row does not stop the job (rows are independent); a row whose
// first operations succeeded before a later one failed is reported as
// failed with how far it got.
func (s *Server) runJob(job *bulkJob, cred *directory.Credential, actx *reqCtx) {
	bg := context.Background()
	var conn *ad.Conn
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	for _, row := range job.Rows {
		job.mu.Lock()
		skip := row.Status != store.RowPending
		job.mu.Unlock()
		if skip {
			continue
		}
		ctx, cancel := context.WithTimeout(bg, rowTimeout)
		status, msg := store.RowOK, ""
		var err error
		done := 0
		var perDC []ad.DCResult
		{
			for _, op := range row.ops {
				if len(op.DCs()) > 0 {
					// Written on every DC with its own bindings.
					var res []ad.DCResult
					res, err = s.applyOnEveryDC(ctx, cred, op)
					perDC = append(perDC, res...)
				} else {
					if conn == nil {
						if conn, err = s.backend.Connect(ctx, cred); err != nil {
							break
						}
					}
					err = conn.Apply(ctx, op)
				}
				if err != nil {
					break
				}
				done++
			}
		}
		if len(perDC) > 0 {
			// The report names what happened on every DC.
			msg = dcReport(actx.T, perDC)
		}
		if err != nil {
			status = store.RowFailed
			msg = s.errMessage(actx.T, err)
			if done > 0 {
				msg = fmt.Sprintf("%s (%d/%d)", msg, done, len(row.ops))
			}
			s.log.Warn("bulk row failed", "job", job.ID, "row", row.No, "err", err)
			if conn != nil && !errors.Is(err, ad.ErrAccessDenied) && !errors.Is(err, ad.ErrConflict) && !errors.Is(err, ad.ErrNotFound) &&
				!errors.Is(err, ad.ErrAlreadyExists) && !errors.Is(err, ad.ErrPasswordPolicy) {
				// Possibly a broken connection: reconnect for the next row.
				_ = conn.Close()
				conn = nil
			}
		}
		cancel()
		job.mu.Lock()
		row.Status, row.Error = status, msg
		if status != store.RowOK {
			row.password = ""
		}
		job.mu.Unlock()
		_ = s.store.SetBulkRowResult(bg, job.ID, row.No, status, msg)
		result := store.ResultOK
		if status != store.RowOK {
			result = resultOf(err)
		}
		detail := fmt.Sprintf("job %s row %d\n%s", job.ID, row.No, row.Preview)
		if len(perDC) > 0 {
			detail += "\n# per DC: " + dcReport(func(k string, a ...any) string { return s.cat.T("en", k, a...) }, perDC)
		}
		if msg != "" && status != store.RowOK {
			detail += "\n# error: " + msg
		}
		s.audit(bg, actx, "bulk."+job.Kind, row.Target, detail, result)
	}
	job.mu.Lock()
	job.Status = store.JobDone
	for _, r := range job.Rows {
		if r.password != "" {
			job.passwordsLeft = true
		}
	}
	job.mu.Unlock()
	_ = s.store.SetBulkJobStatus(bg, job.ID, store.JobDone)
	s.audit(bg, actx, "bulk.done", job.ID, job.Kind, store.ResultOK)
}

func (s *Server) handleBulkReport(rc *reqCtx) {
	_, stored, ok := s.jobForOwner(rc)
	if !ok {
		return
	}
	rows, err := s.store.BulkRows(rc.ctx(), stored.ID)
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	rc.w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	rc.w.Header().Set("Content-Disposition", `attachment; filename="conductor-bulk-`+stored.ID+`.csv"`)
	w := newCSVWriter(rc.w)
	_ = w.Write([]string{"row", "label", "target", "status", "error"})
	for _, r := range rows {
		_ = w.Write([]string{strconv.Itoa(r.No), csvCell(r.Label), csvCell(r.Target), r.Status, csvCell(r.Error)})
	}
	w.Flush()
}

func (s *Server) handleBulkPreviewLDIF(rc *reqCtx) {
	_, stored, ok := s.jobForOwner(rc)
	if !ok {
		return
	}
	rows, err := s.store.BulkRows(rc.ctx(), stored.ID)
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	rc.w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rc.w.Header().Set("Content-Disposition", `attachment; filename="conductor-bulk-`+stored.ID+`.ldif"`)
	for _, r := range rows {
		fmt.Fprintf(rc.w, "# row %d: %s\n%s\n", r.No, r.Label, r.Preview)
	}
}

// handleBulkPasswords downloads the generated passwords once (CSV), only
// to the session that ran the job; then they are forgotten.
func (s *Server) handleBulkPasswords(rc *reqCtx) {
	job, stored, ok := s.jobForOwner(rc)
	if !ok {
		return
	}
	if job == nil {
		rc.errorPage(http.StatusGone, "bulk.err.passwords_gone")
		return
	}
	rc.sess.mu.Lock()
	same := rc.sess.hash == job.session
	rc.sess.mu.Unlock()
	job.mu.Lock()
	if !same || !job.passwordsLeft || job.Status != store.JobDone {
		job.mu.Unlock()
		rc.errorPage(http.StatusGone, "bulk.err.passwords_gone")
		return
	}
	var lines [][]string
	for _, r := range job.Rows {
		if r.password != "" && r.Status == store.RowOK {
			lines = append(lines, []string{csvCell(r.Label), r.password})
		}
		r.password = ""
	}
	job.passwordsLeft = false
	job.mu.Unlock()
	if rc.r.Method == http.MethodPost && rc.form("dismiss") == "1" {
		s.audit(rc.ctx(), rc, "bulk.passwords_dismissed", stored.ID, "", store.ResultOK)
		rc.redirect("/admin/bulk/" + stored.ID)
		return
	}
	s.audit(rc.ctx(), rc, "bulk.passwords_downloaded", stored.ID, "rows="+itoa(len(lines)), store.ResultOK)
	rc.w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	rc.w.Header().Set("Content-Disposition", `attachment; filename="conductor-passwords-`+stored.ID+`.csv"`)
	w := newCSVWriter(rc.w)
	_ = w.Write([]string{"username", "password"})
	for _, l := range lines {
		_ = w.Write(l)
	}
	w.Flush()
}

// handleBulkRetry validates the failed and unattempted rows of a finished
// or interrupted job again and makes a new job of them.
func (s *Server) handleBulkRetry(rc *reqCtx) {
	_, stored, ok := s.jobForOwner(rc)
	if !ok {
		return
	}
	if stored.Status != store.JobDone && stored.Status != store.JobInterrupted {
		rc.errorPage(http.StatusConflict, "bulk.err.not_finished")
		return
	}
	rows, err := s.store.BulkRows(rc.ctx(), stored.ID)
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	var inputs []map[string]string
	for _, r := range rows {
		if r.Status != store.RowFailed && r.Status != store.RowPending {
			continue
		}
		in := map[string]string{}
		if err := json.Unmarshal([]byte(r.Input), &in); err == nil {
			inputs = append(inputs, in)
		}
	}
	s.createJob(rc, stored.Kind, rc.T("bulk.retry_title", stored.ID), inputs, func(errs []rowError) {
		rc.render(http.StatusBadRequest, "bulk_errors", map[string]any{"Errors": errs, "Back": "/admin/bulk/" + stored.ID})
	})
}

// handleBulkIndex shows the import forms and recent jobs.
func (s *Server) handleBulkIndex(rc *reqCtx) {
	owner := rc.sess.userSID.String()
	if rc.roles.Admin {
		owner = ""
	}
	list, err := s.store.ListBulkJobs(rc.ctx(), owner, 30)
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	rc.render(http.StatusOK, "bulk", map[string]any{"Jobs": list, "MaxRows": s.cfg.Bulk.MaxRows,
		"CreateColumns": strings.Join(createColumns, ","), "UpdateColumns": strings.Join(updateColumns, ",")})
}

// sortedErrors orders validation errors by row.
func sortedErrors(errs []rowError) []rowError {
	sort.SliceStable(errs, func(i, j int) bool { return errs[i].No < errs[j].No })
	return errs
}

// userByGUIDString loads a user from a GUID string of an input row.
func userByGUIDString(ctx context.Context, conn *ad.Conn, s string) (ad.User, error) {
	g, err := sid.ParseGUID(s)
	if err != nil {
		return ad.User{}, errNotFoundPage
	}
	return userByGUID(ctx, conn, g)
}
