package web

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openbasalt/samba-conductor-provisioner/provapi"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// provApplier is the g2aApplier that runs plan operations through
// conductor-provisioner's plan operations (user.create, user.update,
// user.set_enabled, user.move). Every request names the operation's
// marker, so the provisioner refuses an account linked to another Google
// ID, and carries a one-line reference ("g2a run <id> op <seq>") kept in
// the provisioner's own audit log.
type provApplier struct {
	call func(ctx context.Context, actor provapi.Actor, op provapi.Op, params provapi.Params, out any) error
}

// errG2AOp: an operation the plan describes incompletely (no SID for an
// existing account, no OU for a create).
var errG2AOp = errors.New("web: the plan operation lacks what conductor-provisioner needs")

func g2aRef(ref string, op syncapi.G2AOp) string { return fmt.Sprintf("%s op %d", ref, op.Seq) }

// changes converts a plan operation's changes to provisioner changes
// (same attribute names; multi-valued attributes use the same sorted,
// newline-joined form).
func provChanges(op syncapi.G2AOp) []provapi.UserChange {
	out := make([]provapi.UserChange, 0, len(op.Changes))
	for _, c := range op.Changes {
		out = append(out, provapi.UserChange{Attr: c.Field, Before: c.Before, After: c.After})
	}
	return out
}

func (a provApplier) update(ctx context.Context, actor provapi.Actor, ref string, op syncapi.G2AOp) error {
	if op.SID == "" {
		return errG2AOp
	}
	return a.call(ctx, actor, provapi.OpUserUpdate, &provapi.UserUpdateParams{SID: op.SID, Changes: provChanges(op), Marker: op.Marker,
		Reference: g2aRef(ref, op)}, &provapi.UserWriteResult{})
}

// Update writes Google's values of the owned attributes.
func (a provApplier) Update(ctx context.Context, actor provapi.Actor, ref string, op syncapi.G2AOp) error {
	return a.update(ctx, actor, ref, op)
}

// Rename is an update of mail and proxyAddresses.
func (a provApplier) Rename(ctx context.Context, actor provapi.Actor, ref string, op syncapi.G2AOp) error {
	return a.update(ctx, actor, ref, op)
}

func (a provApplier) setEnabled(ctx context.Context, actor provapi.Actor, ref string, op syncapi.G2AOp, enabled bool) error {
	return a.call(ctx, actor, provapi.OpUserSetEnabled, &provapi.UserSetEnabledParams{SID: op.SID, Enabled: enabled, Marker: op.Marker,
		Reference: g2aRef(ref, op)}, &provapi.UserWriteResult{})
}

func (a provApplier) move(ctx context.Context, actor provapi.Actor, ref string, op syncapi.G2AOp) error {
	return a.call(ctx, actor, provapi.OpUserMove, &provapi.UserMoveParams{SID: op.SID, ToOU: op.MoveTo, Marker: op.Marker,
		Reference: g2aRef(ref, op)}, &provapi.UserWriteResult{})
}

// Reenable moves the account back to the managed OU, then enables it.
func (a provApplier) Reenable(ctx context.Context, actor provapi.Actor, ref string, op syncapi.G2AOp) error {
	if op.SID == "" {
		return errG2AOp
	}
	if op.MoveTo != "" {
		if err := a.move(ctx, actor, ref, op); err != nil {
			return err
		}
	}
	if op.Enable {
		return a.setEnabled(ctx, actor, ref, op, true)
	}
	return nil
}

// Disable disables the account (the provisioner also revokes its open
// links), then moves it to the quarantine OU.
func (a provApplier) Disable(ctx context.Context, actor provapi.Actor, ref string, op syncapi.G2AOp) error {
	if op.SID == "" {
		return errG2AOp
	}
	if op.Disable {
		if err := a.setEnabled(ctx, actor, ref, op, false); err != nil {
			return err
		}
	}
	if op.MoveTo != "" {
		return a.move(ctx, actor, ref, op)
	}
	return nil
}

// Create creates the account, disabled, with a random password the
// provisioner generates and never returns.
func (a provApplier) Create(ctx context.Context, actor provapi.Actor, ref string, op syncapi.G2AOp) (g2aCreated, error) {
	if op.ParentOU == "" {
		return g2aCreated{}, errG2AOp
	}
	p := &provapi.UserCreateParams{ScopeOU: op.ParentOU, Marker: op.Marker, Reference: g2aRef(ref, op), Fields: map[string]string{}}
	for _, c := range op.Changes {
		switch c.Field {
		case "sAMAccountName":
			p.SAM = c.After
		case "userPrincipalName":
			p.UPN = c.After
		case "cn":
			p.CN = c.After
		case "mail":
			p.Mail = c.After
		case "givenName":
			p.GivenName = c.After
		case "sn":
			p.Sn = c.After
		case "displayName":
			p.DisplayName = c.After
		default:
			if c.After != "" {
				p.Fields[c.Field] = c.After
			}
		}
	}
	if p.SAM == "" {
		p.SAM = op.SAM
	}
	if len(p.Fields) == 0 {
		p.Fields = nil
	}
	var res provapi.UserCreateResult
	if err := a.call(ctx, actor, provapi.OpUserCreate, p, &res); err != nil {
		return g2aCreated{}, err
	}
	return g2aCreated{SID: res.SID, ObjectGUID: res.ObjectGUID}, nil
}

// g2aErrKey is the message key of a failed plan operation.
func g2aErrKey(err error) string {
	if errors.Is(err, errG2AOp) || errors.Is(err, errG2AUnsupported) {
		return "gf.op.err.plan"
	}
	switch provapi.ErrorCodeOf(err) {
	case provapi.CodeExists:
		return "gf.op.err.exists"
	case provapi.CodeConflict:
		return "gf.op.err.conflict"
	case provapi.CodeMarkerMismatch:
		return "gf.op.err.marker_mismatch"
	case provapi.CodeSchemaMissing:
		return "gf.op.err.schema_missing"
	case provapi.CodePrivileged:
		return "gf.op.err.privileged"
	}
	return provErrKey(err)
}

// g2aErrKinds are the error's kinds (what collided, the attributes in
// conflict, the privilege reasons).
func g2aErrKinds(err error) string {
	var pe *provapi.Error
	if errors.As(err, &pe) && len(pe.Kinds) > 0 {
		return strings.Join(pe.Kinds, ", ")
	}
	return ""
}
