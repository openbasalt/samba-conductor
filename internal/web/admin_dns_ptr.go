package web

import (
	"context"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// The matching PTR record of a new A or AAAA record. When the address lies
// in a reverse zone of the directory, the record form offers (unchecked by
// default) to add the PTR record too: it is planned in the preview of the
// address record and added after it, as its own change with its own audit
// entry, through the same ad validation and with the same connection
// (the signed-in user's). An existing PTR record is never changed, and a
// failed PTR record never undoes the address record.

// reverseName returns the full reverse lookup name of the address of an
// A record (d.c.b.a.in-addr.arpa) or of an AAAA record (32 nibbles under
// ip6.arpa, even for an IPv4-mapped address).
func reverseName(t ad.DNSType, a netip.Addr) string {
	var labels []string
	if t == ad.DNSTypeA {
		b := a.Unmap().As4()
		for i := len(b) - 1; i >= 0; i-- {
			labels = append(labels, strconv.Itoa(int(b[i])))
		}
		return strings.Join(labels, ".") + ".in-addr.arpa"
	}
	b := a.As16()
	h := hex.EncodeToString(b[:])
	for i := len(h) - 1; i >= 0; i-- {
		labels = append(labels, string(h[i]))
	}
	return strings.Join(labels, ".") + ".ip6.arpa"
}

// coveringReverseZone picks the most specific reverse zone that holds the
// reverse name of the address of an A or AAAA record (the longest zone
// name the reverse name ends with, on a label boundary) and returns it
// with the name relative to it.
func coveringReverseZone(zones []ad.DNSZone, t ad.DNSType, a netip.Addr) (ad.DNSZone, string, bool) {
	switch {
	case t == ad.DNSTypeA && a.Unmap().Is4():
	case t == ad.DNSTypeAAAA && a.Is6():
	default:
		return ad.DNSZone{}, "", false
	}
	full := reverseName(t, a)
	var best ad.DNSZone
	var bestLen int
	var rel string
	for _, z := range zones {
		zn := strings.ToLower(strings.TrimSuffix(z.Name, "."))
		// full is an in-addr.arpa or ip6.arpa name, so a zone it ends with
		// is a reverse zone.
		if !strings.HasSuffix(full, "."+zn) || len(zn) <= bestLen {
			continue
		}
		best, bestLen, rel = z, len(zn), strings.TrimSuffix(full, "."+zn)
	}
	return best, rel, bestLen > 0
}

// ptrState is what a reverse name already holds for a planned PTR record.
type ptrState int

const (
	ptrAbsent ptrState = iota // no live PTR record: the PTR record is added
	ptrSame                   // the same PTR record exists: nothing to do
	ptrOther                  // other PTR records exist: left as they are
)

// ptrStateOf compares the live PTR records of a node with the planned one
// and returns the other targets when there are some.
func ptrStateOf(node ad.DNSNode, ptr ad.DNSRecord) (ptrState, []string) {
	if node.Tombstoned {
		return ptrAbsent, nil
	}
	var others []string
	for _, r := range node.Records {
		if r.Type != ad.DNSTypePTR {
			continue
		}
		if r.Equal(ptr) || strings.EqualFold(strings.TrimSuffix(r.Data, "."), strings.TrimSuffix(ptr.Data, ".")) {
			return ptrSame, nil
		}
		others = append(others, r.Data)
	}
	if len(others) > 0 {
		return ptrOther, others
	}
	return ptrAbsent, nil
}

// reverseZoneNames lists the reverse zones (the record form shows them
// next to the PTR option, which it only offers when there is one).
func reverseZoneNames(zones []ad.DNSZone) []string {
	var out []string
	for _, z := range zones {
		if z.Reverse() {
			out = append(out, z.Name)
		}
	}
	return out
}

// planPTR adds the matching PTR record to the pending A/AAAA operation p:
// a preview note, and the after step that adds it (or only reports why it
// is not added). target is the FQDN of the address record's name.
func (s *Server) planPTR(ctx context.Context, rc *reqCtx, conn *ad.Conn, p *pendingOp, rec ad.DNSRecord, target string) error {
	addr, err := netip.ParseAddr(rec.Data)
	if err != nil {
		return nil // NewDNSRecord accepted it; nothing to plan otherwise
	}
	zones, err := conn.DNSZones(ctx)
	if err != nil {
		return err
	}
	rz, name, ok := coveringReverseZone(zones, rec.Type, addr)
	if !ok {
		p.previewNote += "\n# then: no PTR record, no reverse zone covers " + rec.Data
		p.warning = rc.T("dns.ptr.none", rec.Data)
		return nil
	}
	revFQDN := name + "." + rz.Name
	ptr, err := ad.NewDNSRecord(ad.DNSTypePTR, target, rec.TTL)
	if err != nil {
		// A wildcard name, for example, cannot be a PTR target.
		p.previewNote += "\n# then: no PTR record, " + target + " cannot be the target of one"
		p.warning = rc.T("dns.ptr.invalid", target)
		return nil
	}
	node, err := conn.DNSNodeByName(ctx, rz, name)
	if err != nil {
		return err
	}
	switch state, others := ptrStateOf(node, ptr); state {
	case ptrSame:
		p.previewNote += "\n# then: PTR " + revFQDN + " -> " + ptr.Data + " already exists, nothing to add"
	case ptrOther:
		p.previewNote += "\n# then: no PTR record, " + revFQDN + " already points to " + strings.Join(others, ", ") + " (not changed)"
		p.warning = rc.T("dns.ptr.other", revFQDN, strings.Join(others, ", "))
	default:
		p.previewNote += "\n# then: add PTR " + revFQDN + " -> " + ptr.Data + " in zone " + rz.Name + " (a change of its own, audited separately)"
	}
	p.after = s.addPTRAfter(rz.Name, name, ptr)
	return nil
}

// addPTRAfter is the after step of an A/AAAA record with its PTR record:
// it reads the reverse zone again, adds the PTR record when the name has
// none (one audit entry, like a record added by hand), and reports in a
// message when the PTR record exists already, points elsewhere, or fails.
// It never fails the address record, which is already applied.
func (s *Server) addPTRAfter(zoneName, name string, ptr ad.DNSRecord) func(context.Context, *reqCtx) error {
	return func(ctx context.Context, rc *reqCtx) error {
		revFQDN := name + "." + zoneName
		state, others := ptrAbsent, []string(nil)
		err := rc.withConn(ctx, func(conn *ad.Conn) error {
			rz, err := conn.DNSZoneByName(ctx, zoneName)
			if err != nil {
				return err
			}
			pol, err := conn.DNSPolicy(ctx)
			if err != nil {
				return err
			}
			apex, err := conn.DNSNodeByName(ctx, rz, "@")
			if err != nil {
				return err
			}
			node, err := conn.DNSNodeByName(ctx, rz, name)
			if err != nil {
				return err
			}
			revFQDN = node.FQDN(rz.Name)
			if state, others = ptrStateOf(node, ptr); state != ptrAbsent {
				return nil
			}
			op, err := ad.AddDNSRecord(rz, pol, apex, node, ptr)
			if err != nil {
				return err
			}
			detail := op.Preview().String() + "\n# PTR record of a new address record"
			if err := conn.Apply(ctx, op); err != nil {
				s.audit(ctx, rc, "dns.record_add", node.DN, detail+"\n# error: "+s.adErrorKey(err), resultOf(err))
				return err
			}
			s.audit(ctx, rc, "dns.record_add", node.DN, detail, store.ResultOK)
			return nil
		})
		switch {
		case err != nil:
			s.log.Warn("PTR record of a new address record failed", "ptr", revFQDN, "user", rc.sess.sam, "err", err)
			rc.sess.addFlash("error", rc.T("dns.ptr.failed", revFQDN, ptr.Data, s.errMessage(rc.T, err)))
		case state == ptrSame:
			rc.sess.addFlash("ok", rc.T("dns.ptr.exists", revFQDN, ptr.Data))
		case state == ptrOther:
			rc.sess.addFlash("error", rc.T("dns.ptr.other", revFQDN, strings.Join(others, ", ")))
		default:
			rc.sess.addFlash("ok", rc.T("dns.ptr.done", revFQDN, ptr.Data))
		}
		return nil
	}
}
