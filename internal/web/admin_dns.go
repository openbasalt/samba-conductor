package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/samba-conductor/ad"
)

// DNS management: AD-integrated zones and records, read and written over
// LDAP with the signed-in user's own credentials (ad's DNS operations).
// The AD zones and the records AD manages are shown read-only; ad refuses
// to build operations on them in any case.

// recordID identifies one record value in forms (hash of its exact bytes).
func recordID(r ad.DNSRecord) string {
	h := sha256.Sum256(r.Raw())
	return hex.EncodeToString(h[:8])
}

// dnsRow is one record of the zone page.
type dnsRow struct {
	Name      string
	FQDN      string
	Record    ad.DNSRecord
	ID        string
	Protected bool
	First     bool // first record of its name (the name cell)
}

func (s *Server) zoneParam(ctx context.Context, rc *reqCtx, conn *ad.Conn) (ad.DNSZone, error) {
	name := rc.r.PathValue("zone")
	if _, err := ad.ValidZoneName(name); err != nil && !strings.HasPrefix(name, "_msdcs.") {
		return ad.DNSZone{}, errNotFoundPage
	}
	return conn.DNSZoneByName(ctx, name)
}

func zoneLink(z string) string { return "/admin/dns/zones/" + url.PathEscape(z) }

func (s *Server) handleDNSZones(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		zones, err := conn.DNSZones(ctx)
		if err != nil {
			return err
		}
		pol, err := conn.DNSPolicy(ctx)
		if err != nil {
			return err
		}
		type zoneView struct {
			Z    ad.DNSZone
			AD   bool
			Link string
		}
		var out []zoneView
		for _, z := range zones {
			out = append(out, zoneView{Z: z, AD: pol.ADZone(z.Name), Link: zoneLink(z.Name)})
		}
		rc.render(http.StatusOK, "dns_zones", map[string]any{"Zones": out, "DCs": pol.DCHosts})
		return nil
	})
}

func (s *Server) handleDNSZone(rc *reqCtx) {
	q := strings.TrimSpace(rc.r.URL.Query().Get("q"))
	page := rc.pageParam()
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		z, err := s.zoneParam(ctx, rc, conn)
		if err != nil {
			return err
		}
		pol, err := conn.DNSPolicy(ctx)
		if err != nil {
			return err
		}
		nodes, more, err := conn.DNSNodes(ctx, z, q, (page-1)*pageSize, pageSize)
		if err != nil {
			return err
		}
		var rows []dnsRow
		for _, n := range nodes {
			for i, r := range n.Records {
				rows = append(rows, dnsRow{Name: n.Name, FQDN: n.FQDN(z.Name), Record: r, ID: recordID(r),
					Protected: pol.ProtectedRecord(z.Name, n.Name, r.Type), First: i == 0})
			}
		}
		rc.render(http.StatusOK, "dns_zone", map[string]any{"Z": z, "AD": pol.ADZone(z.Name), "Rows": rows, "Q": q,
			"Page": page, "More": more, "Types": ad.WritableDNSTypes, "Link": zoneLink(z.Name), "F": map[string]string{"type": "A"}})
		return nil
	})
}

// zoneNameFromNetwork turns an IPv4 network (/8, /16, /24) or an IPv6
// network (multiple of /4) into its reverse zone name.
func zoneNameFromNetwork(cidr string) (string, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		return "", err
	}
	p = p.Masked()
	b := p.Addr().AsSlice()
	if p.Addr().Is4() {
		if p.Bits() == 0 || p.Bits()%8 != 0 {
			return "", fmt.Errorf("IPv4 reverse zones need a /8, /16 or /24 network")
		}
		var labels []string
		for i := p.Bits()/8 - 1; i >= 0; i-- {
			labels = append(labels, strconv.Itoa(int(b[i])))
		}
		return strings.Join(labels, ".") + ".in-addr.arpa", nil
	}
	if p.Bits() == 0 || p.Bits()%4 != 0 {
		return "", fmt.Errorf("IPv6 reverse zones need a prefix length that is a multiple of 4")
	}
	h := hex.EncodeToString(b)[:p.Bits()/4]
	var labels []string
	for i := len(h) - 1; i >= 0; i-- {
		labels = append(labels, string(h[i]))
	}
	return strings.Join(labels, ".") + ".ip6.arpa", nil
}

func (s *Server) handleDNSZoneNewPage(rc *reqCtx) {
	rc.render(http.StatusOK, "dns_zone_new", map[string]any{"F": map[string]string{"partition": ad.DNSPartitionDomain}})
}

func (s *Server) handleDNSZoneNew(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		f := map[string]string{"name": rc.form("name"), "network": rc.form("network"), "partition": rc.form("partition")}
		fail := func(key string) error {
			rc.render(http.StatusBadRequest, "dns_zone_new", map[string]any{"F": f, "Error": rc.T(key)})
			return nil
		}
		name := f["name"]
		if name == "" && f["network"] != "" {
			n, err := zoneNameFromNetwork(f["network"])
			if err != nil {
				return fail("dns.err.network")
			}
			name = n
		}
		if f["partition"] != ad.DNSPartitionDomain && f["partition"] != ad.DNSPartitionForest {
			return fail("form.invalid")
		}
		container, err := conn.DNSPartitionDN(f["partition"])
		if err != nil {
			return fail("form.invalid")
		}
		if _, err := conn.DNSZoneByName(ctx, name); err == nil {
			return fail("err.ad.exists")
		}
		pol, err := conn.DNSPolicy(ctx)
		if err != nil {
			return err
		}
		// The zone's SOA/NS name the DC this connection uses: discovered,
		// never a configured or hardcoded name.
		op, err := ad.CreateDNSZone(container, name, conn.DCHostName(), pol)
		if err != nil {
			return fail("dns.err.zone_name")
		}
		zn, _ := ad.ValidZoneName(name)
		rc.propose(&pendingOp{perm: PermDNSWrite, action: "dns.zone_create", target: op.Preview().Changes[0].DN, op: op,
			title: rc.T("dns.zone_new.title"), summary: rc.T("dns.summary.zone_create", zn, conn.DCHostName()),
			back: zoneLink(zn), done: rc.T("dns.zone_new.done")})
		return nil
	})
}

func (s *Server) handleDNSZoneDelete(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		z, err := s.zoneParam(ctx, rc, conn)
		if err != nil {
			return err
		}
		if !strings.EqualFold(rc.form("confirm"), z.Name) {
			rc.flashErr("dns.err.confirm_name")
			rc.redirect(zoneLink(z.Name))
			return nil
		}
		pol, err := conn.DNSPolicy(ctx)
		if err != nil {
			return err
		}
		n, err := conn.CountDNSNodes(ctx, z)
		if err != nil {
			return err
		}
		op, err := ad.DeleteDNSZone(z, pol, n)
		if err != nil {
			return err
		}
		rc.propose(&pendingOp{perm: PermDNSWrite, action: "dns.zone_delete", target: z.DN, op: op, reauth: true,
			title: rc.T("dns.zone_delete.title", z.Name), summary: rc.T("dns.summary.zone_delete", z.Name, n),
			warning: rc.T("confirm.warn.delete"), back: "/admin/dns", done: rc.T("op.deleted")})
		return nil
	})
}

// recordForm reads type, data and TTL of the record forms.
func recordForm(rc *reqCtx, t ad.DNSType) (ad.DNSRecord, error) {
	ttl := uint64(0)
	if v := rc.form("ttl"); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return ad.DNSRecord{}, ad.ErrInvalid
		}
		ttl = n
	}
	return ad.NewDNSRecord(t, rc.form("data"), uint32(ttl))
}

func (s *Server) handleDNSRecordNew(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		z, err := s.zoneParam(ctx, rc, conn)
		if err != nil {
			return err
		}
		back := zoneLink(z.Name)
		t, err := ad.ParseDNSType(rc.form("type"))
		if err != nil {
			rc.flashErr("dns.err.record")
			rc.redirect(back)
			return nil
		}
		rec, err := recordForm(rc, t)
		if err != nil {
			rc.flashErr("dns.err.record_data", t.String())
			rc.redirect(back)
			return nil
		}
		pol, err := conn.DNSPolicy(ctx)
		if err != nil {
			return err
		}
		apex, err := conn.DNSNodeByName(ctx, z, "@")
		if err != nil {
			return err
		}
		name := rc.form("name")
		if name == "" {
			name = "@"
		}
		node, err := conn.DNSNodeByName(ctx, z, name)
		if err != nil {
			rc.flashErr("dns.err.name")
			rc.redirect(back)
			return nil
		}
		op, err := ad.AddDNSRecord(z, pol, apex, node, rec)
		if err != nil {
			rc.flashErr(s.adErrorKey(err))
			rc.redirect(back)
			return nil
		}
		rc.propose(&pendingOp{perm: PermDNSWrite, action: "dns.record_add", target: node.DN, op: op,
			title: rc.T("dns.record_new.title", z.Name), summary: rc.T("dns.summary.record_add", rec.Type.String(), node.FQDN(z.Name), rec.Data),
			back: back + "?q=" + url.QueryEscape(strings.TrimPrefix(node.Name, "@")), done: rc.T("op.done")})
		return nil
	})
}

// findRecord loads the node and the record a form refers to.
func findRecord(ctx context.Context, conn *ad.Conn, z ad.DNSZone, name, id string) (ad.DNSNode, ad.DNSRecord, error) {
	node, err := conn.DNSNodeByName(ctx, z, name)
	if err != nil || !node.Exists {
		return node, ad.DNSRecord{}, errNotFoundPage
	}
	for _, r := range node.Records {
		if recordID(r) == id {
			return node, r, nil
		}
	}
	return node, ad.DNSRecord{}, fmt.Errorf("%w: record changed", ad.ErrConflict)
}

func (s *Server) handleDNSRecordEditPage(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		z, err := s.zoneParam(ctx, rc, conn)
		if err != nil {
			return err
		}
		q := rc.r.URL.Query()
		node, rec, err := findRecord(ctx, conn, z, q.Get("name"), q.Get("rid"))
		if err != nil {
			return err
		}
		pol, err := conn.DNSPolicy(ctx)
		if err != nil {
			return err
		}
		if pol.ProtectedRecord(z.Name, node.Name, rec.Type) {
			rc.errorPage(http.StatusForbidden, "dns.err.protected")
			return nil
		}
		rc.render(http.StatusOK, "dns_record", map[string]any{"Z": z, "Node": node, "R": rec, "ID": recordID(rec),
			"FQDN": node.FQDN(z.Name), "Link": zoneLink(z.Name)})
		return nil
	})
}

func (s *Server) handleDNSRecordEdit(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		z, err := s.zoneParam(ctx, rc, conn)
		if err != nil {
			return err
		}
		back := zoneLink(z.Name)
		node, old, err := findRecord(ctx, conn, z, rc.form("name"), rc.form("rid"))
		if err != nil {
			return err
		}
		rec, err := recordForm(rc, old.Type)
		if err != nil {
			rc.render(http.StatusBadRequest, "dns_record", map[string]any{"Z": z, "Node": node, "R": old, "ID": recordID(old),
				"FQDN": node.FQDN(z.Name), "Link": back, "Error": rc.T("dns.err.record_data", old.Type.String())})
			return nil
		}
		pol, err := conn.DNSPolicy(ctx)
		if err != nil {
			return err
		}
		apex, err := conn.DNSNodeByName(ctx, z, "@")
		if err != nil {
			return err
		}
		op, err := ad.UpdateDNSRecord(z, pol, apex, node, old, rec)
		if err != nil {
			rc.flashErr(s.adErrorKey(err))
			rc.redirect(back)
			return nil
		}
		rc.propose(&pendingOp{perm: PermDNSWrite, action: "dns.record_update", target: node.DN, op: op,
			title:   rc.T("dns.record_edit.title", node.FQDN(z.Name)),
			summary: rc.T("dns.summary.record_update", old.Type.String(), node.FQDN(z.Name), old.Data, rec.Data),
			back:    back + "?q=" + url.QueryEscape(strings.TrimPrefix(node.Name, "@")), done: rc.T("op.done")})
		return nil
	})
}

func (s *Server) handleDNSRecordDelete(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		z, err := s.zoneParam(ctx, rc, conn)
		if err != nil {
			return err
		}
		back := zoneLink(z.Name)
		node, rec, err := findRecord(ctx, conn, z, rc.form("name"), rc.form("rid"))
		if err != nil {
			return err
		}
		pol, err := conn.DNSPolicy(ctx)
		if err != nil {
			return err
		}
		apex, err := conn.DNSNodeByName(ctx, z, "@")
		if err != nil {
			return err
		}
		op, err := ad.DeleteDNSRecord(z, pol, apex, node, rec)
		if err != nil {
			rc.flashErr(s.adErrorKey(err))
			rc.redirect(back)
			return nil
		}
		rc.propose(&pendingOp{perm: PermDNSWrite, action: "dns.record_delete", target: node.DN, op: op,
			title:   rc.T("dns.record_delete.title", node.FQDN(z.Name)),
			summary: rc.T("dns.summary.record_delete", rec.Type.String(), node.FQDN(z.Name), rec.Data),
			warning: rc.T("confirm.warn.delete"), back: back, done: rc.T("op.deleted")})
		return nil
	})
}
