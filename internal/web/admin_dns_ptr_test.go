package web

import (
	"net/netip"
	"slices"
	"testing"

	ad "github.com/openbasalt/samba-conductor-ad"
)

func TestReverseName(t *testing.T) {
	cases := []struct {
		t    ad.DNSType
		addr string
		want string
	}{
		{ad.DNSTypeA, "10.93.0.60", "60.0.93.10.in-addr.arpa"},
		{ad.DNSTypeA, "192.0.2.1", "1.2.0.192.in-addr.arpa"},
		{ad.DNSTypeAAAA, "2001:db8::50", "0.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"},
		{ad.DNSTypeAAAA, "::ffff:192.0.2.1", "1.0.2.0.0.0.0.c.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"},
	}
	for _, c := range cases {
		if got := reverseName(c.t, netip.MustParseAddr(c.addr)); got != c.want {
			t.Errorf("%s %s: %q, want %q", c.t, c.addr, got, c.want)
		}
	}
}

func TestCoveringReverseZone(t *testing.T) {
	zones := []ad.DNSZone{
		{Name: "lab.example"},
		{Name: "_msdcs.lab.example"},
		{Name: "10.in-addr.arpa"},
		{Name: "0.93.10.in-addr.arpa"},
		{Name: "93.10.in-addr.arpa"},
		{Name: "100.51.198.in-addr.arpa."},
		{Name: "1.198.in-addr.arpa"},
		{Name: "8.b.d.0.1.0.0.2.ip6.arpa"},
		{Name: "0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"},
		{Name: "in-addr.arpa.lab.example"},
	}
	cases := []struct {
		t        ad.DNSType
		addr     string
		zone     string
		name     string
		covering bool
	}{
		// The most specific zone wins, whatever the listing order.
		{ad.DNSTypeA, "10.93.0.60", "0.93.10.in-addr.arpa", "60", true},
		{ad.DNSTypeA, "10.93.7.1", "93.10.in-addr.arpa", "1.7", true},
		{ad.DNSTypeA, "10.1.2.3", "10.in-addr.arpa", "3.2.1", true},
		// A trailing dot on the zone name does not matter.
		{ad.DNSTypeA, "198.51.100.5", "100.51.198.in-addr.arpa.", "5", true},
		// Label boundaries: 11.198.x is not in 1.198.in-addr.arpa.
		{ad.DNSTypeA, "198.11.0.1", "", "", false},
		{ad.DNSTypeA, "192.0.2.1", "", "", false},
		{ad.DNSTypeAAAA, "2001:db8::50", "0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", "0.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0", true},
		{ad.DNSTypeAAAA, "2001:db8:1::1", "8.b.d.0.1.0.0.2.ip6.arpa", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0", true},
		{ad.DNSTypeAAAA, "2001:db9::1", "", "", false},
		// The family follows the record type: an IPv4-mapped AAAA address
		// is not looked up under in-addr.arpa.
		{ad.DNSTypeAAAA, "::ffff:10.93.0.60", "", "", false},
		{ad.DNSTypeA, "2001:db8::50", "", "", false},
		{ad.DNSTypeCNAME, "10.93.0.60", "", "", false},
	}
	for _, c := range cases {
		z, name, ok := coveringReverseZone(zones, c.t, netip.MustParseAddr(c.addr))
		if ok != c.covering || z.Name != c.zone || name != c.name {
			t.Errorf("%s %s: (%q, %q, %v), want (%q, %q, %v)", c.t, c.addr, z.Name, name, ok, c.zone, c.name, c.covering)
		}
	}
	if _, _, ok := coveringReverseZone(nil, ad.DNSTypeA, netip.MustParseAddr("10.93.0.60")); ok {
		t.Error("no zones: covered")
	}
}

func TestPTRStateOf(t *testing.T) {
	ptr, err := ad.NewDNSRecord(ad.DNSTypePTR, "www.lab.example.", 0)
	if err != nil {
		t.Fatal(err)
	}
	rec := func(typ ad.DNSType, data string) ad.DNSRecord {
		r, err := ad.NewDNSRecord(typ, data, 0)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	cases := []struct {
		desc   string
		node   ad.DNSNode
		want   ptrState
		others []string
	}{
		{"no name yet", ad.DNSNode{Name: "60"}, ptrAbsent, nil},
		{"other types only", ad.DNSNode{Name: "60", Exists: true, Records: []ad.DNSRecord{rec(ad.DNSTypeTXT, "note")}}, ptrAbsent, nil},
		{"same target, other case", ad.DNSNode{Name: "60", Exists: true, Records: []ad.DNSRecord{rec(ad.DNSTypePTR, "WWW.lab.example")}}, ptrSame, nil},
		{"same among others", ad.DNSNode{Name: "60", Exists: true, Records: []ad.DNSRecord{rec(ad.DNSTypePTR, "old.lab.example"), rec(ad.DNSTypePTR, "www.lab.example")}}, ptrSame, nil},
		{"other target", ad.DNSNode{Name: "60", Exists: true, Records: []ad.DNSRecord{rec(ad.DNSTypePTR, "old.lab.example")}}, ptrOther, []string{"old.lab.example"}},
		{"tombstoned name", ad.DNSNode{Name: "60", Exists: true, Tombstoned: true, Records: []ad.DNSRecord{rec(ad.DNSTypePTR, "old.lab.example")}}, ptrAbsent, nil},
	}
	for _, c := range cases {
		got, others := ptrStateOf(c.node, ptr)
		if got != c.want || !slices.Equal(others, c.others) {
			t.Errorf("%s: (%v, %v), want (%v, %v)", c.desc, got, others, c.want, c.others)
		}
	}
}

func TestReverseZoneNames(t *testing.T) {
	got := reverseZoneNames([]ad.DNSZone{{Name: "lab.example"}, {Name: "0.93.10.in-addr.arpa"}, {Name: "8.b.d.0.1.0.0.2.ip6.arpa"}})
	if !slices.Equal(got, []string{"0.93.10.in-addr.arpa", "8.b.d.0.1.0.0.2.ip6.arpa"}) {
		t.Errorf("reverse zones: %v", got)
	}
	if reverseZoneNames([]ad.DNSZone{{Name: "lab.example"}}) != nil {
		t.Error("forward zones listed")
	}
}
