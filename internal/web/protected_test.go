package web

import (
	"testing"

	"github.com/openbasalt/samba-conductor-ad/sid"
)

// TestProtectedSet: the privileged groups are recognized by SID, including
// the key and replication groups and conductor's own role groups.
func TestProtectedSet(t *testing.T) {
	h := newHarness(t)
	rs := h.s.roleSIDs
	dom := sid.MustParse(testDomain)
	user, _ := dom.WithRID(1101)
	for _, rid := range []uint32{498, 512, 516, 518, 519, 520, 521, 526, 527} {
		g, _ := dom.WithRID(rid)
		if !rs.isProtectedGroup(g) {
			t.Errorf("RID %d not protected", rid)
		}
		if !rs.isProtectedMember(user, []sid.SID{g}) {
			t.Errorf("member of RID %d not protected", rid)
		}
	}
	for _, s := range []string{"S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551", "S-1-5-32-552",
		helpdeskSID, auditorSID} {
		g := sid.MustParse(s)
		if !rs.isProtectedGroup(g) || !rs.isProtectedMember(user, []sid.SID{g}) {
			t.Errorf("%s not protected", s)
		}
	}
	users, _ := dom.WithRID(513)
	if rs.isProtectedGroup(users) || rs.isProtectedMember(user, []sid.SID{users}) {
		t.Error("Domain Users is protected")
	}
	for v, want := range map[string]bool{"": false, "0": false, "1": true, " 1 ": true} {
		if adminCountSet(v) != want {
			t.Errorf("adminCount %q: %v", v, !want)
		}
	}
}
