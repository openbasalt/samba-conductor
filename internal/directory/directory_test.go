package directory

import "testing"

func TestNormalizeUsername(t *testing.T) {
	cases := map[string]string{
		"User0001":                     "user0001",
		"LAB\\Lab.Admin":               "lab.admin",
		"lab.admin@lab.conductor.test": "lab.admin",
		"  normal.user ":               "normal.user",
		"x@other.example":              "",
		"a,b":                          "",
		"(objectClass=*)":              "",
		"user\x00":                     "",
		"":                             "",
		"verylongname-verylongname-verylongname-verylongname-verylongname-x": "",
	}
	for in, want := range cases {
		got, ok := NormalizeUsername(in, "LAB.CONDUCTOR.TEST")
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %v, want %q", in, got, ok, want)
		}
	}
}
