package web

import (
	"html"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	ad "github.com/openbasalt/samba-conductor-ad"
)

// formRC is a request context carrying a posted form.
func formRC(v url.Values) *reqCtx {
	r := httptest.NewRequest("POST", "/admin/dns/zones/x/records/new", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return &reqCtx{r: r}
}

func TestRecordFormTXTLines(t *testing.T) {
	dkim := "v=DKIM1; h=sha256; k=rsa;\r\np=abcdef\r\nghijklmnop\r\n\r\n"
	want := `"v=DKIM1; h=sha256; k=rsa;" "p=abcdef" "ghijklmnop"`
	cases := []struct {
		name string
		form url.Values
		t    ad.DNSType
		want string
	}{
		{"add form, multi-line field", url.Values{"data": {""}, "txt": {dkim}}, ad.DNSTypeTXT, want},
		{"multi-line field wins over a stale one-line value", url.Values{"data": {"old"}, "txt": {dkim}}, ad.DNSTypeTXT, want},
		{"add form, one-line field (no :has() support)", url.Values{"data": {`"a b" "c"`}, "txt": {""}}, ad.DNSTypeTXT, `"a b" "c"`},
		{"edit form, textarea named data", url.Values{"data": {dkim}}, ad.DNSTypeTXT, want},
		{"other types ignore the TXT field", url.Values{"data": {"192.0.2.7"}, "txt": {"x"}}, ad.DNSTypeA, "192.0.2.7"},
	}
	for _, c := range cases {
		rec, err := recordForm(formRC(c.form), c.t)
		if err != nil || rec.Data != c.want {
			t.Errorf("%s: %q %v, want %q", c.name, rec.Data, err, c.want)
		}
	}
	if _, err := recordForm(formRC(url.Values{"txt": {"\r\n\r\n"}}), ad.DNSTypeTXT); err == nil {
		t.Error("blank TXT accepted")
	}
}

func TestDNSRecordEditTXTTextarea(t *testing.T) {
	h := newHarness(t)
	rec, err := ad.NewDNSRecord(ad.DNSTypeTXT, "v=DKIM1; k=rsa;\np="+strings.Repeat("A", 300)+"\n\"quoted \\\" line\"", 0)
	if err != nil {
		t.Fatal(err)
	}
	d := map[string]any{"Z": ad.DNSZone{Name: "lab.test"}, "Node": ad.DNSNode{Name: "s1._domainkey"}, "R": rec, "ID": "abc",
		"FQDN": "s1._domainkey.lab.test", "Link": "/admin/dns/zones/lab.test", "Value": recordFieldValue(rec), "TTL": rec.TTL}
	body := renderAs(t, h, Roles{Admin: true}, "dns_record", d)
	start := strings.Index(body, `data-e2e="dnsrec-input-data">`)
	if !strings.Contains(body, `<textarea id="r-data" name="data"`) || start < 0 {
		t.Fatalf("TXT edit form has no textarea:\n%s", body)
	}
	text := body[start+len(`data-e2e="dnsrec-input-data">`):]
	text = html.UnescapeString(text[:strings.Index(text, "</textarea>")])
	wantLines := "v=DKIM1; k=rsa;\np=" + strings.Repeat("A", 253) + "\n" + strings.Repeat("A", 47) + "\nquoted \" line"
	if text != wantLines {
		t.Errorf("textarea %q, want %q", text, wantLines)
	}
	// What the browser sends back (CRLF) is the same record: a no-op.
	back, err := recordForm(formRC(url.Values{"data": {strings.ReplaceAll(text, "\n", "\r\n")}, "ttl": {"3600"}}), ad.DNSTypeTXT)
	if err != nil || back.Data != rec.Data || back.TTL != rec.TTL {
		t.Errorf("round trip %q %v, want %q", back.Data, err, rec.Data)
	}
	// Other types keep the one-line field.
	a, _ := ad.NewDNSRecord(ad.DNSTypeA, "192.0.2.7", 0)
	d["R"], d["Value"] = a, recordFieldValue(a)
	body = renderAs(t, h, Roles{Admin: true}, "dns_record", d)
	if strings.Contains(body, "<textarea") || !strings.Contains(body, `value="192.0.2.7" required data-e2e="dnsrec-input-data"`) {
		t.Error("A record edit form is not a one-line field")
	}
}

func TestDNSZoneAddFormTXTField(t *testing.T) {
	h := newHarness(t)
	d := map[string]any{"Z": ad.DNSZone{Name: "lab.test"}, "Link": "/admin/dns/zones/lab.test", "Types": ad.WritableDNSTypes,
		"F": map[string]string{"type": "A"}, "Page": 1}
	body := renderAs(t, h, Roles{Admin: true}, "dns_zone", d)
	for _, want := range []string{`class="field dns-data-line"`, `data-e2e="dns-input-data"`, `class="field dns-data-txt"`,
		`<textarea id="r-txt" name="txt"`, `data-e2e="dns-input-txt"`} {
		if !strings.Contains(body, want) {
			t.Errorf("add form lacks %s", want)
		}
	}
	// A hidden required field would block the submit: neither is required.
	if strings.Contains(body, `data-e2e="dns-input-data" required`) || strings.Contains(body, `required data-e2e="dns-input-data"`) {
		t.Error("the one-line data field is required")
	}
}
