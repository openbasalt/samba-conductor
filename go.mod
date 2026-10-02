module github.com/samba-conductor/conductor

go 1.27.0

// The ad library is local only until the family's GitHub home is decided
// (planning/docs/decisions.md); the family go.work resolves it too.
replace github.com/samba-conductor/ad => ../ad

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/fxamacker/cbor/v2 v2.9.4
	github.com/go-ldap/ldap/v3 v3.4.14
	github.com/go-webauthn/webauthn v0.18.2
	github.com/samba-conductor/ad v0.0.0
	golang.org/x/term v0.46.0
	modernc.org/sqlite v1.60.1
	rsc.io/qr v0.2.0
)

require (
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8 // indirect
	github.com/go-crypt/x v0.4.12 // indirect
	github.com/go-krb5/krb5 v0.1.0 // indirect
	github.com/go-krb5/x v0.3.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
