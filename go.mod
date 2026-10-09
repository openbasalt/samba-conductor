module github.com/openbasalt/samba-conductor

go 1.27.2

// Sibling modules of the Samba Conductor family are pinned by commit
// (pseudo-versions until they are tagged). A go.work in the family
// directory overrides the pins for local development (CONTRIBUTING.md).

require (
	filippo.io/age v1.3.2
	github.com/BurntSushi/toml v1.6.0
	github.com/fxamacker/cbor/v2 v2.9.4
	github.com/go-ldap/ldap/v3 v3.4.14
	github.com/go-webauthn/webauthn v0.18.2
	github.com/openbasalt/samba-conductor-ad v0.0.0-20261009012208-17469fcb3764
	github.com/openbasalt/samba-conductor-files v0.0.0-20261009012130-1ff33f4cb0c6
	github.com/openbasalt/samba-conductor-idp v0.0.0-20261009022042-5d3f9f8e1f25
	github.com/openbasalt/samba-conductor-sync v0.0.0-20261009022047-f5f8a11975ac
	golang.org/x/term v0.46.0
	modernc.org/sqlite v1.60.1
	rsc.io/qr v0.2.0
)

require (
	filippo.io/hpke v0.4.0 // indirect
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8 // indirect
	github.com/go-crypt/x v0.4.12 // indirect
	github.com/go-krb5/krb5 v0.1.0 // indirect
	github.com/go-krb5/x v0.4.1 // indirect
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
	golang.org/x/sys v0.48.0 // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
