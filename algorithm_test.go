package dsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// makeSimpleDoc creates a simple XML element suitable for signing.
func makeSimpleDoc() *etree.Element {
	el := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}
	el.CreateAttr("ID", "_test-algo-roundtrip")
	return el
}

// randomECDSAP384TestKeyAndCert generates a P-384 ECDSA key + self-signed cert.
func randomECDSAP384TestKeyAndCert() (crypto.Signer, *x509.Certificate) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic(err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		panic(err)
	}
	return key, cert
}

// expiredTestKeyAndCert creates a key+cert whose validity window is entirely in the past.
func expiredTestKeyAndCert() (crypto.Signer, *x509.Certificate) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		panic(err)
	}
	return key, cert
}

// ---------------------------------------------------------------------------
// 1-9: Algorithm Round-Trip Tests (table-driven)
// ---------------------------------------------------------------------------

func TestAlgoRoundTrip(t *testing.T) {
	type keyGenFunc func() (crypto.Signer, *x509.Certificate)

	rsaGen := func() (crypto.Signer, *x509.Certificate) { return randomTestKeyAndCert() }
	ecP256Gen := func() (crypto.Signer, *x509.Certificate) { return randomECDSATestKeyAndCert() }
	ecP384Gen := func() (crypto.Signer, *x509.Certificate) { return randomECDSAP384TestKeyAndCert() }

	tests := []struct {
		name     string
		keyGen   keyGenFunc
		hash     crypto.Hash
		allowSHA1 bool
	}{
		{"RSA_SHA256", rsaGen, crypto.SHA256, false},
		{"RSA_SHA384", rsaGen, crypto.SHA384, false},
		{"RSA_SHA512", rsaGen, crypto.SHA512, false},
		{"RSA_SHA1", rsaGen, crypto.SHA1, true},
		{"ECDSA_P256_SHA256", ecP256Gen, crypto.SHA256, false},
		{"ECDSA_P256_SHA384", ecP256Gen, crypto.SHA384, false},
		{"ECDSA_P256_SHA512", ecP256Gen, crypto.SHA512, false},
		{"ECDSA_P384_SHA384", ecP384Gen, crypto.SHA384, false},
		{"ECDSA_P256_SHA1", ecP256Gen, crypto.SHA1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, cert := tt.keyGen()

			signer := &Signer{
				Key:   key,
				Certs: []*x509.Certificate{cert},
				Hash:  tt.hash,
			}

			doc := makeSimpleDoc()
			signed, err := signer.SignEnveloped(doc)
			require.NoError(t, err)
			require.NotNil(t, signed)

			verifier := &Verifier{
				TrustedCerts: []*x509.Certificate{cert},
				AllowSHA1:    tt.allowSHA1,
			}

			result, err := verifier.Verify(signed)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotNil(t, result.Element)
			require.Equal(t, cert, result.Certificate)
		})
	}
}

// Expose individual test names for `go test -run` convenience.
func TestAlgoRoundTrip_RSA_SHA256(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA256}
	signed, err := signer.SignEnveloped(makeSimpleDoc())
	require.NoError(t, err)
	result, err := (&Verifier{TrustedCerts: []*x509.Certificate{cert}}).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestAlgoRoundTrip_RSA_SHA384(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA384}
	signed, err := signer.SignEnveloped(makeSimpleDoc())
	require.NoError(t, err)
	result, err := (&Verifier{TrustedCerts: []*x509.Certificate{cert}}).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestAlgoRoundTrip_RSA_SHA512(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA512}
	signed, err := signer.SignEnveloped(makeSimpleDoc())
	require.NoError(t, err)
	result, err := (&Verifier{TrustedCerts: []*x509.Certificate{cert}}).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestAlgoRoundTrip_RSA_SHA1(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA1}
	signed, err := signer.SignEnveloped(makeSimpleDoc())
	require.NoError(t, err)
	result, err := (&Verifier{TrustedCerts: []*x509.Certificate{cert}, AllowSHA1: true}).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestAlgoRoundTrip_ECDSA_P256_SHA256(t *testing.T) {
	key, cert := randomECDSATestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA256}
	signed, err := signer.SignEnveloped(makeSimpleDoc())
	require.NoError(t, err)
	result, err := (&Verifier{TrustedCerts: []*x509.Certificate{cert}}).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestAlgoRoundTrip_ECDSA_P256_SHA384(t *testing.T) {
	key, cert := randomECDSATestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA384}
	signed, err := signer.SignEnveloped(makeSimpleDoc())
	require.NoError(t, err)
	result, err := (&Verifier{TrustedCerts: []*x509.Certificate{cert}}).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestAlgoRoundTrip_ECDSA_P256_SHA512(t *testing.T) {
	key, cert := randomECDSATestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA512}
	signed, err := signer.SignEnveloped(makeSimpleDoc())
	require.NoError(t, err)
	result, err := (&Verifier{TrustedCerts: []*x509.Certificate{cert}}).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestAlgoRoundTrip_ECDSA_P384_SHA384(t *testing.T) {
	key, cert := randomECDSAP384TestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA384}
	signed, err := signer.SignEnveloped(makeSimpleDoc())
	require.NoError(t, err)
	result, err := (&Verifier{TrustedCerts: []*x509.Certificate{cert}}).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestAlgoRoundTrip_ECDSA_P256_SHA1(t *testing.T) {
	key, cert := randomECDSATestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA1}
	signed, err := signer.SignEnveloped(makeSimpleDoc())
	require.NoError(t, err)
	result, err := (&Verifier{TrustedCerts: []*x509.Certificate{cert}, AllowSHA1: true}).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// 10-16: SignString / VerifyString Tests
// ---------------------------------------------------------------------------

func TestSignStringVerifyString_RSA(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA256}

	content := "hello world"
	sig, err := signer.SignString(content)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	verifiedCert, err := verifier.VerifyString(content, sig, RSASHA256SignatureMethod)
	require.NoError(t, err)
	require.Equal(t, cert, verifiedCert)
}

func TestSignStringVerifyString_ECDSA(t *testing.T) {
	key, cert := randomECDSATestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA256}

	content := "hello ecdsa world"
	sig, err := signer.SignString(content)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	verifiedCert, err := verifier.VerifyString(content, sig, ECDSASHA256SignatureMethod)
	require.NoError(t, err)
	require.Equal(t, cert, verifiedCert)
}

func TestSignStringVerifyString_WrongContent(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA256}

	sig, err := signer.SignString("correct content")
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.VerifyString("wrong content", sig, RSASHA256SignatureMethod)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrSignatureInvalid), "expected ErrSignatureInvalid, got: %v", err)
}

func TestSignStringVerifyString_WrongAlgorithm(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA256}

	content := "signed with RSA"
	sig, err := signer.SignString(content)
	require.NoError(t, err)

	// Verify with ECDSA algorithm URI — the RSA cert doesn't have an ECDSA key,
	// so no cert will match and it should fail.
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.VerifyString(content, sig, ECDSASHA256SignatureMethod)
	require.Error(t, err)
}

func TestSignStringVerifyString_EmptyTrustedCerts(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA256}

	sig, err := signer.SignString("data")
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{}}
	_, err = verifier.VerifyString("data", sig, RSASHA256SignatureMethod)
	require.Error(t, err)
}

func TestSignStringVerifyString_AllCertsExpired(t *testing.T) {
	key, cert := expiredTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA256}

	content := "expired cert test"
	sig, err := signer.SignString(content)
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.VerifyString(content, sig, ECDSASHA256SignatureMethod)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrSignatureInvalid), "expected ErrSignatureInvalid, got: %v", err)
}

func TestSignStringVerifyString_SHA1Blocked(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA1}

	sig, err := signer.SignString("sha1 test")
	require.NoError(t, err)

	// Default AllowSHA1=false
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.VerifyString("sha1 test", sig, RSASHA1SignatureMethod)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrAlgorithmNotAllowed), "expected ErrAlgorithmNotAllowed, got: %v", err)
}

// ---------------------------------------------------------------------------
// 17-23: ECDSA Encoding Edge Cases
// ---------------------------------------------------------------------------

func TestDecodeXMLDSigECDSA_WrongLength(t *testing.T) {
	// P-256 expects 64 bytes; supply 63.
	_, _, err := decodeXMLDSigECDSA(make([]byte, 63), elliptic.P256())
	require.Error(t, err)
	require.Contains(t, err.Error(), "wrong length")
}

func TestDecodeXMLDSigECDSA_ZeroLength(t *testing.T) {
	_, _, err := decodeXMLDSigECDSA([]byte{}, elliptic.P256())
	require.Error(t, err)
	require.Contains(t, err.Error(), "wrong length")
}

func TestDecodeXMLDSigECDSA_ValidP256(t *testing.T) {
	// Build a known 64-byte raw r||s for P-256.
	r := big.NewInt(0).SetBytes([]byte{0x01, 0x02, 0x03, 0x04})
	s := big.NewInt(0).SetBytes([]byte{0x05, 0x06, 0x07, 0x08})

	byteLen := 32 // P-256
	raw := make([]byte, 2*byteLen)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(raw[byteLen-len(rBytes):byteLen], rBytes)
	copy(raw[2*byteLen-len(sBytes):], sBytes)

	decodedR, decodedS, err := decodeXMLDSigECDSA(raw, elliptic.P256())
	require.NoError(t, err)
	require.Equal(t, r, decodedR)
	require.Equal(t, s, decodedS)
}

func TestDecodeXMLDSigECDSA_ValidP384(t *testing.T) {
	// Build a known 96-byte raw r||s for P-384.
	r := big.NewInt(0).SetBytes([]byte{0xAA, 0xBB, 0xCC})
	s := big.NewInt(0).SetBytes([]byte{0xDD, 0xEE, 0xFF})

	byteLen := 48 // P-384
	raw := make([]byte, 2*byteLen)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(raw[byteLen-len(rBytes):byteLen], rBytes)
	copy(raw[2*byteLen-len(sBytes):], sBytes)

	decodedR, decodedS, err := decodeXMLDSigECDSA(raw, elliptic.P384())
	require.NoError(t, err)
	require.Equal(t, r, decodedR)
	require.Equal(t, s, decodedS)
}

func TestConvertECDSAASN1ToRawRS_InvalidASN1(t *testing.T) {
	_, err := convertECDSAASN1ToRawRS([]byte{0xFF, 0xFE, 0xFD}, elliptic.P256())
	require.Error(t, err)
}

func TestConvertECDSAASN1ToRawRS_RoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a hash to sign
	hash := crypto.SHA256.New()
	hash.Write([]byte("round trip test"))
	digest := hash.Sum(nil)

	// Sign with standard library (produces ASN.1 DER)
	derSig, err := ecdsa.SignASN1(rand.Reader, key, digest)
	require.NoError(t, err)

	// Convert ASN.1 → raw r||s
	rawRS, err := convertECDSAASN1ToRawRS(derSig, elliptic.P256())
	require.NoError(t, err)
	require.Len(t, rawRS, 64) // 2 * 32 for P-256

	// Decode raw r||s
	decodedR, decodedS, err := decodeXMLDSigECDSA(rawRS, elliptic.P256())
	require.NoError(t, err)

	// Verify that the decoded r,s produce a valid ECDSA signature
	ok := ecdsa.Verify(&key.PublicKey, digest, decodedR, decodedS)
	require.True(t, ok, "decoded r,s should form a valid ECDSA signature")
}

func TestConvertECDSAASN1ToRawRS_TruncatedInput(t *testing.T) {
	// A too-short input that starts with valid-looking ASN.1 but is truncated
	_, err := convertECDSAASN1ToRawRS([]byte{0x30, 0x06, 0x02, 0x01}, elliptic.P256())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// 24: Canonicalizer Algorithm Round-Trips
// ---------------------------------------------------------------------------

func TestCanonicalizerRoundTrip(t *testing.T) {
	tests := []struct {
		name          string
		canonicalize  Canonicalizer
		shouldSucceed bool
	}{
		{
			"C14N10ExclusiveEmpty",
			MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
			true,
		},
		{
			"C14N11",
			MakeC14N11Canonicalizer(),
			true,
		},
		{
			"C14N10Rec",
			MakeC14N10RecCanonicalizer(),
			true,
		},
		{
			"C14N10ExclusiveWithComments",
			MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(""),
			true,
		},
		{
			"C14N11WithComments",
			MakeC14N11WithCommentsCanonicalizer(),
			true,
		},
		{
			"C14N10WithComments",
			MakeC14N10WithCommentsCanonicalizer(),
			true,
		},
		{
			// NullCanonicalizer has Algorithm() == "NULL" which is not a
			// valid c14n algorithm — verification will reject it.
			"NullCanonicalizer",
			MakeNullCanonicalizer(),
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, cert := randomTestKeyAndCert()

			signer := &Signer{
				Key:           key,
				Certs:         []*x509.Certificate{cert},
				Hash:          crypto.SHA256,
				Canonicalizer: tt.canonicalize,
			}

			// Use a plain element (no namespace prefix) to avoid
			// "undeclared namespace prefix" errors with exc-c14n.
			el := &etree.Element{Tag: "TestRoot"}
			el.CreateAttr("ID", "_c14n-test")
			signed, err := signer.SignEnveloped(el)
			require.NoError(t, err)

			verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
			result, err := verifier.Verify(signed)

			if tt.shouldSucceed {
				require.NoError(t, err, "canonicalizer %s should succeed", tt.name)
				require.NotNil(t, result)
			} else {
				// NullCanonicalizer produces "NULL" c14n Algorithm which is
				// rejected during verification as an invalid
				// CanonicalizationMethod — this is expected.
				require.Error(t, err, "canonicalizer %s should fail verification", tt.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 25: Ed25519 Rejected
// ---------------------------------------------------------------------------

func TestSigner_Ed25519Rejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_ = pub

	// We need a cert to pass to the signer; create a dummy one.
	// We can't create a real Ed25519 x509 cert easily with CreateCertificate
	// on older Go, but we only need the Signer to call validate().
	// Use any cert — the validation checks the key type, not the cert's key.
	_, dummyCert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   priv,
		Certs: []*x509.Certificate{dummyCert},
		Hash:  crypto.SHA256,
	}

	_, err = signer.SignEnveloped(makeSimpleDoc())
	require.Error(t, err)
	require.Contains(t, err.Error(), "Ed25519")
}

// ---------------------------------------------------------------------------
// 26: Custom Prefix
// ---------------------------------------------------------------------------

func TestSigner_CustomPrefix(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:    key,
		Certs:  []*x509.Certificate{cert},
		Hash:   crypto.SHA256,
		Prefix: "mysig",
	}

	doc := makeSimpleDoc()
	signed, err := signer.SignEnveloped(doc)
	require.NoError(t, err)

	// Serialize to string and verify the prefix is present
	xmlDoc := etree.NewDocument()
	xmlDoc.SetRoot(signed)
	xmlStr, err := xmlDoc.WriteToString()
	require.NoError(t, err)

	require.Contains(t, xmlStr, "mysig:Signature")
	require.Contains(t, xmlStr, "mysig:SignedInfo")
	require.Contains(t, xmlStr, "mysig:SignatureValue")
	require.Contains(t, xmlStr, "mysig:KeyInfo")

	// Also verify the signature is still valid
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	result, err := verifier.Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// 27: Multiple Certs in Chain
// ---------------------------------------------------------------------------

func TestSigner_MultipleCertsInChain(t *testing.T) {
	key, cert1 := randomTestKeyAndCert()
	_, cert2 := randomTestKeyAndCert() // second cert (different key, doesn't matter)

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert1, cert2},
		Hash:  crypto.SHA256,
	}

	doc := makeSimpleDoc()
	signed, err := signer.SignEnveloped(doc)
	require.NoError(t, err)

	// Find all X509Certificate elements in the signed output
	xmlDoc := etree.NewDocument()
	xmlDoc.SetRoot(signed)
	xmlStr, err := xmlDoc.WriteToString()
	require.NoError(t, err)

	// Count occurrences of X509Certificate tags
	count := strings.Count(xmlStr, "X509Certificate")
	// Each cert produces an opening and closing tag = 2 occurrences per cert
	require.Equal(t, 4, count, "expected 2 X509Certificate elements (4 tag occurrences), got %d", count)

	// Verify the signature using the signing cert
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert1}}
	result, err := verifier.Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}
