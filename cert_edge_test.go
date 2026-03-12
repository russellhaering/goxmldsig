package dsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Certificate Handling Edge Cases (Security TODO #7)
// ---------------------------------------------------------------------------

// genKeyCert creates an RSA 2048 key and self-signed cert with the given
// validity window.
func genKeyCert(t *testing.T, bits int, notBefore, notAfter time.Time) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)

	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}

// genECDSAKeyCert creates a P-256 ECDSA key and self-signed cert.
func genECDSAKeyCert(t *testing.T, notBefore, notAfter time.Time) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}

// signDocWithCerts signs a simple <Root ID=id><Data>hello</Data></Root>
// element, optionally embedding multiple certs in KeyInfo.
func signDocWithCerts(t *testing.T, key crypto.Signer, certs []*x509.Certificate, id string) *etree.Element {
	t.Helper()
	el := &etree.Element{Tag: "Root"}
	if id != "" {
		el.CreateAttr("ID", id)
	}
	el.CreateElement("Data").SetText("hello")
	signer := &Signer{Key: key, Certs: certs}
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	return reparse(t, signed)
}

// ---------------------------------------------------------------------------
// 1. NotBefore in future → ErrCertificateExpired
// ---------------------------------------------------------------------------
func TestCertEdge_NotBeforeInFuture(t *testing.T) {
	now := time.Now()
	// Cert valid from tomorrow to +2 days.
	notBefore := now.Add(24 * time.Hour)
	notAfter := now.Add(48 * time.Hour)
	key, cert := genKeyCert(t, 2048, notBefore, notAfter)

	// Sign within the cert's validity window so the signature is
	// cryptographically valid; the failure should come from time checking.
	signed := signDocWithCerts(t, key, []*x509.Certificate{cert}, "_future")

	v := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
		Clock:        func() time.Time { return now }, // now is before NotBefore
	}
	_, err := v.Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertificateExpired),
		"expected ErrCertificateExpired, got: %v", err)
}

// ---------------------------------------------------------------------------
// 2. NotAfter in past → ErrCertificateExpired
// ---------------------------------------------------------------------------
func TestCertEdge_NotAfterInPast(t *testing.T) {
	now := time.Now()
	// Cert was valid yesterday only.
	notBefore := now.Add(-48 * time.Hour)
	notAfter := now.Add(-24 * time.Hour)
	key, cert := genKeyCert(t, 2048, notBefore, notAfter)

	signed := signDocWithCerts(t, key, []*x509.Certificate{cert}, "_expired")

	v := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
		Clock:        func() time.Time { return now }, // now is after NotAfter
	}
	_, err := v.Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertificateExpired),
		"expected ErrCertificateExpired, got: %v", err)
}

// ---------------------------------------------------------------------------
// 3. Clock manipulation: custom clock inside validity window
// ---------------------------------------------------------------------------
func TestCertEdge_ClockManipulationAccepts(t *testing.T) {
	// Cert valid in a narrow window: 2030-Jun-01 to 2030-Jun-02.
	windowStart := time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
	windowEnd := time.Date(2030, 6, 2, 0, 0, 0, 0, time.UTC)
	key, cert := genKeyCert(t, 2048, windowStart, windowEnd)

	signed := signDocWithCerts(t, key, []*x509.Certificate{cert}, "_clock")

	// Real wall clock is outside the window. Custom Clock returns time inside.
	midWindow := windowStart.Add(12 * time.Hour)
	v := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
		Clock:        func() time.Time { return midWindow },
	}
	res, err := v.Verify(signed)
	require.NoError(t, err)
	assert.True(t, res.Certificate.Equal(cert))
}

// ---------------------------------------------------------------------------
// 4. Same public key, different cert (DER bytes differ)
// ---------------------------------------------------------------------------
func TestCertEdge_SameKeyDifferentCert(t *testing.T) {
	now := time.Now()
	notBefore := now.Add(-1 * time.Hour)
	notAfter := now.Add(1 * time.Hour)

	// Generate one RSA key.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create the "real" (trusted) cert.
	realTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	realDER, err := x509.CreateCertificate(rand.Reader, realTpl, realTpl, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)
	realCert, err := x509.ParseCertificate(realDER)
	require.NoError(t, err)

	// Create an "attacker" cert with the SAME public key but different serial.
	attackerTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(999),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	attackerDER, err := x509.CreateCertificate(rand.Reader, attackerTpl, attackerTpl, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)
	attackerCert, err := x509.ParseCertificate(attackerDER)
	require.NoError(t, err)

	// Certs share the key but are not equal (different DER).
	require.False(t, realCert.Equal(attackerCert), "certs must differ")

	// Sign with the attacker cert in KeyInfo.
	signed := signDocWithCerts(t, rsaKey, []*x509.Certificate{attackerCert}, "_samekey")

	// Trust only the real cert.
	v := &Verifier{TrustedCerts: []*x509.Certificate{realCert}}
	_, err = v.Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertificateNotTrusted),
		"expected ErrCertificateNotTrusted, got: %v", err)
}

// ---------------------------------------------------------------------------
// 5. Multiple KeyInfo certs — only the first is used
// ---------------------------------------------------------------------------
func TestCertEdge_MultipleKeyInfoCerts(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	_, extraCert := randomTestKeyAndCert()

	// Sign with both certs in KeyInfo. Signer embeds all certs in order.
	signed := signDocWithCerts(t, key, []*x509.Certificate{cert, extraCert}, "_multi")

	// Verify: the library picks the first cert. Trust the signing cert → success.
	v := newVerifier(cert)
	res, err := v.Verify(signed)
	require.NoError(t, err)
	assert.True(t, res.Certificate.Equal(cert))

	// If we trust only the second cert, it should fail because the code only
	// checks the first X509Certificate element.
	v2 := newVerifier(extraCert)
	_, err = v2.Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertificateNotTrusted),
		"second cert in KeyInfo should be ignored; got: %v", err)
}

// ---------------------------------------------------------------------------
// 6. KeyInfo cert omitted: single trusted → fallback; multiple → error
// ---------------------------------------------------------------------------
func TestCertEdge_NoKeyInfo_SingleTrustedFallback(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_noki")

	// Remove KeyInfo so the verifier must fall back.
	removeKeyInfoFromSig(signed)
	signed = reparse(t, signed)

	v := newVerifier(cert)
	res, err := v.Verify(signed)
	require.NoError(t, err)
	assert.True(t, res.Certificate.Equal(cert))
}

func TestCertEdge_NoKeyInfo_MultipleTrustedFails(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	_, cert2 := randomTestKeyAndCert()

	signed := signDoc(t, key, cert, "_noki2")
	removeKeyInfoFromSig(signed)
	signed = reparse(t, signed)

	v := newVerifier(cert, cert2)
	_, err := v.Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertificateNotTrusted),
		"expected ErrCertificateNotTrusted with multiple trusted certs and no KeyInfo, got: %v", err)
}

// ---------------------------------------------------------------------------
// 7. Small RSA key (1024 bits): library doesn't enforce minimum key sizes
// ---------------------------------------------------------------------------
func TestCertEdge_SmallRSAKey1024(t *testing.T) {
	now := time.Now()
	key, cert := genKeyCert(t, 1024, now.Add(-1*time.Hour), now.Add(1*time.Hour))

	signed := signDocWithCerts(t, key, []*x509.Certificate{cert}, "_rsa1024")

	// NOTE: The library does NOT enforce minimum key sizes. This documents
	// current behavior. A 1024-bit RSA key is considered insecure, but the
	// library accepts it.
	v := newVerifier(cert)
	res, err := v.Verify(signed)
	require.NoError(t, err, "library currently accepts RSA-1024; if this fails, minimum key size enforcement was added")
	assert.True(t, res.Certificate.Equal(cert))
	assert.Equal(t, 1024, res.Certificate.PublicKey.(*rsa.PublicKey).N.BitLen())
}

// ---------------------------------------------------------------------------
// 8. ECDSA P-256 cert: sign and verify round-trip
// ---------------------------------------------------------------------------
func TestCertEdge_ECDSAP256(t *testing.T) {
	now := time.Now()
	key, cert := genECDSAKeyCert(t, now.Add(-1*time.Hour), now.Add(1*time.Hour))

	signed := signDocWithCerts(t, key, []*x509.Certificate{cert}, "_ecdsa256")

	v := newVerifier(cert)
	res, err := v.Verify(signed)
	require.NoError(t, err)
	assert.True(t, res.Certificate.Equal(cert))

	// Confirm the key is ECDSA P-256.
	ecPub, ok := res.Certificate.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "expected ECDSA public key")
	assert.Equal(t, elliptic.P256(), ecPub.Curve)
}

// ---------------------------------------------------------------------------
// 9. Cert chain (leaf + intermediate): direct equality fails against root
// ---------------------------------------------------------------------------
func TestCertEdge_CertChainNotBuilt(t *testing.T) {
	now := time.Now()
	notBefore := now.Add(-1 * time.Hour)
	notAfter := now.Add(1 * time.Hour)

	// Create a "root" CA.
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	// Create a "leaf" cert signed by the root.
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	leafTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, rootTpl, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	// Sign using the leaf key, embed leaf cert (and root) in KeyInfo.
	// The library uses only the FIRST cert from KeyInfo.
	signed := signDocWithCerts(t, leafKey, []*x509.Certificate{leafCert, rootCert}, "_chain")

	// Trust only the root. The library does direct cert.Equal comparison,
	// NOT chain building, so leaf != root → must fail.
	v := newVerifier(rootCert)
	_, err = v.Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertificateNotTrusted),
		"library uses cert equality, not chain building; got: %v", err)

	// Trust the leaf directly → should succeed.
	v2 := newVerifier(leafCert)
	res, err := v2.Verify(signed)
	require.NoError(t, err)
	assert.True(t, res.Certificate.Equal(leafCert))
}

// ---------------------------------------------------------------------------
// 10. Empty TrustedCerts → proper error
// ---------------------------------------------------------------------------
func TestCertEdge_EmptyTrustedCerts(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_empty")

	// Nil TrustedCerts
	v := &Verifier{TrustedCerts: nil}
	_, err := v.Verify(signed)
	require.Error(t, err)
	// The code wraps ErrMissingSignature for empty TrustedCerts.
	assert.True(t, errors.Is(err, ErrMissingSignature),
		"expected error for empty TrustedCerts, got: %v", err)

	// Empty slice
	v2 := &Verifier{TrustedCerts: []*x509.Certificate{}}
	_, err = v2.Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingSignature),
		"expected error for empty TrustedCerts slice, got: %v", err)
}

// ---------------------------------------------------------------------------
// 11. KeyInfo cert matches trusted but both expired → ErrCertificateExpired
// ---------------------------------------------------------------------------
func TestCertEdge_MatchingButExpired(t *testing.T) {
	now := time.Now()
	// Cert expired 1 hour ago.
	notBefore := now.Add(-48 * time.Hour)
	notAfter := now.Add(-1 * time.Hour)
	key, cert := genKeyCert(t, 2048, notBefore, notAfter)

	signed := signDocWithCerts(t, key, []*x509.Certificate{cert}, "_matchexpired")

	// The cert in KeyInfo and the trusted cert are the same (Equal), but expired.
	v := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
		Clock:        func() time.Time { return now },
	}
	_, err := v.Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertificateExpired),
		"expected ErrCertificateExpired for matched-but-expired cert, got: %v", err)
}

// ---------------------------------------------------------------------------
// Additional edge case: KeyInfo contains garbage base64 cert data
// ---------------------------------------------------------------------------
func TestCertEdge_MalformedKeyInfoCert(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_malformed")

	// Replace the X509Certificate text with garbage.
	certEl := signed.FindElement("//" + X509CertificateTag)
	require.NotNil(t, certEl)
	certEl.SetText(base64.StdEncoding.EncodeToString([]byte("this-is-not-a-certificate")))

	v := newVerifier(cert)
	_, err := v.Verify(signed)
	require.Error(t, err)
	// Parsing garbage DER should yield a malformed signature error.
	assert.True(t, errors.Is(err, ErrMalformedSignature),
		"expected ErrMalformedSignature for garbage cert data, got: %v", err)
}

// ---------------------------------------------------------------------------
// Additional edge case: KeyInfo cert invalid base64
// ---------------------------------------------------------------------------
func TestCertEdge_InvalidBase64KeyInfoCert(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_badbase64")

	// Replace the X509Certificate text with invalid base64.
	certEl := signed.FindElement("//" + X509CertificateTag)
	require.NotNil(t, certEl)
	certEl.SetText("!!!not-base64!!!")

	v := newVerifier(cert)
	_, err := v.Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMalformedSignature),
		"expected ErrMalformedSignature for invalid base64 cert, got: %v", err)
}
