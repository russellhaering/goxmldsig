package dsig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// reparse serializes el to XML and re-parses it so all etree parent pointers
// are correct. SignEnveloped appends via the Child slice directly, so a
// serialize→parse round-trip is required before calling Verify.
func reparse(t *testing.T, el *etree.Element) *etree.Element {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el)
	s, err := doc.WriteToString()
	require.NoError(t, err)
	doc2 := etree.NewDocument()
	require.NoError(t, doc2.ReadFromString(s))
	return doc2.Root()
}

// signAndReparse signs el enveloped, then round-trips through XML text.
func signAndReparse(t *testing.T, key crypto.Signer, cert *x509.Certificate, el *etree.Element) *etree.Element {
	t.Helper()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	return reparse(t, signed)
}

// signDoc builds <Response ID=id><Data>good</Data></Response>, signs, reparses.
func signDoc(t *testing.T, key crypto.Signer, cert *x509.Certificate, id string) *etree.Element {
	t.Helper()
	el := &etree.Element{Tag: "Response"}
	if id != "" {
		el.CreateAttr("ID", id)
	}
	el.CreateElement("Data").SetText("good")
	return signAndReparse(t, key, cert, el)
}

func newVerifier(certs ...*x509.Certificate) *Verifier {
	return &Verifier{TrustedCerts: certs}
}

func findSig(el *etree.Element) *etree.Element {
	for _, c := range el.ChildElements() {
		if c.Tag == SignatureTag {
			return c
		}
	}
	return nil
}

func removeKeyInfoFromSig(el *etree.Element) {
	sig := findSig(el)
	if sig == nil {
		return
	}
	for _, c := range sig.ChildElements() {
		if c.Tag == KeyInfoTag {
			sig.RemoveChild(c)
			return
		}
	}
}

func customCert(key crypto.Signer, notBefore, notAfter time.Time) *x509.Certificate {
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return c
}

// ============================================================================
// XSW / Signature Wrapping Tests
// ============================================================================

func TestXSW_SignatureMovedToGrandchild(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	sig := findSig(signed)
	require.NotNil(t, sig)
	wrapper := signed.CreateElement("Wrapper")
	signed.RemoveChild(sig)
	wrapper.AddChild(sig)

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrMissingSignature), "got: %v", err)
}

func TestXSW_EvilSiblingElement(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	evil := etree.NewElement("Evil")
	evil.SetText("bad")
	signed.InsertChildAt(0, evil)

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestXSW_WrappedSignature(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	sig := findSig(signed)
	require.NotNil(t, sig)
	container := etree.NewElement("SigContainer")
	signed.RemoveChild(sig)
	container.AddChild(sig)
	signed.AddChild(container)

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrMissingSignature), "got: %v", err)
}

func TestXSW_DuplicateIDDifferentContent(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	// Put the signed element inside an outer Envelope alongside an evil clone.
	envelope := etree.NewElement("Envelope")
	evil := etree.NewElement("Response")
	evil.CreateAttr("ID", "_r1")
	evil.CreateElement("Data").SetText("evil")
	envelope.AddChild(evil)
	envelope.AddChild(signed)

	// Verify the actual signed element; result must contain "good".
	result, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)
	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	require.Equal(t, "good", d.Text())
}

func TestXSW_EmptyURIWithInjectedContent(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	// No ID → empty URI reference.
	signed := signDoc(t, key, cert, "")

	// Verify clean round-trip works.
	res, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, res)

	// Inject evil content.
	signed.CreateElement("Evil").SetText("bad")
	_, err = newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestXSW_ModifiedContentAfterSignature(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	signed.FindElement("//Data").SetText("tampered")

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestXSW_AddedAttributeAfterSigning(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	signed.CreateAttr("evil", "true")

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestXSW_RemovedChildAfterSigning(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	d := signed.FindElement("//Data")
	require.NotNil(t, d)
	signed.RemoveChild(d)

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestXSW_ReorderedChildrenAfterSigning(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_reorder")
	el.CreateElement("First").SetText("1")
	el.CreateElement("Second").SetText("2")
	signed := signAndReparse(t, key, cert, el)

	first := signed.FindElement("//First")
	second := signed.FindElement("//Second")
	sig := findSig(signed)
	require.NotNil(t, first)
	require.NotNil(t, second)
	require.NotNil(t, sig)

	signed.Child = nil
	signed.AddChild(second)
	signed.AddChild(first)
	signed.AddChild(sig)

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestXSW_ModifiedNamespaceAfterSigning(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response", Space: "samlp"}
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	el.CreateAttr("ID", "_ns")
	el.CreateElement("Data").SetText("good")
	signed := signAndReparse(t, key, cert, el)

	// Verify clean first.
	_, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)

	// Tamper with the namespace URI.
	for i, a := range signed.Attr {
		if a.Key == "samlp" && a.Space == "xmlns" {
			signed.Attr[i].Value = "urn:evil:ns"
			break
		}
	}

	_, err = newVerifier(cert).Verify(signed)
	require.Error(t, err)
	// May break at signature or digest level depending on c14n scope.
	require.True(t,
		errors.Is(err, ErrDigestMismatch) || errors.Is(err, ErrSignatureInvalid),
		"got: %v", err)
}

// ============================================================================
// Certificate Trust Tests
// ============================================================================

func TestCert_UntrustedCertInKeyInfo(t *testing.T) {
	keyA, certA := randomTestKeyAndCert()
	_, certB := randomTestKeyAndCert()

	signed := signDoc(t, keyA, certA, "_r1")

	_, err := newVerifier(certB).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrCertificateNotTrusted), "got: %v", err)
}

func TestCert_SelfSignedAttackerCert(t *testing.T) {
	_, trustedCert := randomTestKeyAndCert()
	attackerKey, attackerCert := randomTestKeyAndCert()

	signed := signDoc(t, attackerKey, attackerCert, "_r1")

	_, err := newVerifier(trustedCert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrCertificateNotTrusted), "got: %v", err)
}

func TestCert_ExpiredCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := customCert(key,
		time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC))

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_exp")
	el.CreateElement("Data").SetText("good")
	signed := signAndReparse(t, key, cert, el)

	v := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
		Clock:        func() time.Time { return time.Date(2022, 6, 1, 0, 0, 0, 0, time.UTC) },
	}
	_, verr := v.Verify(signed)
	require.Error(t, verr)
	require.True(t, errors.Is(verr, ErrCertificateExpired), "got: %v", verr)
}

func TestCert_NotYetValidCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := customCert(key,
		time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC))

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_nyv")
	el.CreateElement("Data").SetText("good")
	signed := signAndReparse(t, key, cert, el)

	v := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
		Clock:        func() time.Time { return time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC) },
	}
	_, verr := v.Verify(signed)
	require.Error(t, verr)
	require.True(t, errors.Is(verr, ErrCertificateExpired), "got: %v", verr)
}

func TestCert_NoKeyInfoMultipleTrustedCerts(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	_, cert2 := randomTestKeyAndCert()

	signed := signDoc(t, key, cert, "_r1")
	removeKeyInfoFromSig(signed)

	_, err := newVerifier(cert, cert2).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrCertificateNotTrusted), "got: %v", err)
}

func TestCert_NoKeyInfoSingleTrustedCert(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")
	removeKeyInfoFromSig(signed)

	res, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.True(t, res.Certificate.Equal(cert))
}

func TestCert_ClockInjection(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	var called int64
	v := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
		Clock: func() time.Time {
			atomic.AddInt64(&called, 1)
			return time.Now()
		},
	}
	res, err := v.Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Greater(t, atomic.LoadInt64(&called), int64(0), "Clock was never called")
}

// ============================================================================
// Digest Tampering Tests
// ============================================================================

func TestTamper_ModifiedTextContent(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	signed.FindElement("//Data").SetText("tampered")

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestTamper_ModifiedAttributeValue(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_attr")
	el.CreateAttr("Flavor", "vanilla")
	el.CreateElement("Data").SetText("good")
	signed := signAndReparse(t, key, cert, el)

	for i, a := range signed.Attr {
		if a.Key == "Flavor" {
			signed.Attr[i].Value = "chocolate"
			break
		}
	}

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestTamper_AddedChildElement(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	signed.CreateElement("Injected").SetText("evil")

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestTamper_RemovedChildElement(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	d := signed.FindElement("//Data")
	require.NotNil(t, d)
	signed.RemoveChild(d)

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestTamper_AddedComment(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	// --- default C14N 1.1 (strips comments) ---
	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_cmt1")
	el.CreateElement("Data").SetText("good")
	signed := signAndReparse(t, key, cert, el)

	signed.InsertChildAt(0, etree.NewComment("injected"))

	res, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err, "comment should be ignored by non-comment c14n")
	require.NotNil(t, res)

	// --- WithComments canonicalizer ---
	signer2 := &Signer{
		Key: key, Certs: []*x509.Certificate{cert},
		Canonicalizer: MakeC14N11WithCommentsCanonicalizer(),
	}
	el2 := &etree.Element{Tag: "Response"}
	el2.CreateAttr("ID", "_cmt2")
	el2.CreateElement("Data").SetText("good")
	raw2, err := signer2.SignEnveloped(el2)
	require.NoError(t, err)
	signed2 := reparse(t, raw2)

	signed2.InsertChildAt(0, etree.NewComment("injected"))

	_, err = newVerifier(cert).Verify(signed2)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

// ============================================================================
// Algorithm Tests
// ============================================================================

func TestAlgo_SHA1BlockedByDefault(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA1}
	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_sha1")
	el.CreateElement("Data").SetText("good")
	raw, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed := reparse(t, raw)

	// Default: AllowSHA1 = false.
	v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = v.Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrAlgorithmNotAllowed), "got: %v", err)

	// Allow SHA-1.
	v.AllowSHA1 = true
	res, err := v.Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, res)
}

func TestAlgo_UnknownSignatureAlgorithm(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	sm := signed.FindElement("//" + SignatureMethodTag)
	require.NotNil(t, sm)
	for i, a := range sm.Attr {
		if a.Key == AlgorithmAttr {
			sm.Attr[i].Value = "http://example.com/bogus-sig"
			break
		}
	}

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrAlgorithmNotAllowed), "got: %v", err)
}

func TestAlgo_UnknownDigestAlgorithm(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	dm := signed.FindElement("//" + DigestMethodTag)
	require.NotNil(t, dm)
	for i, a := range dm.Attr {
		if a.Key == AlgorithmAttr {
			dm.Attr[i].Value = "http://example.com/bogus-digest"
			break
		}
	}

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrAlgorithmNotAllowed), "got: %v", err)
}

// ============================================================================
// Bonus security edge-cases
// ============================================================================

func TestCert_SwappedKeyInfoCert(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	_, attackerCert := randomTestKeyAndCert()

	signed := signDoc(t, key, cert, "_r1")

	certEl := signed.FindElement("//" + X509CertificateTag)
	require.NotNil(t, certEl)
	certEl.SetText(base64.StdEncoding.EncodeToString(attackerCert.Raw))

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrCertificateNotTrusted), "got: %v", err)
}

func TestRoundTrip_ECDSAVerifiesClean(t *testing.T) {
	key, cert := randomECDSATestKeyAndCert()
	signed := signDoc(t, key, cert, "_ecdsa")

	res, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)
	require.True(t, res.Certificate.Equal(cert))
	d := res.Element.FindElement("//Data")
	require.NotNil(t, d)
	require.Equal(t, "good", d.Text())
}

func TestTamper_ModifiedSignatureValue(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	sv := signed.FindElement("//" + SignatureValueTag)
	require.NotNil(t, sv)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sv.Text()))
	require.NoError(t, err)
	raw[0] ^= 0xff
	sv.SetText(base64.StdEncoding.EncodeToString(raw))

	_, err = newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrSignatureInvalid), "got: %v", err)
}

func TestTamper_ModifiedDigestValue(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	dv := signed.FindElement("//" + DigestValueTag)
	require.NotNil(t, dv)
	dv.SetText(base64.StdEncoding.EncodeToString([]byte("fakefakefakefakefakefakefakefake")))

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	// Changing DigestValue changes SignedInfo → signature check fails first.
	require.True(t, errors.Is(err, ErrSignatureInvalid), "got: %v", err)
}
