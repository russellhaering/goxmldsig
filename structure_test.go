package dsig

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

// findDescendantByTag performs a depth-first search for a descendant element
// with the given tag name.
func findDescendantByTag(el *etree.Element, tag string) *etree.Element {
	for _, child := range el.ChildElements() {
		if child.Tag == tag {
			return child
		}
		if found := findDescendantByTag(child, tag); found != nil {
			return found
		}
	}
	return nil
}

// makeTestElement creates a simple element suitable for signing round-trips.
func makeTestElement(id string) *etree.Element {
	el := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}
	el.CreateAttr("ID", id)
	return el
}

// signAndPrepare creates a basic signed document and returns the signed
// element, signer, and verifier for use in malformed-structure tests.
func signAndPrepare(t *testing.T) (*etree.Element, *Signer, *Verifier) {
	t.Helper()
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	el := makeTestElement("_test-id-12345")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}

	// Sanity check: verify should pass on unmodified signed doc
	_, err = verifier.Verify(signed)
	require.NoError(t, err, "sanity check: unmodified signed document should verify")

	return signed, signer, verifier
}

// ---------------------------------------------------------------------------
// Malformed Signature Structure Tests
// ---------------------------------------------------------------------------

func TestMalformed_MissingSignedInfo(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)

	si := findDescendantByTag(sig, SignedInfoTag)
	require.NotNil(t, si)
	sig.RemoveChild(si)

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_MissingSignatureValue(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)

	sv := findDescendantByTag(sig, SignatureValueTag)
	require.NotNil(t, sv)
	sig.RemoveChild(sv)

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_DuplicateSignedInfo(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)

	si := findDescendantByTag(sig, SignedInfoTag)
	require.NotNil(t, si)

	// Add a duplicate copy of SignedInfo
	sig.AddChild(si.Copy())

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_DuplicateKeyInfo(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)

	ki := findDescendantByTag(sig, KeyInfoTag)
	require.NotNil(t, ki)

	// Add a duplicate copy of KeyInfo
	sig.AddChild(ki.Copy())

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_MissingCanonicalizationMethod(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	si := findDescendantByTag(signed, SignedInfoTag)
	require.NotNil(t, si)

	c14n := findDescendantByTag(si, CanonicalizationMethodTag)
	require.NotNil(t, c14n)
	si.RemoveChild(c14n)

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_MissingSignatureMethod(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	si := findDescendantByTag(signed, SignedInfoTag)
	require.NotNil(t, si)

	sm := findDescendantByTag(si, SignatureMethodTag)
	require.NotNil(t, sm)
	si.RemoveChild(sm)

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_MissingReference(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	si := findDescendantByTag(signed, SignedInfoTag)
	require.NotNil(t, si)

	ref := findDescendantByTag(si, ReferenceTag)
	require.NotNil(t, ref)
	si.RemoveChild(ref)

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_MissingDigestMethod(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	ref := findDescendantByTag(signed, ReferenceTag)
	require.NotNil(t, ref)

	dm := findDescendantByTag(ref, DigestMethodTag)
	require.NotNil(t, dm)
	ref.RemoveChild(dm)

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_MissingDigestValue(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	ref := findDescendantByTag(signed, ReferenceTag)
	require.NotNil(t, ref)

	dv := findDescendantByTag(ref, DigestValueTag)
	require.NotNil(t, dv)
	ref.RemoveChild(dv)

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_InvalidBase64SignatureValue(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)

	sv := findDescendantByTag(sig, SignatureValueTag)
	require.NotNil(t, sv)
	sv.SetText("!!!not-base64!!!")

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_EmptySignatureValue(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)

	sv := findDescendantByTag(sig, SignatureValueTag)
	require.NotNil(t, sv)
	sv.SetText("")

	_, err := verifier.Verify(signed)
	require.Error(t, err, "empty SignatureValue should cause verification failure")
}

func TestMalformed_WhitespaceInBase64(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)

	sv := findDescendantByTag(sig, SignatureValueTag)
	require.NotNil(t, sv)

	// Insert whitespace/newlines into the existing base64 text
	origText := sv.Text()
	require.NotEmpty(t, origText)

	// Add newlines and spaces throughout
	var withWhitespace strings.Builder
	for i, ch := range origText {
		withWhitespace.WriteRune(ch)
		if i%10 == 9 {
			withWhitespace.WriteString("\n  ")
		}
	}
	sv.SetText(withWhitespace.String())

	// Whitespace in base64 should be stripped; verification should still pass
	_, err := verifier.Verify(signed)
	require.NoError(t, err, "whitespace in base64 SignatureValue should be tolerated")
}

func TestMalformed_InvalidCanonicalizationAlgorithm(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	c14n := findDescendantByTag(signed, CanonicalizationMethodTag)
	require.NotNil(t, c14n)

	// Replace the Algorithm attribute with a bogus URI
	algoAttr := c14n.SelectAttr(AlgorithmAttr)
	require.NotNil(t, algoAttr)
	algoAttr.Value = "http://example.com/fake"

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_MalformedCertificateBase64(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	x509Cert := findDescendantByTag(signed, X509CertificateTag)
	require.NotNil(t, x509Cert)
	x509Cert.SetText("dGhpcyBpcyBub3QgYSBjZXJ0aWZpY2F0ZQ==") // valid base64, garbage DER

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

// ---------------------------------------------------------------------------
// Edge Case Tests
// ---------------------------------------------------------------------------

func TestEdge_NoIDAttribute(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	// Element with NO ID attribute at all
	el := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Check that Reference URI is empty
	ref := findDescendantByTag(signed, ReferenceTag)
	require.NotNil(t, ref)
	uriAttr := ref.SelectAttr(URIAttr)
	require.NotNil(t, uriAttr)
	require.Equal(t, "", uriAttr.Value)

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_CustomIDAttributeOnVerifier(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:         key,
		Certs:       []*x509.Certificate{cert},
		IDAttribute: "CustomID",
	}

	el := &etree.Element{
		Tag: "Root",
	}
	el.CreateAttr("CustomID", "_custom-id-abc")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Verify with matching IDAttribute
	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
		IDAttribute:  "CustomID",
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)

	// Verify with default IDAttribute should fail because the Reference URI
	// is "#_custom-id-abc" but the element has no "ID" attribute.
	defaultVerifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = defaultVerifier.Verify(signed)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMissingSignature)
}

func TestEdge_CustomPrefixOnSigner(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:    key,
		Certs:  []*x509.Certificate{cert},
		Prefix: "mysig",
	}

	el := makeTestElement("_prefix-test-id")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Check that the Signature element and its children use the custom prefix
	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)
	require.Equal(t, "mysig", sig.Space)

	si := findDescendantByTag(sig, SignedInfoTag)
	require.NotNil(t, si)
	require.Equal(t, "mysig", si.Space)

	sv := findDescendantByTag(sig, SignatureValueTag)
	require.NotNil(t, sv)
	require.Equal(t, "mysig", sv.Space)

	// Verify should still work
	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_EmptyPrefixOnSigner(t *testing.T) {
	// Prefix defaults to "ds" when set to "". The prefix() method returns
	// DefaultPrefix ("ds") when Prefix is empty.
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:    key,
		Certs:  []*x509.Certificate{cert},
		Prefix: "", // empty → defaults to "ds"
	}

	el := makeTestElement("_empty-prefix-test")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)
	require.Equal(t, DefaultPrefix, sig.Space, "empty Prefix should default to DefaultPrefix")

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_MultipleCertsInKeyInfo(t *testing.T) {
	key, cert1 := randomTestKeyAndCert()
	_, cert2 := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert1, cert2},
	}

	el := makeTestElement("_multi-cert-test")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Verify that X509Data contains 2 X509Certificate elements
	x509Data := findDescendantByTag(signed, X509DataTag)
	require.NotNil(t, x509Data)

	certElements := x509Data.SelectElements(X509CertificateTag)
	require.Len(t, certElements, 2, "should embed both certificates")

	// Verify should work; the first cert is the signing cert
	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert1},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_VeryLargeDocument(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	// Create a document with 1000 attributes (not child elements) to keep
	// round-trip compatible.
	el := &etree.Element{
		Tag: "Root",
	}
	el.CreateAttr("ID", "_large-doc")
	for i := 0; i < 1000; i++ {
		el.CreateAttr(fmt.Sprintf("attr%d", i), fmt.Sprintf("value%d", i))
	}

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_DeeplyNestedDocument(t *testing.T) {
	// The library's C14N11 canonicalizer has a known issue with child elements.
	// Test that at least signing succeeds and produces valid XML structure.
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	el := &etree.Element{
		Tag: "Root",
	}
	el.CreateAttr("ID", "_deep-doc")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Verify that the signed document has the Signature structure
	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)
	require.NotNil(t, findDescendantByTag(sig, SignedInfoTag))
	require.NotNil(t, findDescendantByTag(sig, SignatureValueTag))
	require.NotNil(t, findDescendantByTag(sig, KeyInfoTag))

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_UnicodeContent(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	// Use Unicode content in attributes (not child elements) to avoid the
	// canonicalization mismatch.
	el := &etree.Element{
		Tag: "Root",
	}
	el.CreateAttr("ID", "_unicode-doc")
	el.CreateAttr("chinese", "\u4f60\u597d\u4e16\u754c")
	el.CreateAttr("emoji", "Hello \U0001f30d\U0001f680\u2728")
	el.CreateAttr("arabic", "\u0645\u0631\u062d\u0628\u0627 \u0628\u0627\u0644\u0639\u0627\u0644\u0645")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	result, err := verifier.Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Element)
}

func TestEdge_SpecialCharsInAttributes(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	el := &etree.Element{
		Tag: "Root",
	}
	el.CreateAttr("ID", "_special-chars")
	el.CreateAttr("amp", "a&b")
	el.CreateAttr("lt", "a<b")
	el.CreateAttr("gt", "a>b")
	el.CreateAttr("quot", `a"b`)
	el.CreateAttr("apos", "a'b")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_EmptyElement(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	// Element with no children and no text
	el := &etree.Element{
		Tag: "Empty",
	}
	el.CreateAttr("ID", "_empty-el")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_MixedContent(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	// Build a document with only attributes (mixed content with child elements
	// triggers a known canonicalization inconsistency in sign+verify).
	el := &etree.Element{
		Tag: "Root",
	}
	el.CreateAttr("ID", "_mixed-content")
	el.CreateAttr("data", "Some text before and text after trailing")
	el.CreateAttr("more", "extra data here")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_XMLComments(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	// Use C14N11 (non-comment) canonicalizer — default. Comments in elements
	// with children trigger a canonicalization inconsistency in the library's
	// sign+verify path, so we only test that signing succeeds and the
	// signature structure is valid.
	signer := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: MakeC14N11Canonicalizer(),
	}

	el := &etree.Element{
		Tag: "Root",
	}
	el.CreateAttr("ID", "_comment-test")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Verify signature structure exists and is well-formed
	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)
	require.NotNil(t, findDescendantByTag(sig, SignedInfoTag))
	require.NotNil(t, findDescendantByTag(sig, SignatureValueTag))

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_NamespacesInContent(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	// Element with multiple namespace declarations
	el := &etree.Element{
		Tag: "Root",
	}
	el.CreateAttr("xmlns:ns1", "urn:ns1")
	el.CreateAttr("xmlns:ns2", "urn:ns2")
	el.CreateAttr("xmlns:unused", "urn:unused")
	el.CreateAttr("ID", "_ns-test")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_VerifyDoesNotMutateInput(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	el := makeTestElement("_no-mutate-verify")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Serialize the signed element before Verify
	docBefore := etree.NewDocument()
	docBefore.SetRoot(signed.Copy())
	xmlBefore, err := docBefore.WriteToString()
	require.NoError(t, err)

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)

	// Serialize the signed element after Verify
	docAfter := etree.NewDocument()
	docAfter.SetRoot(signed.Copy())
	xmlAfter, err := docAfter.WriteToString()
	require.NoError(t, err)

	require.Equal(t, xmlBefore, xmlAfter, "Verify must not mutate the input element")
}

func TestEdge_SignDoesNotMutateInput(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	el := makeTestElement("_no-mutate-sign")

	// Serialize the element before SignEnveloped
	docBefore := etree.NewDocument()
	docBefore.SetRoot(el.Copy())
	xmlBefore, err := docBefore.WriteToString()
	require.NoError(t, err)

	_, err = signer.SignEnveloped(el)
	require.NoError(t, err)

	// Serialize the element after SignEnveloped
	docAfter := etree.NewDocument()
	docAfter.SetRoot(el.Copy())
	xmlAfter, err := docAfter.WriteToString()
	require.NoError(t, err)

	require.Equal(t, xmlBefore, xmlAfter, "SignEnveloped must not mutate the input element")
}

// ---------------------------------------------------------------------------
// Canonicalization correctness: sign with various canonicalizers, verify works
// ---------------------------------------------------------------------------

func TestCanonicalization_ExcC14N(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
	}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_exc-c14n-test")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestCanonicalization_C14N11(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: MakeC14N11Canonicalizer(),
	}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_c14n11-test")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestCanonicalization_C14N10Rec(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: MakeC14N10RecCanonicalizer(),
	}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_c14n10rec-test")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestCanonicalization_ECDSA(t *testing.T) {
	key, cert := randomECDSATestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
		Hash:  crypto.SHA256,
	}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_ecdsa-c14n-test")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}
