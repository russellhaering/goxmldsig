package dsig

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNamespaceConfusion tests Namespace Confusion / Prefix Rebinding attacks.
//
// These attacks try to trick the verifier into either:
//   - Accepting a forged Signature by binding the expected prefix to a different URI
//   - Ignoring the real Signature because prefix resolution is prefix-based instead
//     of URI-based
//   - Misinterpreting non-signature elements as signature elements via default
//     namespace shadowing
//
// The verifier MUST resolve namespace prefixes to URIs via the in-scope
// namespace context (not by comparing prefix strings) and only recognise
// elements whose resolved URI equals "http://www.w3.org/2000/09/xmldsig#".
func TestNamespaceConfusion(t *testing.T) {

	// signDocWithPrefix is a helper that signs a simple document using
	// the given namespace prefix for ds: elements.
	signDocWithPrefix := func(t *testing.T, prefix string, c14n Canonicalizer) (*etree.Element, crypto.Signer, *x509.Certificate) {
		t.Helper()
		key, cert := randomTestKeyAndCert()
		signer := &Signer{
			Key:    key,
			Certs:  []*x509.Certificate{cert},
			Prefix: prefix,
		}
		if c14n != nil {
			signer.Canonicalizer = c14n
		}

		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("ID", "_ns_test")
		el.CreateElement("Data").SetText("payload")

		signed, err := signer.SignEnveloped(el)
		require.NoError(t, err)
		signed = reparse(t, signed)
		return signed, key, cert
	}

	// ----------------------------------------------------------------
	// 1. Prefix rebinding attack
	// ----------------------------------------------------------------
	t.Run("PrefixRebindingAttack", func(t *testing.T) {
		// Attack scenario: An attacker takes a validly-signed document and
		// adds a namespace declaration on an ancestor element that re-binds
		// the "ds" prefix to a different (evil) URI. If the verifier compares
		// only prefix strings ("ds" == "ds") instead of resolving to URIs,
		// it could be fooled into treating a completely different element
		// tree as a valid Signature.
		//
		// Expected: The verifier must still find the real Signature because
		// the Signature element itself carries xmlns:ds="http://www.w3.org/
		// 2000/09/xmldsig#" which shadows the evil outer declaration. If the
		// outer rebinding is placed such that it DOES shadow the Signature's
		// own declaration (not possible when the Signature carries its own),
		// the verifier must fail with ErrMissingSignature.

		signed, _, cert := signDocWithPrefix(t, "ds", nil)

		// Wrap in an outer element that rebinds "ds" to an evil URI.
		// The real Signature still carries its own xmlns:ds, so the
		// verifier should shadow correctly and still verify.
		envelope := etree.NewElement("Envelope")
		envelope.CreateAttr("xmlns:ds", "http://evil.example.com/fake-dsig")
		envelope.AddChild(signed)
		envelope = reparse(t, envelope)

		// Extract the Response child back out for verification.
		response := envelope.FindElement("//Response")
		require.NotNil(t, response)

		// Detach from envelope so it's the root for Verify.
		doc := etree.NewDocument()
		doc.SetRoot(response.Copy())
		s, err := doc.WriteToString()
		require.NoError(t, err)
		doc2 := etree.NewDocument()
		require.NoError(t, doc2.ReadFromString(s))
		responseRoot := doc2.Root()

		v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		result, err := v.Verify(responseRoot)
		// The Signature carries its own xmlns:ds declaration so it
		// should still verify successfully.
		require.NoError(t, err)
		require.NotNil(t, result)

		// Now test the case where we REMOVE the xmlns:ds from the
		// Signature element itself and rely on an ancestor that binds
		// ds to the WRONG URI. The verifier must NOT find the Signature.
		signed2, _, cert2 := signDocWithPrefix(t, "ds", nil)

		// Manually strip xmlns:ds from the Signature element.
		sig := findSig(signed2)
		require.NotNil(t, sig)
		newAttrs := make([]etree.Attr, 0, len(sig.Attr))
		for _, attr := range sig.Attr {
			if attr.Space == "xmlns" && attr.Key == "ds" {
				continue
			}
			newAttrs = append(newAttrs, attr)
		}
		sig.Attr = newAttrs

		// Add an ancestor-level xmlns:ds binding to a wrong URI.
		signed2.CreateAttr("xmlns:ds", "http://evil.example.com/not-dsig")
		signed2 = reparse(t, signed2)

		v2 := &Verifier{TrustedCerts: []*x509.Certificate{cert2}}
		_, err = v2.Verify(signed2)
		// The verifier resolves ds → http://evil.example.com/not-dsig,
		// which ≠ Namespace, so the Signature is not found.
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrMissingSignature),
			"expected ErrMissingSignature when ds prefix is rebound to evil URI, got: %v", err)
	})

	// ----------------------------------------------------------------
	// 2. Default namespace shadowing
	// ----------------------------------------------------------------
	t.Run("DefaultNamespaceShadowing", func(t *testing.T) {
		// Attack scenario: A non-Signature element declares
		// xmlns="http://www.w3.org/2000/09/xmldsig#" (the default
		// namespace) to make its unprefixed child elements look like
		// dsig elements. The verifier must NOT confuse these with the
		// actual ds:Signature.

		key, cert := randomTestKeyAndCert()
		signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("ID", "_ns_shadow")
		el.CreateElement("Data").SetText("payload")
		signed, err := signer.SignEnveloped(el)
		require.NoError(t, err)
		signed = reparse(t, signed)

		// Insert a decoy that uses the default namespace to masquerade.
		// <FakeContainer xmlns="http://www.w3.org/2000/09/xmldsig#">
		//   <Signature>...</Signature>
		// </FakeContainer>
		// The inner <Signature> has no prefix → Space="" → default ns
		// = dsig namespace. But it is NOT a direct child of Response,
		// so the verifier must not be confused.
		fakeContainer := signed.CreateElement("FakeContainer")
		fakeContainer.CreateAttr("xmlns", Namespace)
		fakeSig := fakeContainer.CreateElement("Signature")
		// Space is empty (default namespace).
		fakeSig.Space = ""
		fakeSig.CreateElement("FakeData").SetText("evil")

		signed = reparse(t, signed)

		// The real ds:Signature is a direct child; the decoy is nested.
		// Verify should still find the real one and succeed.
		v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		_, err = v.Verify(signed)
		// The fake Signature is not structurally valid (wrong children),
		// and the real one is intact. Depending on ordering, the verifier
		// may skip the fake or may error on its structure. Either way,
		// the real data must not be corrupted.
		// Actually: the fake is a child of FakeContainer, not of Response,
		// so findSignature (which only looks at direct children) won't see it.
		// But adding FakeContainer changes the digest.
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrDigestMismatch),
			"expected ErrDigestMismatch because we added a new child, got: %v", err)
	})

	// ----------------------------------------------------------------
	// 3. Alternative prefix for Signature
	// ----------------------------------------------------------------
	t.Run("AlternativePrefixSignature", func(t *testing.T) {
		// Verify that the library correctly handles non-standard prefixes.
		// Sign with prefix "mysig" instead of "ds". The verifier must find
		// the Signature by resolving "mysig" → Namespace URI, not by
		// looking for prefix "ds".

		signed, _, cert := signDocWithPrefix(t, "mysig", nil)

		// Sanity: confirm the prefix is actually "mysig" in the output.
		doc := etree.NewDocument()
		doc.SetRoot(signed)
		xmlStr, err := doc.WriteToString()
		require.NoError(t, err)
		assert.Contains(t, xmlStr, "mysig:Signature")
		assert.Contains(t, xmlStr, "xmlns:mysig")

		// Re-parse (WriteToString may have altered parent pointers).
		doc2 := etree.NewDocument()
		require.NoError(t, doc2.ReadFromString(xmlStr))

		v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		result, err := v.Verify(doc2.Root())
		require.NoError(t, err, "verifier should find Signature via namespace URI, not prefix name")
		require.NotNil(t, result)
		d := result.Element.FindElement("//Data")
		require.NotNil(t, d)
		assert.Equal(t, "payload", d.Text())
	})

	// ----------------------------------------------------------------
	// 4. Empty namespace undeclaration inside signed content
	// ----------------------------------------------------------------
	t.Run("EmptyNamespaceUndeclaration", func(t *testing.T) {
		// Ensure that xmlns="" on a child element within the signed
		// content is handled correctly by canonicalization.
		// We build a document with xmlns="" on a child, sign it, and
		// verify. The canonical form must be stable.

		key, cert := randomTestKeyAndCert()
		signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("ID", "_ns_undecl")
		el.CreateAttr("xmlns:app", "urn:example:app")

		child := el.CreateElement("Child")
		child.Space = "app"
		child.SetText("value")

		// Undeclare default namespace on a nested element.
		nested := child.CreateElement("Nested")
		nested.CreateAttr("xmlns", "")
		nested.SetText("inner")

		signed, err := signer.SignEnveloped(el)
		require.NoError(t, err)
		signed = reparse(t, signed)

		v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		result, err := v.Verify(signed)
		require.NoError(t, err, "xmlns='' undeclaration must be handled correctly by C14N")
		require.NotNil(t, result)
	})

	// ----------------------------------------------------------------
	// 5. Namespace URI in attribute values (not declarations)
	// ----------------------------------------------------------------
	t.Run("NamespaceInAttributeValues", func(t *testing.T) {
		// A namespace URI appearing in an attribute *value* (not an xmlns
		// declaration) must NOT be treated as a namespace binding. For
		// example:
		//   <Response Algorithm="http://www.w3.org/2000/09/xmldsig#">
		// This does not bind any prefix to the dsig namespace.

		key, cert := randomTestKeyAndCert()
		signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("ID", "_ns_attrval")
		// Put the dsig namespace URI in a plain attribute value.
		el.CreateAttr("SchemaLocation", Namespace)
		el.CreateElement("Data").SetText("with-ns-in-attr")

		signed, err := signer.SignEnveloped(el)
		require.NoError(t, err)
		signed = reparse(t, signed)

		v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		result, err := v.Verify(signed)
		require.NoError(t, err, "namespace URI in attribute value must not confuse verifier")
		require.NotNil(t, result)

		// Now tamper: add an element that uses the attribute-value URI as
		// if it were a namespace. This should break the digest.
		signed2, err := signer.SignEnveloped(el)
		require.NoError(t, err)
		signed2 = reparse(t, signed2)
		signed2.CreateElement("Injected").SetText("evil")
		_, err = v.Verify(signed2)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
	})

	// ----------------------------------------------------------------
	// 6. Multiple prefixes for same namespace
	// ----------------------------------------------------------------
	t.Run("MultiplePrefixesSameNamespace", func(t *testing.T) {
		// Two different prefixes pointing to the same namespace URI.
		// Canonicalization must handle this correctly and produce a
		// stable canonical form. We build a document with both
		// xmlns:ns1 and xmlns:ns2 pointing to the same custom URI,
		// sign it, and verify.

		key, cert := randomTestKeyAndCert()
		signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("ID", "_ns_multi")
		el.CreateAttr("xmlns:ns1", "urn:example:shared")
		el.CreateAttr("xmlns:ns2", "urn:example:shared")

		c1 := el.CreateElement("Child1")
		c1.Space = "ns1"
		c1.SetText("hello")

		c2 := el.CreateElement("Child2")
		c2.Space = "ns2"
		c2.SetText("world")

		signed, err := signer.SignEnveloped(el)
		require.NoError(t, err)
		signed = reparse(t, signed)

		v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		result, err := v.Verify(signed)
		require.NoError(t, err, "multiple prefixes for same NS should not break verification")
		require.NotNil(t, result)
	})

	// ----------------------------------------------------------------
	// 7. Fake Signature with wrong namespace
	// ----------------------------------------------------------------
	t.Run("FakeSignatureWrongNamespace", func(t *testing.T) {
		// Attack scenario: An attacker crafts a <fake:Signature> element
		// where "fake" maps to http://evil.com/ns instead of the real
		// dsig namespace. This must NOT be treated as a valid ds:Signature.

		key, cert := randomTestKeyAndCert()

		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("ID", "_ns_fake")
		el.CreateElement("Data").SetText("payload")

		// Build a fake Signature element with a non-dsig namespace.
		fakeSig := el.CreateElement("Signature")
		fakeSig.Space = "fake"
		el.CreateAttr("xmlns:fake", "http://evil.com/ns")

		// Give it a plausible-looking structure.
		si := fakeSig.CreateElement("SignedInfo")
		si.Space = "fake"
		sv := fakeSig.CreateElement("SignatureValue")
		sv.Space = "fake"
		sv.SetText("ZmFrZQ==") // base64("fake")

		// Re-parse so namespace declarations are materialised.
		el = reparse(t, el)

		v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		_, err := v.Verify(el)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrMissingSignature),
			"fake:Signature (xmlns:fake=http://evil.com/ns) must not be recognised, got: %v", err)

		// Bonus: also add a REAL signature and the fake one. The verifier
		// must use the real one, ignoring the fake.
		el2 := &etree.Element{Tag: "Response"}
		el2.CreateAttr("ID", "_ns_fake2")
		el2.CreateAttr("xmlns:fake", "http://evil.com/ns")
		el2.CreateElement("Data").SetText("payload")

		signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
		signed, err := signer.SignEnveloped(el2)
		require.NoError(t, err)
		signed = reparse(t, signed)

		// Add the fake Signature as well (direct child).
		fakeSig2 := signed.CreateElement("Signature")
		fakeSig2.Space = "fake"
		fakeSignedInfo := fakeSig2.CreateElement("SignedInfo")
		fakeSignedInfo.Space = "fake"
		fakeSigVal := fakeSig2.CreateElement("SignatureValue")
		fakeSigVal.Space = "fake"
		fakeSigVal.SetText("ZmFrZQ==")

		signed = reparse(t, signed)

		// The digest will fail because we added the fake element to the tree
		// after signing, but importantly the verifier must not confuse the
		// fake Signature with the real one. The error should be digest
		// mismatch (real sig found, digest broken), NOT missing signature.
		_, err = v.Verify(signed)
		require.Error(t, err)
		assert.False(t, errors.Is(err, ErrMissingSignature),
			"verifier should find the REAL signature, not report missing; got: %v", err)
	})

	// ----------------------------------------------------------------
	// 8. Prefix reuse with different namespace on ancestor
	// ----------------------------------------------------------------
	t.Run("PrefixReuseWithDifferentNamespace", func(t *testing.T) {
		// Attack scenario: The element tree has an ancestor element
		// <ds:Foo xmlns:ds="http://other.com"> wrapping a legitimately
		// signed document. The Signature inside still declares
		// xmlns:ds="http://www.w3.org/2000/09/xmldsig#" on itself.
		// The verifier must use the NEAREST ancestor's ns declaration
		// (i.e., the one on the Signature itself), not the outer one.

		signed, _, cert := signDocWithPrefix(t, "ds", nil)

		// Serialize to XML.
		doc := etree.NewDocument()
		doc.SetRoot(signed)
		xmlStr, err := doc.WriteToString()
		require.NoError(t, err)

		// Wrap in an outer element that reuses "ds" for a different namespace.
		wrapped := fmt.Sprintf(
			`<ds:Outer xmlns:ds="http://other.com/ns">%s</ds:Outer>`,
			xmlStr,
		)
		doc2 := etree.NewDocument()
		require.NoError(t, doc2.ReadFromString(wrapped))

		// Extract the inner Response.
		var response *etree.Element
		for _, child := range doc2.Root().ChildElements() {
			if child.Tag == "Response" {
				response = child
				break
			}
		}
		require.NotNil(t, response)

		// Re-root the response (detach from the outer element).
		doc3 := etree.NewDocument()
		doc3.SetRoot(response.Copy())
		reXML, err := doc3.WriteToString()
		require.NoError(t, err)
		doc4 := etree.NewDocument()
		require.NoError(t, doc4.ReadFromString(reXML))

		v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		result, err := v.Verify(doc4.Root())
		require.NoError(t, err, "nearest-ancestor ns declaration must win")
		require.NotNil(t, result)
	})
}

// TestNamespaceConfusion_PrefixRebindOnSignedInfoChildren tests that even
// if someone injects a namespace redeclaration on inner elements of a
// signed Signature (e.g. on SignedInfo), it either invalidates the crypto
// or is ignored.
func TestNamespaceConfusion_PrefixRebindOnSignedInfoChildren(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_rsi")

	// Attempt to add a namespace rebinding on the SignedInfo element.
	sig := findSig(signed)
	require.NotNil(t, sig)
	var signedInfo *etree.Element
	for _, c := range sig.ChildElements() {
		if c.Tag == SignedInfoTag {
			signedInfo = c
			break
		}
	}
	require.NotNil(t, signedInfo)

	// Rebind "ds" on SignedInfo to a different URI.
	signedInfo.CreateAttr("xmlns:ds", "http://evil.example.com/attack")
	signed = reparse(t, signed)

	v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err := v.Verify(signed)
	// The rebinding changes the canonical form of SignedInfo, which
	// should invalidate the cryptographic signature. Alternatively,
	// findSignature may fail to find SignedInfo because it now resolves
	// to the wrong namespace.
	require.Error(t, err, "rebinding ds on SignedInfo must break verification")
	assert.True(t,
		errors.Is(err, ErrSignatureInvalid) ||
			errors.Is(err, ErrMissingSignature) ||
			errors.Is(err, ErrMalformedSignature),
		"expected crypto or structure error, got: %v", err)
}

// TestNamespaceConfusion_UnprefixedSignature tests that a Signature element
// using the default namespace (no prefix) with the correct dsig URI is
// recognised by the verifier, and that one with the wrong default namespace
// is rejected.
//
// Note: The Signer.Prefix field defaults to "ds" when empty, so we cannot
// get a truly unprefixed Signature from the Signer API alone. We test the
// verifier side using hand-crafted XML.
func TestNamespaceConfusion_UnprefixedSignature(t *testing.T) {
	_, cert := randomTestKeyAndCert()

	// Build raw XML with unprefixed Signature having the wrong namespace.
	rawXML := `<Response ID="_unpref_wrong">
  <Data>payload</Data>
  <Signature xmlns="http://evil.example.com/fake">
    <SignedInfo/>
    <SignatureValue>ZmFrZQ==</SignatureValue>
  </Signature>
</Response>`

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(rawXML))

	v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err := v.Verify(doc.Root())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingSignature),
		"unprefixed Signature with wrong default namespace must be rejected, got: %v", err)

	// Now test with correct default namespace but malformed structure.
	rawXML2 := `<Response ID="_unpref_right">
  <Data>payload</Data>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo/>
    <SignatureValue>ZmFrZQ==</SignatureValue>
  </Signature>
</Response>`

	doc2 := etree.NewDocument()
	require.NoError(t, doc2.ReadFromString(rawXML2))

	_, err = v.Verify(doc2.Root())
	require.Error(t, err)
	// The Signature IS found (correct namespace), but has invalid structure.
	assert.False(t, errors.Is(err, ErrMissingSignature),
		"unprefixed Signature with correct xmlns should be found (not missing), got: %v", err)
}

// TestNamespaceConfusion_MultipleDsigPrefixesOnSameElement tests that having
// two xmlns declarations for the dsig namespace on the same document does
// not confuse the verifier or canonicalization.
func TestNamespaceConfusion_MultipleDsigPrefixesOnSameElement(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_multi_dsig")
	// Declare the dsig namespace under a second prefix on the root.
	el.CreateAttr("xmlns:dsig2", Namespace)
	el.CreateElement("Data").SetText("multi-dsig")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	result, err := v.Verify(signed)
	require.NoError(t, err, "extra dsig prefix alias should not break verification")
	require.NotNil(t, result)
}

// TestNamespaceConfusion_SignatureInWrongDefaultNS ensures that an unprefixed
// <Signature> whose default namespace is NOT the dsig namespace is correctly
// ignored by the verifier.
func TestNamespaceConfusion_SignatureInWrongDefaultNS(t *testing.T) {
	_, cert := randomTestKeyAndCert()

	// Build a document from raw XML with a <Signature> element whose default
	// namespace is wrong.
	rawXML := `<Response ID="_wrong_ns">
  <Data>payload</Data>
  <Signature xmlns="http://wrong.example.com/not-dsig">
    <SignedInfo/>
    <SignatureValue>ZmFrZQ==</SignatureValue>
  </Signature>
</Response>`

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(rawXML))

	v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err := v.Verify(doc.Root())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingSignature),
		"Signature in wrong default namespace must not be recognised, got: %v", err)
}

// TestNamespaceConfusion_AlternativePrefixes_ExcC14N tests that signing with
// different prefixes works correctly with exclusive C14N as well.
func TestNamespaceConfusion_AlternativePrefixes_ExcC14N(t *testing.T) {
	prefixes := []string{"ds", "dsig", "mysig", "xmldsig", ""}

	for _, prefix := range prefixes {
		name := prefix
		if name == "" {
			name = "empty"
		}
		t.Run(fmt.Sprintf("Prefix_%s", name), func(t *testing.T) {
			key, cert := randomTestKeyAndCert()
			signer := &Signer{
				Key:           key,
				Certs:         []*x509.Certificate{cert},
				Prefix:        prefix,
				Canonicalizer: MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
			}

			el := &etree.Element{Tag: "Response"}
			el.CreateAttr("ID", fmt.Sprintf("_prefix_%s", name))
			el.CreateElement("Data").SetText("test-" + name)

			signed, err := signer.SignEnveloped(el)
			require.NoError(t, err)
			signed = reparse(t, signed)

			v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
			result, err := v.Verify(signed)
			require.NoError(t, err, "prefix %q with exc-c14n should verify", prefix)
			require.NotNil(t, result)

			d := result.Element.FindElement("//Data")
			require.NotNil(t, d)
			assert.Equal(t, "test-"+name, d.Text())
		})
	}
}

// TestNamespaceConfusion_XmlnsAttributeInjection tests that injecting xmlns
// attributes after signing invalidates the digest, even if the injected
// attribute doesn't change the apparent structure.
func TestNamespaceConfusion_XmlnsAttributeInjection(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_xmlns_inject")

	// Inject a new namespace declaration that wasn't there at signing time.
	signed.CreateAttr("xmlns:evil", "http://evil.example.com/ns")
	signed = reparse(t, signed)

	v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err := v.Verify(signed)
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrDigestMismatch) || errors.Is(err, ErrSignatureInvalid),
		"injected xmlns attribute must invalidate signature, got: %v", err)
}

// TestNamespaceConfusion_DeeplyNestedPrefixShadowing tests that prefix
// shadowing at many levels deep is handled correctly.
func TestNamespaceConfusion_DeeplyNestedPrefixShadowing(t *testing.T) {
	// Build a document where prefix "app" is shadowed at multiple levels.
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_deep")
	el.CreateAttr("xmlns:app", "urn:level0")

	level1 := el.CreateElement("Level1")
	level1.CreateAttr("xmlns:app", "urn:level1")
	c1 := level1.CreateElement("Item")
	c1.Space = "app"
	c1.SetText("at-level-1")

	level2 := level1.CreateElement("Level2")
	level2.CreateAttr("xmlns:app", "urn:level2")
	c2 := level2.CreateElement("Item")
	c2.Space = "app"
	c2.SetText("at-level-2")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	result, err := v.Verify(signed)
	require.NoError(t, err, "deeply nested prefix shadowing should not break verification")
	require.NotNil(t, result)

	// Tamper: change one of the shadowed namespace URIs.
	signed2, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed2 = reparse(t, signed2)

	// Find Level2 and change its xmlns:app.
	doc := etree.NewDocument()
	doc.SetRoot(signed2)
	xmlStr, err := doc.WriteToString()
	require.NoError(t, err)
	// Tamper by replacing the namespace URI.
	tampered := strings.Replace(xmlStr, "urn:level2", "urn:evil2", 1)
	doc2 := etree.NewDocument()
	require.NoError(t, doc2.ReadFromString(tampered))

	_, err = v.Verify(doc2.Root())
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrDigestMismatch) || errors.Is(err, ErrSignatureInvalid),
		"tampering with nested namespace URI must break verification, got: %v", err)
}
