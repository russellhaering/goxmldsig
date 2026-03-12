package dsig

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Cross-Reference Confusion Attack Tests
//
// These tests verify that the library correctly handles Reference URI matching
// in ds:Signature elements, preventing attackers from confusing the verifier
// about which element was actually signed.
//
// Key areas tested:
//   - Duplicate ID values in a document
//   - Percent-encoded URIs
//   - XPointer URIs (should be unsupported)
//   - Empty URI semantics
//   - External URIs (must be rejected)
//   - URIs with query strings or fragments
//   - Case sensitivity of ID matching
//   - URIs with spaces or special characters
// =============================================================================

// ---------------------------------------------------------------------------
// Test 1: Duplicate IDs
// ---------------------------------------------------------------------------

func TestCrossRef_DuplicateIDs_SignedElementVerifies(t *testing.T) {
	// Attack scenario: An attacker creates a document with two elements sharing
	// the same ID. The signer signs one element. If the verifier picks a different
	// element by ID, the attacker could substitute content.
	//
	// Expected behavior: When we call Verify on the actual signed element, it
	// should succeed and return the content that was actually signed ("good").
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_dup1")
	el.CreateElement("Data").SetText("good")

	signed := signAndReparse(t, key, cert, el)

	// Verify the signed element directly – must succeed.
	result, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)
	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	assert.Equal(t, "good", d.Text())
}

func TestCrossRef_DuplicateIDs_EvilSiblingWithSameID(t *testing.T) {
	// Attack scenario: The signed element is placed alongside an evil sibling
	// that shares the same ID value. The verifier should only examine the
	// element it was asked to verify (the signed one), not resolve the ID
	// globally and potentially pick the evil sibling.
	//
	// Expected behavior: Verify on the signed element succeeds and returns
	// "good" content, not "evil".
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_dup2")

	// Create an outer envelope with an evil sibling having the same ID.
	envelope := etree.NewElement("Envelope")
	evil := etree.NewElement("Response")
	evil.CreateAttr("ID", "_dup2")
	evil.CreateElement("Data").SetText("evil")
	envelope.AddChild(evil)
	envelope.AddChild(signed)

	// Verify the actual signed element, not the envelope.
	result, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)
	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	assert.Equal(t, "good", d.Text(), "verifier must return the actually-signed content, not evil sibling")
}

func TestCrossRef_DuplicateIDs_VerifyEvilElementFails(t *testing.T) {
	// Attack scenario: Attacker takes a legitimately signed document and tries
	// to get the verifier to accept a different element (evil) that happens to
	// share the same ID. We verify the evil element that does not contain a
	// valid signature.
	//
	// Expected behavior: Verification of the evil element fails because the
	// signature is not a direct child of it.
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_dup3")

	evil := etree.NewElement("Response")
	evil.CreateAttr("ID", "_dup3")
	evil.CreateElement("Data").SetText("evil")

	envelope := etree.NewElement("Envelope")
	envelope.AddChild(evil)
	envelope.AddChild(signed)

	// Verifying the evil element should fail – it has no signature child.
	_, err := newVerifier(cert).Verify(evil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingSignature), "got: %v", err)
}

// ---------------------------------------------------------------------------
// Test 2: URL-Encoded / Percent-Encoded URI
// ---------------------------------------------------------------------------

func TestCrossRef_PercentEncodedURI(t *testing.T) {
	// Attack scenario: The Reference URI uses percent-encoding, e.g.
	// URI="#%5Fid1" instead of URI="#_id1". If the library decodes percent-
	// encoding before matching, this could allow bypasses. XML Digital
	// Signatures should compare the URI value as-is (no percent decoding
	// for fragment identifiers in the Reference element).
	//
	// Expected behavior: A percent-encoded URI will NOT match the element's
	// ID attribute (since the library does literal string comparison), so
	// verification should fail with ErrMissingSignature.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_id1")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	// Tamper: change the Reference URI to a percent-encoded equivalent.
	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)

	// Original URI is "#_id1"; replace with percent-encoded form.
	// %5F = underscore, so "#%5Fid1" is semantically "#_id1" in URL terms.
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#%5Fid1"
			break
		}
	}

	// Re-serialize to ensure consistent tree.
	reparsed := reparse(t, signed)

	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	// The literal string "%5Fid1" != "_id1", so the signature won't match.
	// It could be ErrMissingSignature (no matching ref) or ErrSignatureInvalid
	// (SignedInfo was tampered). Either way, it must not succeed.
	assert.True(t,
		errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid) || errors.Is(err, ErrDigestMismatch),
		"percent-encoded URI must not verify; got: %v", err)
}

func TestCrossRef_PercentEncodedAlpha(t *testing.T) {
	// Attack scenario: URI="#%41%42%43" which percent-decodes to "#ABC".
	// Element has ID="ABC". If the library normalizes percent-encoding,
	// it would incorrectly match.
	//
	// Expected behavior: No match, verification fails.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "ABC")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#%41%42%43"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err, "percent-encoded alphabetic URI must not match literal ID")
}

// ---------------------------------------------------------------------------
// Test 3: XPointer URIs
// ---------------------------------------------------------------------------

func TestCrossRef_XPointerURI(t *testing.T) {
	// Attack scenario: XPointer expressions like URI="#xpointer(/)" could
	// reference arbitrary parts of the document. The library should not
	// support XPointer and must reject (or not match) such URIs.
	//
	// Expected behavior: Verification fails – the URI doesn't match the
	// element's ID, so findSignature returns ErrMissingSignature.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_xp1")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#xpointer(/)"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	// The literal "xpointer(/)" won't equal "_xp1", so no match.
	assert.True(t,
		errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid),
		"XPointer URI must not verify; got: %v", err)
}

func TestCrossRef_XPointerID(t *testing.T) {
	// Attack scenario: URI="#xpointer(id('_xp2'))" is another XPointer form.
	// It must not be treated as a simple fragment reference.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_xp2")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#xpointer(id('_xp2'))"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err, "xpointer(id(...)) URI must not match")
}

// ---------------------------------------------------------------------------
// Test 4: Empty URI
// ---------------------------------------------------------------------------

func TestCrossRef_EmptyURI_ValidRoundTrip(t *testing.T) {
	// Baseline: An element with no ID attribute gets an empty URI reference.
	// A clean round-trip (sign, reparse, verify) should succeed.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	// Deliberately no ID attribute → empty URI.
	el.CreateElement("Data").SetText("good")
	signed := signAndReparse(t, key, cert, el)

	// Confirm the Reference URI is indeed empty.
	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	assert.Equal(t, "", ref.SelectAttrValue(URIAttr, "MISSING"))

	result, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)
	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	assert.Equal(t, "good", d.Text())
}

func TestCrossRef_EmptyURI_InjectedContentDetected(t *testing.T) {
	// Attack scenario: With an empty URI, the signature covers the entire
	// element. An attacker injects a new child element after signing.
	// The digest must fail because the canonical form changes.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateElement("Data").SetText("good")
	signed := signAndReparse(t, key, cert, el)

	// Inject evil content outside the original scope.
	signed.CreateElement("Evil").SetText("injected")

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestCrossRef_EmptyURI_MatchesElementWithID(t *testing.T) {
	// Verify that an empty URI (meaning "whole document/element") also matches
	// an element that happens to have an ID. The library allows empty URI to
	// match any element per the spec: sig.refURI == "" is the first branch.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_hasid")
	el.CreateElement("Data").SetText("payload")

	// Sign normally (will get URI="#_hasid").
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	rawSigned, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Tamper: change Reference URI to empty.
	ref := rawSigned.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = ""
			break
		}
	}

	reparsed := reparse(t, rawSigned)

	// This should fail because we changed the URI inside SignedInfo,
	// which changes the SignedInfo canonical form, invalidating the signature.
	_, err = newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrSignatureInvalid) || errors.Is(err, ErrMissingSignature),
		"changing URI after signing must invalidate signature; got: %v", err)
}

// ---------------------------------------------------------------------------
// Test 5: External URIs
// ---------------------------------------------------------------------------

func TestCrossRef_ExternalHTTPURI(t *testing.T) {
	// Attack scenario: An attacker sets URI="http://evil.com/doc.xml" to try
	// to make the verifier fetch an external resource. The library must never
	// dereference external URIs.
	//
	// Expected behavior: The URI doesn't start with '#' and isn't empty, so
	// it won't match the element's ID → ErrMissingSignature.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_ext1")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "http://evil.com/doc.xml"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	// Must not succeed. The URI doesn't start with '#' and isn't empty.
	assert.True(t,
		errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid),
		"external HTTP URI must not verify; got: %v", err)
}

func TestCrossRef_ExternalHTTPSURI(t *testing.T) {
	// Same as above but with https.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_ext2")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "https://evil.com/doc.xml"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid),
		"external HTTPS URI must not verify; got: %v", err)
}

func TestCrossRef_FileURI(t *testing.T) {
	// Attack scenario: URI="file:///etc/passwd" – an attacker tries to make
	// the verifier read a local file.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_ext3")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "file:///etc/passwd"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err, "file: URI must be rejected")
}

// ---------------------------------------------------------------------------
// Test 6: URI with Query String
// ---------------------------------------------------------------------------

func TestCrossRef_URIWithQueryString(t *testing.T) {
	// Attack scenario: URI="#_id1?extra=param" – appending a query string to
	// a fragment URI. The library should not strip query parameters before
	// matching. Since it does literal string comparison after the '#',
	// "_id1?extra=param" != "_id1".
	//
	// Expected behavior: No match, verification fails.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_id1")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#_id1?extra=param"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid),
		"URI with query string must not match; got: %v", err)
}

func TestCrossRef_URIWithAnchorSuffix(t *testing.T) {
	// Attack scenario: URI="#_id1#extra" – a double-fragment.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_id1")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#_id1#extra"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err, "double-fragment URI must not match")
}

// ---------------------------------------------------------------------------
// Test 7: Case Sensitivity
// ---------------------------------------------------------------------------

func TestCrossRef_CaseSensitiveID(t *testing.T) {
	// Attack scenario: XML IDs are case-sensitive. An attacker changes the
	// Reference URI to a different case, hoping the verifier does a
	// case-insensitive comparison.
	//
	// Expected behavior: "_ABC" != "_abc", verification fails.
	key, cert := randomTestKeyAndCert()

	t.Run("uppercase_id_lowercase_ref", func(t *testing.T) {
		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("ID", "_ABC")
		el.CreateElement("Data").SetText("payload")
		signed := signAndReparse(t, key, cert, el)

		ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
		require.NotNil(t, ref)
		for i, a := range ref.Attr {
			if a.Key == URIAttr {
				ref.Attr[i].Value = "#_abc"
				break
			}
		}

		reparsed := reparse(t, signed)
		_, err := newVerifier(cert).Verify(reparsed)
		require.Error(t, err)
		assert.True(t,
			errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid),
			"case mismatch must not match; got: %v", err)
	})

	t.Run("lowercase_id_uppercase_ref", func(t *testing.T) {
		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("ID", "_abc")
		el.CreateElement("Data").SetText("payload")
		signed := signAndReparse(t, key, cert, el)

		ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
		require.NotNil(t, ref)
		for i, a := range ref.Attr {
			if a.Key == URIAttr {
				ref.Attr[i].Value = "#_ABC"
				break
			}
		}

		reparsed := reparse(t, signed)
		_, err := newVerifier(cert).Verify(reparsed)
		require.Error(t, err)
		assert.True(t,
			errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid),
			"case mismatch must not match; got: %v", err)
	})

	t.Run("mixed_case_id_matches_exactly", func(t *testing.T) {
		// Positive test: exact case match should work.
		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("ID", "_AbCdEf")
		el.CreateElement("Data").SetText("payload")
		signed := signAndReparse(t, key, cert, el)

		result, err := newVerifier(cert).Verify(signed)
		require.NoError(t, err)
		assert.NotNil(t, result)
	})
}

// ---------------------------------------------------------------------------
// Test 8: URI with Spaces and Special Characters
// ---------------------------------------------------------------------------

func TestCrossRef_URIWithLeadingSpace(t *testing.T) {
	// Attack scenario: URI="# _id1" – a space after the '#'. The library
	// strips the '#' and compares " _id1" with "_id1", which should NOT match.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_id1")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "# _id1"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err, "URI with leading space after # must not match")
}

func TestCrossRef_URIWithTrailingSpace(t *testing.T) {
	// Attack scenario: URI="#_id1 " – trailing space. Should not match "_id1".
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_id1")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#_id1 "
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err, "URI with trailing space must not match")
}

func TestCrossRef_URIWithTab(t *testing.T) {
	// Attack scenario: URI="#\t_id1" – tab character. Must not match.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_id1")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#\t_id1"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err, "URI with tab must not match")
}

func TestCrossRef_URIWithNewline(t *testing.T) {
	// Attack scenario: URI="#_id1\n" – newline in URI.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_id1")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#_id1\n"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err, "URI with newline must not match")
}

// ---------------------------------------------------------------------------
// Test: Bare Hash URI
// ---------------------------------------------------------------------------

func TestCrossRef_BareHashURI(t *testing.T) {
	// Attack scenario: URI="#" – just a hash with no ID after it.
	// The code checks len(sig.refURI) > 1, so "#" (length 1) won't enter
	// the ID matching branch. It also isn't empty, so the empty-URI branch
	// doesn't apply either. This must fail.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_bare")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid),
		"bare '#' URI must not match any element; got: %v", err)
}

// ---------------------------------------------------------------------------
// Test: URI Referencing a Different Element's ID
// ---------------------------------------------------------------------------

func TestCrossRef_URIMismatch(t *testing.T) {
	// Attack scenario: The Reference URI points to a completely different ID
	// than the element being verified. The library must not match.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_real")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#_completely_different"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid),
		"mismatched URI must not verify; got: %v", err)
}

// ---------------------------------------------------------------------------
// Test: Non-Default ID Attribute Cross-Reference
// ---------------------------------------------------------------------------

func TestCrossRef_NonDefaultIDAttribute(t *testing.T) {
	// Verify that when a non-default ID attribute is used, the cross-reference
	// matching uses the correct attribute.
	key, cert := randomTestKeyAndCert()

	t.Run("matching_custom_id", func(t *testing.T) {
		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("MyID", "_custom1")
		el.CreateElement("Data").SetText("good")

		signer := &Signer{
			Key:         key,
			Certs:       []*x509.Certificate{cert},
			IDAttribute: "MyID",
		}
		rawSigned, err := signer.SignEnveloped(el)
		require.NoError(t, err)
		signed := reparse(t, rawSigned)

		v := &Verifier{
			TrustedCerts: []*x509.Certificate{cert},
			IDAttribute:  "MyID",
		}
		result, err := v.Verify(signed)
		require.NoError(t, err)
		d := result.Element.FindElement("//Data")
		require.NotNil(t, d)
		assert.Equal(t, "good", d.Text())
	})

	t.Run("wrong_id_attribute_in_verifier", func(t *testing.T) {
		// Signer uses "MyID" but verifier looks for default "ID".
		// The element has no "ID" attribute, so idAttr will be empty.
		// The Reference URI is "#_custom2" which won't match empty string.
		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("MyID", "_custom2")
		el.CreateElement("Data").SetText("good")

		signer := &Signer{
			Key:         key,
			Certs:       []*x509.Certificate{cert},
			IDAttribute: "MyID",
		}
		rawSigned, err := signer.SignEnveloped(el)
		require.NoError(t, err)
		signed := reparse(t, rawSigned)

		// Verifier uses default ID attribute ("ID"), not "MyID".
		v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		_, err = v.Verify(signed)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrMissingSignature),
			"verifier with wrong ID attribute must not find signature; got: %v", err)
	})
}

// ---------------------------------------------------------------------------
// Test: URI with Only Whitespace After Hash
// ---------------------------------------------------------------------------

func TestCrossRef_URIOnlyWhitespace(t *testing.T) {
	// Attack scenario: URI="#   " – hash followed by spaces. Should not match
	// an element whose ID is empty or contains spaces.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_ws")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#   "
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err, "URI with only whitespace after # must not match")
}

// ---------------------------------------------------------------------------
// Test: URI with NUL byte
// ---------------------------------------------------------------------------

func TestCrossRef_URIWithNullByte(t *testing.T) {
	// Attack scenario: URI="#_id1\x00" – null byte appended. In some
	// languages, C-string comparison would stop at the null byte and match.
	// Go strings include null bytes, so this should not match.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_id1")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#_id1\x00"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err, "URI with null byte must not match")
}

// ---------------------------------------------------------------------------
// Test: Positive Baseline – Verify Correct URI Works
// ---------------------------------------------------------------------------

func TestCrossRef_ValidURIRoundTrip(t *testing.T) {
	// Baseline test: a properly signed document with matching URI round-trips.
	key, cert := randomTestKeyAndCert()

	ids := []string{
		"_simple",
		"_with-dashes",
		"_with.dots",
		"_MixedCase123",
		"_a", // minimal ID
	}

	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			el := &etree.Element{Tag: "Response"}
			el.CreateAttr("ID", id)
			el.CreateElement("Data").SetText("value-" + id)
			signed := signAndReparse(t, key, cert, el)

			result, err := newVerifier(cert).Verify(signed)
			require.NoError(t, err)
			d := result.Element.FindElement("//Data")
			require.NotNil(t, d)
			assert.Equal(t, "value-"+id, d.Text())
		})
	}
}

// ---------------------------------------------------------------------------
// Test: uriRegexp is Defined but Unused – Verify Behavior
// ---------------------------------------------------------------------------

func TestCrossRef_UnusedURIRegexp(t *testing.T) {
	// The library defines uriRegexp = regexp.MustCompile("^#[a-zA-Z_][\\w.-]*$")
	// but never uses it in the verification path. This test documents that
	// URIs not matching this regex are still processed (for better or worse).
	//
	// Specifically, IDs starting with a digit (invalid per XML spec but the
	// library doesn't enforce the regex) can still be referenced.
	key, cert := randomTestKeyAndCert()

	// ID starting with a digit – invalid per XML Name rules, but the library
	// doesn't validate this.
	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "123abc")
	el.CreateElement("Data").SetText("digit-id")
	signed := signAndReparse(t, key, cert, el)

	// The signer will create URI="#123abc" and signing will work.
	// The verifier does literal comparison, so it should also work.
	result, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err, "digit-starting ID should verify (uriRegexp is unused)")
	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	assert.Equal(t, "digit-id", d.Text())
}

// ---------------------------------------------------------------------------
// Test: Multiple Signatures Referencing Same Element
// ---------------------------------------------------------------------------

func TestCrossRef_MultipleSignaturesRejected(t *testing.T) {
	// Attack scenario: An attacker injects a second Signature element that
	// also references the same element ID. The library should reject documents
	// with multiple signatures referencing the same element.
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_multi")

	// Clone the existing signature and append it as another direct child.
	sig := findSig(signed)
	require.NotNil(t, sig)
	clone := sig.Copy()
	signed.AddChild(clone)

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMalformedSignature),
		"multiple signatures for same element should be rejected; got: %v", err)
}

// ---------------------------------------------------------------------------
// Test: Signature with Reference URI Not Starting with #
// ---------------------------------------------------------------------------

func TestCrossRef_RelativeURI(t *testing.T) {
	// Attack scenario: URI="doc.xml#_id" – a relative URI with a fragment.
	// The library should not follow relative URIs.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_id")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "doc.xml#_id"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid),
		"relative URI must not match; got: %v", err)
}

// ---------------------------------------------------------------------------
// Test: URI Tampering Changes SignedInfo Digest
// ---------------------------------------------------------------------------

func TestCrossRef_URITamperingInvalidatesSignature(t *testing.T) {
	// Security property: Any change to the Reference URI inside SignedInfo
	// must invalidate the cryptographic signature over SignedInfo, because
	// the signature covers the canonical form of SignedInfo.
	//
	// This is the fundamental protection against post-signing URI manipulation.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_orig")
	el.CreateElement("Data").SetText("payload")

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	rawSigned, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Now craft a second element with a different ID.
	el2 := &etree.Element{Tag: "Response"}
	el2.CreateAttr("ID", "_evil")
	el2.CreateElement("Data").SetText("evil-payload")

	// Take the signature from the first document and try to apply it to the
	// second element by changing the URI.
	sig := findSig(rawSigned)
	require.NotNil(t, sig)

	ref := sig.FindElement("./" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	origURI := ref.SelectAttrValue(URIAttr, "")
	assert.Equal(t, "#_orig", origURI)

	// Change URI to point to the evil element.
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#_evil"
			break
		}
	}

	// Attach the tampered signature to el2.
	result := el2.Copy()
	result.AddChild(sig)
	reparsed := reparse(t, result)

	_, err = newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrSignatureInvalid) || errors.Is(err, ErrDigestMismatch),
		"signature must be invalid after URI tampering; got: %v", err)
}

// ---------------------------------------------------------------------------
// Test: DigestValue Swap Attack with Different URI
// ---------------------------------------------------------------------------

func TestCrossRef_DigestSwapWithDifferentURI(t *testing.T) {
	// Attack scenario: Sign two different documents, then swap the DigestValue
	// from one into the other's SignedInfo. This changes SignedInfo, which
	// should invalidate the cryptographic signature.
	key, cert := randomTestKeyAndCert()

	// Sign document A.
	elA := &etree.Element{Tag: "Response"}
	elA.CreateAttr("ID", "_docA")
	elA.CreateElement("Data").SetText("A-content")
	signedA := signAndReparse(t, key, cert, elA)

	// Sign document B.
	elB := &etree.Element{Tag: "Response"}
	elB.CreateAttr("ID", "_docB")
	elB.CreateElement("Data").SetText("B-content")
	signedB := signAndReparse(t, key, cert, elB)

	// Extract digest from B.
	dvB := signedB.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag + "/" + DigestValueTag)
	require.NotNil(t, dvB)
	digestB := dvB.Text()

	// Swap B's digest into A's SignedInfo.
	dvA := signedA.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag + "/" + DigestValueTag)
	require.NotNil(t, dvA)
	dvA.SetText(digestB)

	_, err := newVerifier(cert).Verify(signedA)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignatureInvalid),
		"swapping DigestValue must invalidate signature; got: %v", err)
}

// ---------------------------------------------------------------------------
// Test: SignatureValue Transplant Between Documents
// ---------------------------------------------------------------------------

func TestCrossRef_SignatureTransplantBetweenDocuments(t *testing.T) {
	// Attack scenario: Take the entire Signature from a legitimately signed
	// document and transplant it to a different document with a different ID.
	// The Reference URI won't match, or the digest will differ.
	key, cert := randomTestKeyAndCert()

	// Sign legitimate document.
	elGood := &etree.Element{Tag: "Response"}
	elGood.CreateAttr("ID", "_good")
	elGood.CreateElement("Data").SetText("legitimate")
	signedGood := signAndReparse(t, key, cert, elGood)

	// Extract the signature.
	sig := findSig(signedGood)
	require.NotNil(t, sig)

	// Create evil document and attach the stolen signature.
	elEvil := &etree.Element{Tag: "Response"}
	elEvil.CreateAttr("ID", "_evil")
	elEvil.CreateElement("Data").SetText("malicious")
	elEvil.AddChild(sig.Copy())

	reparsed := reparse(t, elEvil)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	// The Reference URI is "#_good" but the element has ID="_evil" → no match.
	assert.True(t,
		errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid),
		"transplanted signature must not verify; got: %v", err)
}

func TestCrossRef_SignatureTransplantSameID(t *testing.T) {
	// Attack scenario: Transplant signature to a different document that
	// happens to have the same ID but different content. The URI matches,
	// but the digest should not.
	key, cert := randomTestKeyAndCert()

	elGood := &etree.Element{Tag: "Response"}
	elGood.CreateAttr("ID", "_shared")
	elGood.CreateElement("Data").SetText("legitimate")
	signedGood := signAndReparse(t, key, cert, elGood)

	sig := findSig(signedGood)
	require.NotNil(t, sig)

	// Evil document with same ID but different content.
	elEvil := &etree.Element{Tag: "Response"}
	elEvil.CreateAttr("ID", "_shared")
	elEvil.CreateElement("Data").SetText("evil-content")
	elEvil.AddChild(sig.Copy())

	reparsed := reparse(t, elEvil)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDigestMismatch),
		"different content with same ID must fail digest check; got: %v", err)
}

// ---------------------------------------------------------------------------
// Test: Unicode Normalization in URI
// ---------------------------------------------------------------------------

func TestCrossRef_UnicodeNormalization(t *testing.T) {
	// Attack scenario: Using different Unicode representations of the same
	// character. For example, é can be U+00E9 (precomposed) or U+0065 U+0301
	// (decomposed). If the library normalizes Unicode, these would match.
	//
	// Expected behavior: Go strings are byte sequences; no Unicode normalization
	// is performed. Different byte sequences should not match.
	key, cert := randomTestKeyAndCert()

	// Use precomposed é (U+00E9) in the ID.
	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_caf\u00e9")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	// Tamper: change Reference URI to use decomposed é (e + combining accent).
	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#_cafe\u0301" // decomposed form
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err,
		"different Unicode normalization forms must not match")
}

// ---------------------------------------------------------------------------
// Test: ID Attribute Value Containing '#'
// ---------------------------------------------------------------------------

func TestCrossRef_IDContainingHash(t *testing.T) {
	// Edge case: What if the ID attribute itself contains a '#' character?
	// The signer would create URI="##weird" and the verifier strips the first
	// '#' to compare "#weird" with "#weird" – this should actually work.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "#weird")
	el.CreateElement("Data").SetText("payload")

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	rawSigned, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Verify the Reference URI is "##weird".
	ref := rawSigned.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	assert.Equal(t, "##weird", ref.SelectAttrValue(URIAttr, ""))

	signed := reparse(t, rawSigned)
	result, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// Test: Verifier Returns Reconstructed (Canonical) Element
// ---------------------------------------------------------------------------

func TestCrossRef_VerifyResultIsCanonicalElement(t *testing.T) {
	// Security property: The VerifyResult.Element should be reconstructed from
	// the canonical bytes that were actually digest-verified, not from the
	// original (possibly tampered) input tree.
	//
	// This ensures that consumers of VerifyResult always get the verified content.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_canon")
	el.CreateElement("Data").SetText("verified-content")
	signed := signAndReparse(t, key, cert, el)

	result, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)

	// The returned element should not contain the Signature (it was removed
	// by the enveloped-signature transform).
	sigInResult := result.Element.FindElement("./" + SignatureTag)
	assert.Nil(t, sigInResult, "verified element should not contain the Signature")

	// Content must match.
	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	assert.Equal(t, "verified-content", d.Text())
}

// ---------------------------------------------------------------------------
// Test: Crafted XML with Signature Not in dsig Namespace
// ---------------------------------------------------------------------------

func TestCrossRef_FakeSignatureWrongNamespace(t *testing.T) {
	// Attack scenario: An attacker creates a <Signature> element that is NOT
	// in the XML-DSig namespace but has the same tag name. The verifier must
	// only accept Signature elements in the correct namespace.
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_ns")

	// Remove the real signature.
	realSig := findSig(signed)
	require.NotNil(t, realSig)
	signed.RemoveChild(realSig)

	// Add a fake Signature in a different namespace.
	fakeSig := realSig.Copy()
	fakeSig.Space = "evil"
	fakeSig.CreateAttr("xmlns:evil", "http://evil.com/fake-dsig")
	signed.AddChild(fakeSig)

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingSignature),
		"fake namespace Signature must not be accepted; got: %v", err)
}

// ---------------------------------------------------------------------------
// Test: Empty ID Attribute
// ---------------------------------------------------------------------------

func TestCrossRef_EmptyIDAttribute(t *testing.T) {
	// Edge case: Element has ID="" (empty string). The signer will create
	// URI="" (empty). Verify that this works and is treated consistently.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "") // Explicitly empty ID.
	el.CreateElement("Data").SetText("empty-id")

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	rawSigned, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// The Reference URI should be "" because SelectAttrValue returns "".
	ref := rawSigned.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	assert.Equal(t, "", ref.SelectAttrValue(URIAttr, "MISSING"))

	signed := reparse(t, rawSigned)
	result, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)
	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	assert.Equal(t, "empty-id", d.Text())
}

// ---------------------------------------------------------------------------
// Test: Long URI / ID Values
// ---------------------------------------------------------------------------

func TestCrossRef_LongID(t *testing.T) {
	// Edge case: Very long ID value. Should work if the library does literal
	// string comparison without length limits.
	key, cert := randomTestKeyAndCert()

	longID := "_" + strings.Repeat("a", 10000)
	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", longID)
	el.CreateElement("Data").SetText("long-id")
	signed := signAndReparse(t, key, cert, el)

	result, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)
	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	assert.Equal(t, "long-id", d.Text())
}

// ---------------------------------------------------------------------------
// Test: ID with Special XML Characters
// ---------------------------------------------------------------------------

func TestCrossRef_IDWithSpecialXMLChars(t *testing.T) {
	// Edge case: ID containing characters that need XML escaping in attributes.
	// The etree library handles escaping, but we verify the round-trip.
	key, cert := randomTestKeyAndCert()

	// Ampersand and angle brackets are escaped in XML attributes.
	// However, they're unusual in ID values. Let's verify the library
	// handles the escaping/unescaping consistently.
	specialIDs := []struct {
		name string
		id   string
	}{
		{"ampersand", "_id&amp"},
		{"angle_brackets", "_id<>test"},
		{"quotes", `_id"quoted"`},
	}

	for _, tc := range specialIDs {
		t.Run(tc.name, func(t *testing.T) {
			el := &etree.Element{Tag: "Response"}
			el.CreateAttr("ID", tc.id)
			el.CreateElement("Data").SetText("special")

			signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
			rawSigned, err := signer.SignEnveloped(el)
			require.NoError(t, err)

			signed := reparse(t, rawSigned)
			result, err := newVerifier(cert).Verify(signed)
			require.NoError(t, err)
			assert.NotNil(t, result)
		})
	}
}

// ---------------------------------------------------------------------------
// Test: SignedInfo Integrity Protects All Reference Fields
// ---------------------------------------------------------------------------

func TestCrossRef_SignedInfoCoversDigestMethod(t *testing.T) {
	// Security property: Changing the DigestMethod inside SignedInfo
	// invalidates the signature because SignedInfo is signed.
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_dm")

	dm := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag + "/" + DigestMethodTag)
	require.NotNil(t, dm)

	// Change digest algorithm to SHA-384.
	for i, a := range dm.Attr {
		if a.Key == AlgorithmAttr {
			dm.Attr[i].Value = "http://www.w3.org/2001/04/xmldsig-more#sha384"
			break
		}
	}

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignatureInvalid),
		"changing DigestMethod must invalidate signature; got: %v", err)
}

func TestCrossRef_SignedInfoCoversTransforms(t *testing.T) {
	// Security property: Removing the enveloped-signature transform from
	// SignedInfo invalidates the signature.
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_tr")

	transforms := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag + "/" + TransformsTag)
	require.NotNil(t, transforms)

	// Remove the first Transform (enveloped-signature).
	children := transforms.ChildElements()
	require.GreaterOrEqual(t, len(children), 1)
	transforms.RemoveChild(children[0])

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignatureInvalid),
		"removing Transform must invalidate signature; got: %v", err)
}

// ---------------------------------------------------------------------------
// Test: Attempt to Forge Signature with Known DigestValue
// ---------------------------------------------------------------------------

func TestCrossRef_ForgedSignatureWithCorrectDigest(t *testing.T) {
	// Attack scenario: An attacker knows the correct digest for an element
	// (digests are not secret) and constructs a Signature element with the
	// correct digest but cannot produce a valid signature without the private
	// key. The cryptographic signature must fail.
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_forge")

	// Extract the correct DigestValue.
	dv := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag + "/" + DigestValueTag)
	require.NotNil(t, dv)
	correctDigest := dv.Text()
	require.NotEmpty(t, correctDigest)

	// Tamper: corrupt the SignatureValue but leave DigestValue correct.
	sv := signed.FindElement("./" + SignatureTag + "/" + SignatureValueTag)
	require.NotNil(t, sv)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sv.Text()))
	require.NoError(t, err)
	raw[len(raw)-1] ^= 0xFF // flip last byte
	sv.SetText(base64.StdEncoding.EncodeToString(raw))

	_, err = newVerifier(cert).Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignatureInvalid),
		"forged SignatureValue must not verify; got: %v", err)
}
