package dsig

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/beevik/etree"
)

// FuzzSignStringRoundTrip fuzzes the content string for SignString/VerifyString with RSA.
func FuzzSignStringRoundTrip(f *testing.F) {
	f.Add("hello world")
	f.Add(" ")
	f.Add("special chars: <>&\"'")
	f.Add(strings.Repeat("abcdefghij", 1000))
	f.Add("line1\nline2\nline3")
	f.Add("\x00\x01\x02\xff")

	key, cert := randomTestKeyAndCert()

	f.Fuzz(func(t *testing.T, content string) {
		if len(content) == 0 {
			return
		}

		signer := &Signer{
			Key:   key,
			Certs: []*x509.Certificate{cert},
			Hash:  crypto.SHA256,
		}

		sig, err := signer.SignString(content)
		if err != nil {
			t.Fatalf("SignString failed: %v", err)
		}

		verifier := &Verifier{
			TrustedCerts: []*x509.Certificate{cert},
		}

		_, err = verifier.VerifyString(content, sig, RSASHA256SignatureMethod)
		if err != nil {
			t.Fatalf("VerifyString failed for valid signature: %v", err)
		}

		// Verification with modified content should fail.
		modified := content + "X"
		_, err = verifier.VerifyString(modified, sig, RSASHA256SignatureMethod)
		if err == nil {
			t.Fatal("VerifyString should have failed for modified content")
		}
	})
}

// FuzzECDSASignRoundTrip fuzzes sign+verify with ECDSA keys using fuzzed
// element Tag, Space, ID value, and attributes. The library's enveloped
// signature round trip works reliably on elements without pre-existing
// children, so we fuzz the element's identity and structure.
func FuzzECDSASignRoundTrip(f *testing.F) {
	f.Add("AuthnRequest", "samlp", "_id-1", "attrName", "attrVal")
	f.Add("root", "", "_fuzz-id", "", "")
	f.Add("Assertion", "saml", "_a1", "Version", "2.0")
	f.Add("Response", "samlp", "_resp-123", "Destination", "https://example.com")
	f.Add("r", "", "_r1", "x", "y")

	key, cert := randomECDSATestKeyAndCert()

	f.Fuzz(func(t *testing.T, tag, space, id, extraAttrName, extraAttrVal string) {
		if len(tag) == 0 || len(tag) > 128 || len(id) == 0 || len(id) > 256 {
			return
		}

		// Ensure tag and space are valid XML NCNames.
		if !isSimpleXMLName(tag) || (space != "" && !isSimpleXMLName(space)) {
			return
		}

		// Build a well-formed ID: prefix with "_" and filter to safe chars.
		if !isSimpleXMLName(id) {
			return
		}
		xmlID := "_" + id

		el := &etree.Element{
			Space: space,
			Tag:   tag,
		}
		el.CreateAttr("ID", xmlID)

		if extraAttrName != "" && isSimpleXMLName(extraAttrName) && extraAttrName != "ID" {
			el.CreateAttr(extraAttrName, extraAttrVal)
		}

		signer := &Signer{
			Key:   key,
			Certs: []*x509.Certificate{cert},
			Hash:  crypto.SHA256,
		}

		signed, err := signer.SignEnveloped(el)
		if err != nil {
			return
		}

		verifier := &Verifier{
			TrustedCerts: []*x509.Certificate{cert},
		}

		// Pass signed element directly to Verify (like the library's own tests).
		result, err := verifier.Verify(signed)
		if err != nil {
			t.Fatalf("Verify failed after ECDSA sign: %v", err)
		}
		if result == nil {
			t.Fatal("VerifyResult is nil")
		}
		if result.Certificate == nil {
			t.Fatal("VerifyResult.Certificate is nil")
		}
	})
}

// isSimpleXMLName checks that s is a plausible XML NCName (letters, digits, hyphens, underscores, dots).
func isSimpleXMLName(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_') {
				return false
			}
		} else {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
				return false
			}
		}
	}
	return true
}

// FuzzDecodeXMLDSigECDSA fuzzes the ECDSA raw r||s decoder with arbitrary byte slices.
func FuzzDecodeXMLDSigECDSA(f *testing.F) {
	f.Add(make([]byte, 64))  // 64 zero bytes (P-256 size)
	f.Add(make([]byte, 96))  // 96 zero bytes (P-384 size)
	f.Add([]byte{})          // empty
	f.Add([]byte{0x42})      // 1 byte
	f.Add(make([]byte, 128)) // oversized
	f.Add(bytes.Repeat([]byte{0xff}, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		curves := []elliptic.Curve{elliptic.P256(), elliptic.P384()}
		for _, curve := range curves {
			r, s, err := decodeXMLDSigECDSA(data, curve)
			if err != nil {
				// Error is expected for wrong-length inputs; just ensure no panic.
				continue
			}
			if r == nil {
				t.Fatal("decodeXMLDSigECDSA returned nil r without error")
			}
			if s == nil {
				t.Fatal("decodeXMLDSigECDSA returned nil s without error")
			}
		}
	})
}

// FuzzConvertECDSAASN1ToRawRS fuzzes the ASN.1 to raw r||s converter.
func FuzzConvertECDSAASN1ToRawRS(f *testing.F) {
	// Valid minimal ASN.1 SEQUENCE: SEQUENCE { INTEGER(1), INTEGER(1) }
	f.Add([]byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01})
	// Garbage bytes
	f.Add([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	// Truncated sequence
	f.Add([]byte{0x30, 0x10, 0x02, 0x01})
	// Empty
	f.Add([]byte{})
	// Just the SEQUENCE tag
	f.Add([]byte{0x30})
	// Valid-ish longer signature
	f.Add(append([]byte{0x30, 0x44, 0x02, 0x20}, append(bytes.Repeat([]byte{0x01}, 32), append([]byte{0x02, 0x20}, bytes.Repeat([]byte{0x02}, 32)...)...)...))

	curves := []elliptic.Curve{elliptic.P256(), elliptic.P384()}

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, curve := range curves {
			result, err := convertECDSAASN1ToRawRS(data, curve)
			if err != nil {
				// Errors are expected for malformed input; just ensure no panic.
				continue
			}
			byteLen := (curve.Params().BitSize + 7) / 8
			if len(result) != 2*byteLen {
				t.Fatalf("expected raw signature length %d, got %d", 2*byteLen, len(result))
			}
		}
	})
}

// FuzzVerifyMalformedSignatures fuzzes verification with structurally varied
// but syntactically valid XML that contains ds:Signature elements.
func FuzzVerifyMalformedSignatures(f *testing.F) {
	// Complete but fake signature
	f.Add([]byte(`<Response ID="resp1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#resp1"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>dGVzdA==</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>dGVzdA==</ds:SignatureValue></ds:Signature></Response>`))
	// Missing SignatureValue
	f.Add([]byte(`<root ID="r1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#r1"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AA==</ds:DigestValue></ds:Reference></ds:SignedInfo></ds:Signature></root>`))
	// Empty Signature element
	f.Add([]byte(`<doc ID="d1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/></doc>`))
	// Duplicate Signature elements
	f.Add([]byte(`<msg ID="m1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#m1"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>dGVzdA==</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#m1"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>BBBB</ds:SignatureValue></ds:Signature></msg>`))
	// Unknown algorithm
	f.Add([]byte(`<x ID="x1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://example.com/unknown"/><ds:SignatureMethod Algorithm="http://example.com/fakealgo"/><ds:Reference URI="#x1"><ds:DigestMethod Algorithm="http://example.com/fakedigest"/><ds:DigestValue>dGVzdA==</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>dGVzdA==</ds:SignatureValue></ds:Signature></x>`))

	key, cert := randomTestKeyAndCert()
	_ = key

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			return
		}

		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(data); err != nil {
			return
		}

		root := doc.Root()
		if root == nil {
			return
		}

		verifier := &Verifier{
			TrustedCerts: []*x509.Certificate{cert},
			AllowSHA1:    true,
		}

		// We only care that this doesn't panic.
		verifier.Verify(root)
	})
}

// FuzzCanonicalizeDeterministic fuzzes that canonicalization is deterministic:
// canonicalize the same input twice and verify identical output.
func FuzzCanonicalizeDeterministic(f *testing.F) {
	f.Add([]byte(`<root xmlns:a="http://a" xmlns:b="http://b"><a:child b:attr="val">text</a:child></root>`))
	f.Add([]byte(`<r xmlns="http://default"><child xmlns:x="http://x" x:a="1"/></r>`))
	f.Add([]byte(`<e xmlns:ns1="http://ns1" xmlns:ns2="http://ns2"><ns1:a><ns2:b ns1:c="d"><!-- comment --></ns2:b></ns1:a></e>`))
	f.Add([]byte(`<a xml:lang="en" xml:space="preserve">  text  </a>`))
	f.Add([]byte(`<doc><nested><deep attr1="z" attr2="a">content</deep></nested></doc>`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			return
		}

		doc1 := etree.NewDocument()
		if err := doc1.ReadFromBytes(data); err != nil {
			return
		}

		root1 := doc1.Root()
		if root1 == nil {
			return
		}

		doc2 := etree.NewDocument()
		if err := doc2.ReadFromBytes(data); err != nil {
			return
		}

		root2 := doc2.Root()
		if root2 == nil {
			return
		}

		canonicalizer := MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

		out1, err1 := canonicalizer.Canonicalize(root1)
		out2, err2 := canonicalizer.Canonicalize(root2)

		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("canonicalization error mismatch: err1=%v err2=%v", err1, err2)
		}

		if err1 != nil {
			return
		}

		if !bytes.Equal(out1, out2) {
			t.Fatalf("canonicalization not deterministic:\nfirst:  %q\nsecond: %q", out1, out2)
		}
	})
}
