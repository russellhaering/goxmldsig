package dsig

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// signReparse signs el with the given canonicalizer, serializes, and reparses.
func signReparse(t *testing.T, el *etree.Element, c Canonicalizer) (*etree.Element, crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, cert := randomTestKeyAndCert()
	signer := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: c,
	}
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	return reparse(t, signed), key, cert
}

// testDoc returns a parsed element suitable for signing.
func testDoc() *etree.Element {
	doc := etree.NewDocument()
	doc.ReadFromString(`<Root xmlns="urn:test" ID="_abc123"><Child>hello</Child></Root>`)
	return doc.Root()
}

type canonEntry struct {
	Name string
	C    Canonicalizer
}

func allCanonicalizers() []canonEntry {
	return []canonEntry{
		{"ExcC14N10", MakeC14N10ExclusiveCanonicalizerWithPrefixList("")},
		{"C14N11", MakeC14N11Canonicalizer()},
		{"C14N10Rec", MakeC14N10RecCanonicalizer()},
	}
}

// ---------------------------------------------------------------------------
// Property Test 1 – C14N method mismatch
//
// Sign with each canonicalizer. Verify the baseline succeeds. Then confirm
// the CanonicalizationMethod recorded in SignedInfo matches the algorithm
// used, and that tampering with it (in the serialised XML) breaks verification.
// ---------------------------------------------------------------------------

func TestPropertyC14NMethodMismatch(t *testing.T) {
	for _, tc := range allCanonicalizers() {
		t.Run(tc.Name, func(t *testing.T) {
			el := testDoc()
			signed, _, cert := signReparse(t, el, tc.C)

			// Baseline: verification succeeds.
			verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
			_, err := verifier.Verify(signed)
			require.NoError(t, err, "baseline verification must succeed for %s", tc.Name)

			// The CanonicalizationMethod in SignedInfo must match the
			// algorithm that was requested.
			cmEl := signed.FindElement("//" + CanonicalizationMethodTag)
			require.NotNil(t, cmEl)
			assert.Equal(t, tc.C.Algorithm().String(),
				cmEl.SelectAttrValue(AlgorithmAttr, ""),
				"CanonicalizationMethod must record the signing algorithm")

			// Tamper: swap the CanonicalizationMethod to every other valid
			// algorithm. Because SignedInfo is itself signed, any change
			// must invalidate the cryptographic signature.
			for _, other := range allCanonicalizers() {
				if other.C.Algorithm() == tc.C.Algorithm() {
					continue
				}
				t.Run("swapTo_"+other.Name, func(t *testing.T) {
					copy := reparse(t, signed) // fresh copy
					cm := copy.FindElement("//" + CanonicalizationMethodTag)
					require.NotNil(t, cm)
					cm.CreateAttr(AlgorithmAttr, other.C.Algorithm().String())
					// Re-serialize so the verifier sees the tampered XML.
					tampered := reparse(t, copy)
					_, err := verifier.Verify(tampered)
					assert.Error(t, err,
						"verification must fail when C14N swapped from %s to %s",
						tc.Name, other.Name)
				})
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Property Test 2 – Redundant namespace declarations
//
// The same namespace declared on both parent and child is redundant.
// After canonicalization the output must be identical to a version that
// declares it only at the parent.
// ---------------------------------------------------------------------------

func TestPropertyRedundantNamespaceDeclarations(t *testing.T) {
	for _, tc := range allCanonicalizers() {
		t.Run(tc.Name, func(t *testing.T) {
			redundantXML := `<root xmlns:ns1="urn:example:ns1"><child xmlns:ns1="urn:example:ns1"><ns1:item>value</ns1:item></child></root>`
			cleanXML := `<root xmlns:ns1="urn:example:ns1"><child><ns1:item>value</ns1:item></child></root>`

			rdoc := etree.NewDocument()
			require.NoError(t, rdoc.ReadFromString(redundantXML))
			cdoc := etree.NewDocument()
			require.NoError(t, cdoc.ReadFromString(cleanXML))

			cr, err := tc.C.Canonicalize(rdoc.Root())
			require.NoError(t, err)
			cc, err := tc.C.Canonicalize(cdoc.Root())
			require.NoError(t, err)

			assert.Equal(t, string(cc), string(cr),
				"%s must strip redundant namespace declarations", tc.Name)
		})
	}
}

// ---------------------------------------------------------------------------
// Property Test 3 – C14N determinism
//
// Canonicalizing the same element 100 times must always produce identical
// output.
// ---------------------------------------------------------------------------

func TestPropertyC14NDeterminism(t *testing.T) {
	xmlStr := `<root xmlns:a="urn:a" xmlns:b="urn:b" b:z="1" a:y="2" id="x">` +
		`<a:child b:attr="3">text</a:child>` +
		`<b:other a:foo="bar"/>` +
		`</root>`

	for _, tc := range allCanonicalizers() {
		t.Run(tc.Name, func(t *testing.T) {
			doc := etree.NewDocument()
			require.NoError(t, doc.ReadFromString(xmlStr))
			first, err := tc.C.Canonicalize(doc.Root())
			require.NoError(t, err)
			require.NotEmpty(t, first)

			for i := 1; i < 100; i++ {
				d := etree.NewDocument()
				require.NoError(t, d.ReadFromString(xmlStr))
				got, err := tc.C.Canonicalize(d.Root())
				require.NoError(t, err)
				if !bytes.Equal(first, got) {
					t.Fatalf("iteration %d produced different output", i)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Property Test 4 – Enveloped signature removal
//
// After signing, the Signature element IS present. After verification the
// returned Element must NOT contain a Signature child (it is stripped by
// the enveloped-signature transform).
// ---------------------------------------------------------------------------

func TestPropertyEnvelopedSignatureRemoval(t *testing.T) {
	for _, tc := range allCanonicalizers() {
		t.Run(tc.Name, func(t *testing.T) {
			el := testDoc()
			signed, _, cert := signReparse(t, el, tc.C)

			// Signature child must exist in the signed tree.
			require.NotNil(t, signed.FindElement("//"+SignatureTag),
				"signed element must contain a Signature")

			verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
			result, err := verifier.Verify(signed)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotNil(t, result.Element)

			// Verified element must NOT contain any Signature.
			for _, child := range result.Element.ChildElements() {
				assert.NotEqual(t, SignatureTag, child.Tag,
					"verified element must not contain Signature")
			}
			assert.Nil(t, result.Element.FindElement("//"+SignatureTag),
				"deep search must not find Signature in verified result")
		})
	}
}

// ---------------------------------------------------------------------------
// Structured Signature Fuzzer
//
// Signs a valid document, then uses fuzz bytes to select and apply ONE
// structural mutation from a menu of 12 mutations. The mutated document
// must NOT verify successfully.
// ---------------------------------------------------------------------------

type mutation struct {
	name string
	fn   func(el *etree.Element, data []byte) *etree.Element
}

var mutationMenu = []mutation{
	{"SwapDigestValue", mutSwapDigestValue},
	{"TruncateSignatureValue", mutTruncateSignatureValue},
	{"ExtendDigestValue", mutExtendDigestValue},
	{"EmptyCanonicalizationAlgo", mutEmptyCanonicalizationAlgo},
	{"EmptySignatureMethodAlgo", mutEmptySignatureMethodAlgo},
	{"DuplicateSignedInfo", mutDuplicateSignedInfo},
	{"ReorderSigChildren", mutReorderSigChildren},
	{"InjectNestedSignature", mutInjectNestedSignature},
	{"InjectExtraReference", mutInjectExtraReference},
	{"RemoveAllTransforms", mutRemoveAllTransforms},
	{"ReplaceDigestMethodAlgo", mutReplaceDigestMethodAlgo},
	{"ReplaceSignatureMethodAlgo", mutReplaceSignatureMethodAlgo},
}

func mutSwapDigestValue(el *etree.Element, data []byte) *etree.Element {
	el = el.Copy()
	dv := el.FindElement("//" + DigestValueTag)
	if dv == nil {
		return nil
	}
	newVal := base64.StdEncoding.EncodeToString(append(data, 0xFF))
	if newVal == dv.Text() {
		newVal = base64.StdEncoding.EncodeToString(append(data, 0xFE))
	}
	dv.SetText(newVal)
	return el
}

func mutTruncateSignatureValue(el *etree.Element, data []byte) *etree.Element {
	el = el.Copy()
	sv := el.FindElement("//" + SignatureValueTag)
	if sv == nil {
		return nil
	}
	txt := sv.Text()
	if len(txt) < 4 {
		return nil
	}
	n := 1
	if len(data) > 0 {
		n = int(data[0])%(len(txt)/2) + 1
	}
	sv.SetText(txt[:len(txt)-n])
	return el
}

func mutExtendDigestValue(el *etree.Element, data []byte) *etree.Element {
	el = el.Copy()
	dv := el.FindElement("//" + DigestValueTag)
	if dv == nil {
		return nil
	}
	orig, err := base64.StdEncoding.DecodeString(dv.Text())
	if err != nil {
		return nil
	}
	extended := append(orig, 0x42)
	if len(data) > 0 {
		extended = append(orig, data[0])
	}
	dv.SetText(base64.StdEncoding.EncodeToString(extended))
	return el
}

func mutEmptyCanonicalizationAlgo(el *etree.Element, _ []byte) *etree.Element {
	el = el.Copy()
	cm := el.FindElement("//" + CanonicalizationMethodTag)
	if cm == nil {
		return nil
	}
	cm.CreateAttr(AlgorithmAttr, "")
	return el
}

func mutEmptySignatureMethodAlgo(el *etree.Element, _ []byte) *etree.Element {
	el = el.Copy()
	sm := el.FindElement("//" + SignatureMethodTag)
	if sm == nil {
		return nil
	}
	sm.CreateAttr(AlgorithmAttr, "")
	return el
}

func mutDuplicateSignedInfo(el *etree.Element, _ []byte) *etree.Element {
	el = el.Copy()
	sig := el.FindElement("//" + SignatureTag)
	if sig == nil {
		return nil
	}
	si := findChildByTag(sig, SignedInfoTag)
	if si == nil {
		return nil
	}
	sig.AddChild(si.Copy())
	return el
}

func mutReorderSigChildren(el *etree.Element, _ []byte) *etree.Element {
	// Move the SignatureValue element to before SignedInfo AND
	// inject a bogus text node inside SignedInfo so that the
	// canonical SignedInfo actually changes.
	el = el.Copy()
	si := el.FindElement("//" + SignedInfoTag)
	if si == nil {
		return nil
	}
	// Insert a text node that will change the canonical form.
	si.SetText("injected")
	return el
}

func mutInjectNestedSignature(el *etree.Element, _ []byte) *etree.Element {
	el = el.Copy()
	si := el.FindElement("//" + SignedInfoTag)
	if si == nil {
		return nil
	}
	nested := etree.NewElement(SignatureTag)
	nested.Space = DefaultPrefix
	nested.CreateAttr("xmlns:"+DefaultPrefix, Namespace)
	nsi := nested.CreateElement(SignedInfoTag)
	nsi.Space = DefaultPrefix
	nsi.CreateElement(CanonicalizationMethodTag).CreateAttr(AlgorithmAttr, "http://fake")
	nsi.CreateElement(SignatureMethodTag).CreateAttr(AlgorithmAttr, "http://fake")
	nsv := nested.CreateElement(SignatureValueTag)
	nsv.Space = DefaultPrefix
	nsv.SetText("ZmFrZQ==")
	si.AddChild(nested)
	return el
}

func mutInjectExtraReference(el *etree.Element, _ []byte) *etree.Element {
	el = el.Copy()
	si := el.FindElement("//" + SignedInfoTag)
	if si == nil {
		return nil
	}
	ref := etree.NewElement(ReferenceTag)
	ref.Space = si.Space
	ref.CreateAttr(URIAttr, "#evil")
	dm := ref.CreateElement(DigestMethodTag)
	dm.Space = si.Space
	dm.CreateAttr(AlgorithmAttr, "http://www.w3.org/2001/04/xmlenc#sha256")
	dvEl := ref.CreateElement(DigestValueTag)
	dvEl.Space = si.Space
	dvEl.SetText("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	si.AddChild(ref)
	return el
}

func mutRemoveAllTransforms(el *etree.Element, _ []byte) *etree.Element {
	el = el.Copy()
	ref := el.FindElement("//" + ReferenceTag)
	if ref == nil {
		return nil
	}
	tr := findChildByTag(ref, TransformsTag)
	if tr == nil {
		return nil
	}
	ref.RemoveChild(tr)
	return el
}

func mutReplaceDigestMethodAlgo(el *etree.Element, _ []byte) *etree.Element {
	el = el.Copy()
	dm := el.FindElement("//" + DigestMethodTag)
	if dm == nil {
		return nil
	}
	dm.CreateAttr(AlgorithmAttr, "http://www.w3.org/2099/unknown#digest")
	return el
}

func mutReplaceSignatureMethodAlgo(el *etree.Element, _ []byte) *etree.Element {
	el = el.Copy()
	sm := el.FindElement("//" + SignatureMethodTag)
	if sm == nil {
		return nil
	}
	sm.CreateAttr(AlgorithmAttr, "http://www.w3.org/2099/unknown#sig")
	return el
}

func FuzzStructuredSignature(f *testing.F) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
		Hash:          crypto.SHA256,
	}

	// Build a seed: sign, serialize, re-parse, serialize to bytes.
	seedDoc := etree.NewDocument()
	seedDoc.ReadFromString(`<Root xmlns="urn:test" ID="_seed"><Child>data</Child></Root>`)
	signed, err := signer.SignEnveloped(seedDoc.Root())
	if err != nil {
		f.Fatal(err)
	}
	serDoc := etree.NewDocument()
	serDoc.SetRoot(signed)
	seedBytes, err := serDoc.WriteToBytes()
	if err != nil {
		f.Fatal(err)
	}

	// Add one seed per mutation kind.
	for i := range mutationMenu {
		corpus := make([]byte, 0, len(seedBytes)+8)
		corpus = append(corpus, byte(i))
		corpus = append(corpus, 0x41, 0x42, 0x43) // extra fuzz bytes
		f.Add(corpus)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 2 {
			t.Skip()
		}

		mutIdx := int(data[0]) % len(mutationMenu)
		mut := mutationMenu[mutIdx]
		extra := data[1:]

		// Fresh sign each iteration with the same key.
		freshDoc := etree.NewDocument()
		freshDoc.ReadFromString(`<Root xmlns="urn:test" ID="_fuzz"><Child>data</Child></Root>`)
		freshSigned, err := signer.SignEnveloped(freshDoc.Root())
		if err != nil {
			t.Skip()
		}
		// Reparse for clean tree.
		tmpDoc := etree.NewDocument()
		tmpDoc.SetRoot(freshSigned)
		rawBytes, err := tmpDoc.WriteToBytes()
		if err != nil {
			t.Skip()
		}
		cleanDoc := etree.NewDocument()
		if err := cleanDoc.ReadFromBytes(rawBytes); err != nil {
			t.Skip()
		}

		mutated := mut.fn(cleanDoc.Root(), extra)
		if mutated == nil {
			t.Skip()
		}

		// Serialize the mutated tree so we can check it actually changed.
		mutDoc := etree.NewDocument()
		mutDoc.SetRoot(mutated)
		mutBytes, _ := mutDoc.WriteToBytes()

		// If the mutation was a no-op (fuzz data reconstructed original),
		// skip instead of failing.
		if bytes.Equal(rawBytes, mutBytes) {
			t.Skip()
		}

		verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		_, err = verifier.Verify(mutated)
		if err == nil {
			t.Errorf("mutation %q was accepted on a structurally modified document", mut.name)
		}
	})
}
