package dsig

import (
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	randomKeyStore := RandomKeyStoreForTest()
	ctx := NewDefaultSigningContext(randomKeyStore)
	testSignWithContext(t, ctx, RSASHA256SignatureMethod, crypto.SHA256)
}

func TestNewSigningContext(t *testing.T) {
	randomKeyStore := RandomKeyStoreForTest().(*MemoryX509KeyStore)
	ctx, err := NewSigningContext(randomKeyStore.privateKey, [][]byte{randomKeyStore.cert})
	require.NoError(t, err)
	testSignWithContext(t, ctx, RSASHA256SignatureMethod, crypto.SHA256)
}

func testSignWithContext(t *testing.T, ctx *SigningContext, sigMethodID string, digestAlgo crypto.Hash) {
	authnRequest := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}
	id := "_97e34c50-65ec-4132-8b39-02933960a96a"
	authnRequest.CreateAttr("ID", id)
	hash := digestAlgo.New()
	canonicalized, err := ctx.Canonicalizer.Canonicalize(authnRequest)
	require.NoError(t, err)

	_, err = hash.Write(canonicalized)
	require.NoError(t, err)
	digest := hash.Sum(nil)

	signed, err := ctx.SignEnveloped(authnRequest)
	require.NoError(t, err)
	require.NotEmpty(t, signed)

	sig := signed.FindElement("//" + SignatureTag)
	require.NotEmpty(t, sig)

	signedInfo := sig.FindElement("//" + SignedInfoTag)
	require.NotEmpty(t, signedInfo)

	canonicalizationMethodElement := signedInfo.FindElement("//" + CanonicalizationMethodTag)
	require.NotEmpty(t, canonicalizationMethodElement)

	canonicalizationMethodAttr := canonicalizationMethodElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, canonicalizationMethodAttr)
	require.Equal(t, CanonicalXML11AlgorithmId.String(), canonicalizationMethodAttr.Value)

	signatureMethodElement := signedInfo.FindElement("//" + SignatureMethodTag)
	require.NotEmpty(t, signatureMethodElement)

	signatureMethodAttr := signatureMethodElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, signatureMethodAttr)
	require.Equal(t, sigMethodID, signatureMethodAttr.Value)

	referenceElement := signedInfo.FindElement("//" + ReferenceTag)
	require.NotEmpty(t, referenceElement)

	idAttr := referenceElement.SelectAttr(URIAttr)
	require.NotEmpty(t, idAttr)
	require.Equal(t, "#"+id, idAttr.Value)

	transformsElement := referenceElement.FindElement("//" + TransformsTag)
	require.NotEmpty(t, transformsElement)

	transformElement := transformsElement.FindElement("//" + TransformTag)
	require.NotEmpty(t, transformElement)

	algorithmAttr := transformElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, algorithmAttr)
	require.Equal(t, EnvelopedSignatureAltorithmId.String(), algorithmAttr.Value)

	digestMethodElement := referenceElement.FindElement("//" + DigestMethodTag)
	require.NotEmpty(t, digestMethodElement)

	digestMethodAttr := digestMethodElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, digestMethodElement)
	require.Equal(t, digestAlgorithmIdentifiers[digestAlgo], digestMethodAttr.Value)

	digestValueElement := referenceElement.FindElement("//" + DigestValueTag)
	require.NotEmpty(t, digestValueElement)
	require.Equal(t, base64.StdEncoding.EncodeToString(digest), digestValueElement.Text())
}

func TestSignErrors(t *testing.T) {
	randomKeyStore := RandomKeyStoreForTest()
	ctx := &SigningContext{
		Hash:        crypto.SHA512_256,
		KeyStore:    randomKeyStore,
		IdAttribute: DefaultIdAttr,
		Prefix:      DefaultPrefix,
	}

	authnRequest := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}

	_, err := ctx.SignEnveloped(authnRequest)
	require.Error(t, err)
}

func TestSignNonDefaultID(t *testing.T) {
	// Sign a document by referencing a non-default ID attribute ("OtherID"),
	// and confirm that the signature correctly references it.
	ks := RandomKeyStoreForTest()
	ctx := &SigningContext{
		Hash:          crypto.SHA256,
		KeyStore:      ks,
		IdAttribute:   "OtherID",
		Prefix:        DefaultPrefix,
		Canonicalizer: MakeC14N11Canonicalizer(),
	}

	signable := &etree.Element{
		Space: "foo",
		Tag:   "Bar",
	}

	id := "_97e34c50-65ec-4132-8b39-02933960a96b"

	signable.CreateAttr("OtherID", id)
	signed, err := ctx.SignEnveloped(signable)
	require.NoError(t, err)

	ref := signed.FindElement("./Signature/SignedInfo/Reference")
	require.NotNil(t, ref)
	refURI := ref.SelectAttrValue("URI", "")
	require.Equal(t, refURI, "#"+id)
}

func TestSignManifest(t *testing.T) {
	randomKeyStore := RandomKeyStoreForTest()
	ctx := NewDefaultSigningContext(randomKeyStore)

	test := []byte {0x45, 0xf1, 0xab, 0xd7, 0x8a, 0x6f, 0x92, 0xe6, 0xa4, 0xb6, 0x8e, 0xba, 0x8f, 0xe7, 0x91, 0x96, 0xe0, 0xb2, 0x16, 0xd6, 0x0b, 0x82, 0x1b, 0x00, 0x45, 0xfa, 0xb8, 0xad, 0xd4, 0xfa, 0xff, 0xf9}
	digest := []byte {0x8b, 0xba, 0x7c, 0x7d, 0xbc, 0x28, 0xab, 0x55, 0xd0, 0xf5, 0x52, 0xd3, 0xa4, 0xf1, 0xdd, 0xa6, 0x0e, 0xbf, 0xfc, 0x59, 0x59, 0x2b, 0x5e, 0xfb, 0x22, 0x02, 0xf9, 0x45, 0xfd, 0xcb, 0xdc, 0x11}
	
	sig := ctx.CreateSignature("id1234")
	err := ctx.AddManifestRef(sig, "FirstRef", crypto.SHA256, test)
	require.NoError(t, err)

	man := sig.FindElementPath(ctx.manifestPath(sig))
	require.NotNil(t, man)

	err = ctx.AddManifestRef(sig, "SecondRef", crypto.SHA256, test)
	require.NoError(t, err)

	id := man.SelectAttr(ctx.IdAttribute)
	require.NotEmpty(t, id)

	signed, err := ctx.SignManifest(sig)
	require.NoError(t, err)

	signedInfo := signed.FindElement("//" + SignedInfoTag)
	require.NotEmpty(t, signedInfo)

	referenceElement := signedInfo.FindElement("//" + ReferenceTag)
	require.NotEmpty(t, referenceElement)

	idAttr := referenceElement.SelectAttr(URIAttr)
	require.NotEmpty(t, idAttr)
	require.Equal(t, "#"+id.Value, idAttr.Value)

	typeAttr := referenceElement.SelectAttr(TypeAttr)
	require.NotEmpty(t, typeAttr)
	require.Equal(t, "http://www.w3.org/2000/09/xmldsig#Manifest", typeAttr.Value)

	digestMethodElement := referenceElement.FindElement("//" + DigestMethodTag)
	require.NotEmpty(t, digestMethodElement)

	digestMethodAttr := digestMethodElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, digestMethodElement)
	require.Equal(t, "http://www.w3.org/2001/04/xmlenc#sha256", digestMethodAttr.Value)

	digestValueElement := referenceElement.FindElement("//" + DigestValueTag)
	require.NotEmpty(t, digestValueElement)
	require.Equal(t, base64.StdEncoding.EncodeToString(digest), digestValueElement.Text())
}

func TestIncompatibleSignatureMethods(t *testing.T) {
	// RSA
	randomKeyStore := RandomKeyStoreForTest().(*MemoryX509KeyStore)
	ctx, err := NewSigningContext(randomKeyStore.privateKey, [][]byte{randomKeyStore.cert})
	require.NoError(t, err)

	err = ctx.SetSignatureMethod(ECDSASHA512SignatureMethod)
	require.Error(t, err)

	// ECDSA
	testECDSACert, err := tls.X509KeyPair([]byte(ecdsaCert), []byte(ecdsaKey))
	require.NoError(t, err)

	ctx, err = NewSigningContext(testECDSACert.PrivateKey.(crypto.Signer), testECDSACert.Certificate)
	require.NoError(t, err)

	err = ctx.SetSignatureMethod(RSASHA1SignatureMethod)
	require.Error(t, err)
}

func TestSignWithECDSA(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(ecdsaCert), []byte(ecdsaKey))
	require.NoError(t, err)

	ctx, err := NewSigningContext(cert.PrivateKey.(crypto.Signer), cert.Certificate)
	require.NoError(t, err)

	method := ECDSASHA512SignatureMethod
	err = ctx.SetSignatureMethod(method)
	require.NoError(t, err)

	testSignWithContext(t, ctx, method, crypto.SHA512)
}
