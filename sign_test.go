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

func TestSignSoapRequest(t *testing.T) {
	// Given
	//bs, err := ioutil.ReadFile("./testdata/soaprequest_result.xml")

	ks := RandomKeyStoreForTest()
	ctx := &SigningContext{
		Hash:          crypto.SHA256,
		KeyStore:      ks,
		IdAttribute:   "wsu:Id",
		Prefix:        DefaultPrefix,
		Canonicalizer: MakeC14N11Canonicalizer(),
	}

	doc := etree.NewDocument()
	err := doc.ReadFromFile("./testdata/soaprequest.xml")

	bodyPath, err := etree.CompilePath("./soap:Envelope/soap:Body")
	bodyElement := doc.FindElementPath(bodyPath)
	require.NotNil(t, bodyElement)

	actionPath, err := etree.CompilePath("./soap:Envelope/soap:Header/Action")
	actionElement := doc.FindElementPath(actionPath)
	require.NotNil(t, actionElement)

	securityPath, err := etree.CompilePath("./soap:Envelope/soap:Header/wsse:Security")
	securityElement := doc.FindElementPath(securityPath)
	require.NotNil(t, securityElement)

	// When
	sig, err := ctx.ConstructSignatures([]*etree.Element{bodyElement, actionElement}, true)
	require.NoError(t, err)
	require.NotNil(t, sig)
	securityElement.AddChild(sig)

	// Then
	//	str, err := doc.WriteToString()
	//	require.NoError(t, err)
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
