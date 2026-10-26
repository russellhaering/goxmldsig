package dsig

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

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

func TestSignWithMGF1(t *testing.T) {
	randomKeyStore := RandomKeyStoreForTest().(*MemoryX509KeyStore)

	// signer based context
	ctx, err := NewSigningContext(randomKeyStore.privateKey, [][]byte{randomKeyStore.cert})
	require.NoError(t, err)
	require.NoError(t, ctx.SetSignatureMethod(SHA256RSAMGF1SignatureMethod))
	require.Equal(t, SHA256RSAMGF1SignatureMethod, ctx.GetSignatureMethodIdentifier())
	testSignWithContext(t, ctx, SHA256RSAMGF1SignatureMethod, crypto.SHA256)

	// key store based context
	ctx = NewDefaultSigningContext(randomKeyStore)
	require.NoError(t, ctx.SetSignatureMethod(SHA256RSAMGF1SignatureMethod))
	require.Equal(t, SHA256RSAMGF1SignatureMethod, ctx.GetSignatureMethodIdentifier())
	testSignWithContext(t, ctx, SHA256RSAMGF1SignatureMethod, crypto.SHA256)
}

func TestSignMGF1RoundTrip(t *testing.T) {
	randomKeyStore := RandomKeyStoreForTest().(*MemoryX509KeyStore)

	signerCtx, err := NewSigningContext(randomKeyStore.privateKey, [][]byte{randomKeyStore.cert})
	require.NoError(t, err)
	keyStoreCtx := NewDefaultSigningContext(randomKeyStore)

	for name, ctx := range map[string]*SigningContext{"signer": signerCtx, "keystore": keyStoreCtx} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, ctx.SetSignatureMethod(SHA256RSAMGF1SignatureMethod))

			signed := signTestRequest(t, ctx)
			algo := signed.FindElement("//" + SignatureMethodTag).SelectAttr(AlgorithmAttr)
			require.Equal(t, SHA256RSAMGF1SignatureMethod, algo.Value)

			// validates through x509.SHA256WithRSAPSS
			validateTestRequest(t, signed, randomKeyStore.cert)

			// the signature value is PSS: a PKCS1v15 label for the same value must not validate
			algo.Value = RSASHA256SignatureMethod
			vc := testValidationContext(t, randomKeyStore.cert)
			_, err := vc.Validate(signed)
			require.Error(t, err)
		})
	}
}

func TestSetSignatureMethodResetsMGF1(t *testing.T) {
	randomKeyStore := RandomKeyStoreForTest().(*MemoryX509KeyStore)
	ctx, err := NewSigningContext(randomKeyStore.privateKey, [][]byte{randomKeyStore.cert})
	require.NoError(t, err)

	require.NoError(t, ctx.SetSignatureMethod(SHA256RSAMGF1SignatureMethod))
	require.NoError(t, ctx.SetSignatureMethod(RSASHA256SignatureMethod))
	require.Equal(t, RSASHA256SignatureMethod, ctx.GetSignatureMethodIdentifier())

	signed := signTestRequest(t, ctx)
	require.Equal(t, RSASHA256SignatureMethod, signed.FindElement("//"+SignatureMethodTag).SelectAttr(AlgorithmAttr).Value)
	validateTestRequest(t, signed, randomKeyStore.cert)

	// a Hash changed behind SetSignatureMethod falls back to PKCS1v15 and its identifier
	require.NoError(t, ctx.SetSignatureMethod(SHA256RSAMGF1SignatureMethod))
	ctx.Hash = crypto.SHA512
	require.Equal(t, RSASHA512SignatureMethod, ctx.GetSignatureMethodIdentifier())
	signed = signTestRequest(t, ctx)
	validateTestRequest(t, signed, randomKeyStore.cert)
}

func TestMGF1IncompatibleWithECDSA(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(ecdsaCert), []byte(ecdsaKey))
	require.NoError(t, err)

	ctx, err := NewSigningContext(cert.PrivateKey.(crypto.Signer), cert.Certificate)
	require.NoError(t, err)

	require.Error(t, ctx.SetSignatureMethod(SHA256RSAMGF1SignatureMethod))
}

func signTestRequest(t *testing.T, ctx *SigningContext) *etree.Element {
	t.Helper()

	authnRequest := &etree.Element{Tag: "AuthnRequest"}
	authnRequest.CreateAttr("ID", "_97e34c50-65ec-4132-8b39-02933960a96a")

	signed, err := ctx.SignEnveloped(authnRequest)
	require.NoError(t, err)

	// reparse, so validation sees the serialized form like a receiver
	doc := etree.NewDocument()
	s, err := etree.NewDocumentWithRoot(signed).WriteToString()
	require.NoError(t, err)
	require.NoError(t, doc.ReadFromString(s))

	return doc.Root()
}

func testValidationContext(t *testing.T, certDER []byte) *ValidationContext {
	t.Helper()

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	vc := NewDefaultValidationContext(&MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	vc.Clock = NewFakeClockAt(cert.NotBefore.Add(time.Minute))

	return vc
}

func validateTestRequest(t *testing.T, el *etree.Element, certDER []byte) {
	t.Helper()

	validated, err := testValidationContext(t, certDER).Validate(el)
	require.NoError(t, err)
	require.NotEmpty(t, validated)
}
