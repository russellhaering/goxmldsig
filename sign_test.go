package dsig

import (
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	randomKeyStore := RandomKeyStoreForTest()
	ctx := NewDefaultSigningContext(randomKeyStore)

	authnRequest := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}
	id := "_97e34c50-65ec-4132-8b39-02933960a96a"
	authnRequest.CreateAttr("ID", id)
	hash := crypto.SHA256.New()
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
	require.Equal(t, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", signatureMethodAttr.Value)

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
	require.Equal(t, "http://www.w3.org/2001/04/xmlenc#sha256", digestMethodAttr.Value)

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

func TestSigningContext_SignEnvelopedReader(t *testing.T) {
	type args struct {
		uri   string
		input []byte
	}
	tests := []struct {
		name     string
		args     args
		wantHash string
		wantErr  bool
	}{
		{"Empty", args{"", []byte("")}, "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", false},
		{"Empty", args{"", []byte("asdasdasdasd")}, "ZrETKgFzkQsB7joV705pWDu/L38eRGLJnvvhuatb+Ag=", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &SigningContext{
				Hash:          crypto.SHA256,
				KeyStore:      RandomKeyStoreForTest(),
				IdAttribute:   "OtherID",
				Prefix:        DefaultPrefix,
				Canonicalizer: MakeC14N11Canonicalizer(),
			}
			got, err := ctx.SignEnvelopedReader(tt.args.uri, tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("SigningContext.SignEnvelopedReader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			gotEle := got.FindElement("//DigestValue")
			if gotEle == nil {
				t.Error(got)
			}
			gotHash := gotEle.Text()
			if !reflect.DeepEqual(gotHash, tt.wantHash) {
				t.Errorf("SigningContext.SignEnvelopedReader() = %v, want %v", gotHash, tt.wantHash)
			}
		})
	}
}

func TestSigningContext_SignXAdES(t *testing.T) {
	type args struct {
		uri   string
		input []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"Empty", args{"./fake", []byte("")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &SigningContext{
				Hash:          crypto.SHA256,
				KeyStore:      RandomKeyStoreForTest(),
				IdAttribute:   "OtherID",
				Prefix:        DefaultPrefix,
				Canonicalizer: MakeC14N11Canonicalizer(),
			}
			_, err := ctx.SignXAdES(tt.args.uri, "mime/fake", tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("SigningContext.SignXAdES() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
