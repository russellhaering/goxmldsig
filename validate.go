package dsig

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig/etreeutils"
	"github.com/russellhaering/goxmldsig/types"
)

var uriRegexp = regexp.MustCompile("^[/#][a-zA-Z_][\\w.-]*$")
var whiteSpace = regexp.MustCompile("\\s+")

var (
	// ErrMissingSignature indicates that no enveloped signature was found referencing
	// the top level element passed for signature verification.
	ErrMissingSignature = errors.New("missing signature referencing the top-level element")

	ErrUnsupportedMethod = errors.New("dsig: unsupported algorithm")
	ErrInvalidSignature  = errors.New("dsig: invalid signature")
	ErrBadCertificate    = errors.New("dsig: bad certificate")
	ErrInvalidDigest     = errors.New("dsig: digest was broken")
)

func wrapError(err error) error {

	if errors.Is(err, ErrMissingSignature) ||
		errors.Is(err, ErrUnsupportedMethod) ||
		errors.Is(err, ErrInvalidSignature) ||
		errors.Is(err, ErrBadCertificate) ||
		errors.Is(err, ErrInvalidDigest) {
		return err
	}
	// by default wrap all unknow errors as invalid signature
	return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
}

type ValidationContext struct {
	CertificateStore X509CertificateStore
	IdAttribute      string
	Clock            *Clock
}

func NewDefaultValidationContext(certificateStore X509CertificateStore) *ValidationContext {
	return &ValidationContext{
		CertificateStore: certificateStore,
		IdAttribute:      DefaultIdAttr,
	}
}

// TODO(russell_h): More flexible namespace support. This might barely work.
func inNamespace(el *etree.Element, ns string) bool {
	for _, attr := range el.Attr {
		if attr.Value == ns {
			if attr.Space == "" && attr.Key == "xmlns" {
				return el.Space == ""
			} else if attr.Space == "xmlns" {
				return el.Space == attr.Key
			}
		}
	}

	return false
}

func childPath(space, tag string) string {
	if space == "" {
		return "./" + tag
	} else {
		return "./" + space + ":" + tag
	}
}

// Transform returns a new element equivalent to the passed root el, but with
// the set of transformations described by the ref applied.
//
// The functionality of transform is currently very limited and purpose-specific.
func (ctx *ValidationContext) transform(
	el *etree.Element,
	sig *types.Signature,
	ref *types.Reference) (*etree.Element, Canonicalizer, error) {

	if ref == nil {
		return nil, nil, ErrMissingSignature
	}
	transforms := ref.Transforms.Transforms

	var canonicalizer Canonicalizer

	for _, transform := range transforms {
		algo := transform.Algorithm

		switch AlgorithmID(algo) {
		case EnvelopedSignatureAltorithmId:
			el = el.Copy() // make a copy of the passed root
			if !sig.RemoveUnderlyingElement(el) {
				return nil, nil, fmt.Errorf("%w: error applying canonicalization transform: Signature not found", ErrInvalidSignature)
			}

		case CanonicalXML10ExclusiveAlgorithmId:
			var prefixList string
			if transform.InclusiveNamespaces != nil {
				prefixList = transform.InclusiveNamespaces.PrefixList
			}

			canonicalizer = MakeC14N10ExclusiveCanonicalizerWithPrefixList(prefixList)

		case CanonicalXML10ExclusiveWithCommentsAlgorithmId:
			var prefixList string
			if transform.InclusiveNamespaces != nil {
				prefixList = transform.InclusiveNamespaces.PrefixList
			}

			canonicalizer = MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(prefixList)

		case CanonicalXML11AlgorithmId:
			canonicalizer = MakeC14N11Canonicalizer()

		case CanonicalXML11WithCommentsAlgorithmId:
			canonicalizer = MakeC14N11WithCommentsCanonicalizer()

		case CanonicalXML10RecAlgorithmId:
			canonicalizer = MakeC14N10RecCanonicalizer()

		case CanonicalXML10WithCommentsAlgorithmId:
			canonicalizer = MakeC14N10WithCommentsCanonicalizer()

		default:
			return nil, nil, fmt.Errorf("%w: transform: %s", ErrUnsupportedMethod, algo)
		}
	}

	if canonicalizer == nil {
		canonicalizer = MakeNullCanonicalizer()
	}

	return el, canonicalizer, nil
}

func (ctx *ValidationContext) digest(el *etree.Element, digestAlgorithmId string, canonicalizer Canonicalizer) ([]byte, error) {
	data, err := canonicalizer.Canonicalize(el)
	if err != nil {
		return nil, err
	}

	digestAlgorithm, ok := digestAlgorithmsByIdentifier[digestAlgorithmId]
	if !ok {
		return nil, fmt.Errorf("%w: digest: %s", ErrUnsupportedMethod, digestAlgorithmId)
	}

	hash := digestAlgorithm.New()
	_, err = hash.Write(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedMethod, err)
	}

	return hash.Sum(nil), nil
}

func (ctx *ValidationContext) verifySignedInfo(sig *types.Signature, cert *x509.Certificate) error {

	if sig.SignatureValue == nil {
		return errors.New("missing SignatureValue")
	}

	// Decode the 'SignatureValue' so we can compare against it
	decodedSignature, err := base64.StdEncoding.DecodeString(sig.SignatureValue.Data)
	if err != nil {
		return fmt.Errorf("could not decode signature: %w", ErrInvalidDigest)
	}

	signatureElement := sig.UnderlyingElement()

	nsCtx, err := etreeutils.NSBuildParentContext(signatureElement)
	if err != nil {
		return err
	}

	signedInfo, err := etreeutils.NSFindOneChildCtx(nsCtx, signatureElement, Namespace, SignedInfoTag)
	if err != nil {
		return err
	}

	if signedInfo == nil {
		return errors.New("missing SignedInfo")
	}

	// Canonicalize the xml
	canonical, err := canonicalSerialize(signedInfo)
	if err != nil {
		return err
	}

	signatureMethodId := sig.SignedInfo.SignatureMethod.Algorithm
	algo, ok := x509SignatureAlgorithmByIdentifier[signatureMethodId]
	if !ok {
		return fmt.Errorf("%w: signature method: %s", ErrUnsupportedMethod, signatureMethodId)
	}

	err = cert.CheckSignature(algo, canonical, decodedSignature)
	if err != nil {
		return fmt.Errorf("%w [%v]", ErrInvalidDigest, err)
	}

	return nil
}

func (ctx *ValidationContext) validateSignature(el *etree.Element, sig *types.Signature, cert *x509.Certificate) (*etree.Element, error) {

	// Perform all transformations listed in the 'SignedInfo'
	// Basically, this means removing the 'SignedInfo'
	transformed, canonicalizer, err := ctx.transform(el, sig, sig.RootRef)
	if err != nil {
		return nil, err
	}

	data, err := canonicalizer.Canonicalize(transformed)
	if err != nil {
		return nil, err
	}

	// Digest the transformed XML and compare it to the 'DigestValue' from the 'SignedInfo'
	err = ctx.VerifyReference(sig.RootRef, data)
	if err != nil {
		return nil, err
	}

	// Actually verify the 'SignedInfo' was signed by a trusted source
	err = ctx.verifySignedInfo(sig, cert)
	if err != nil {
		return nil, err
	}

	return transformed, nil
}

func contains(roots []*x509.Certificate, cert *x509.Certificate) bool {
	for _, root := range roots {
		if root.Equal(cert) {
			return true
		}
	}
	return false
}

// In most places, we use etree Elements, but while deserializing the Signature, we use
// encoding/xml unmarshal directly to convert to a convenient go struct. This presents a problem in some cases because
// when an xml element repeats under the parent, the last element will win and/or be appended. We need to assert that
// the Signature object matches the expected shape of a Signature object.
func validateShape(signatureEl *etree.Element) error {
	children := signatureEl.ChildElements()

	childCounts := map[string]int{}
	for _, child := range children {
		childCounts[child.Tag]++
	}

	validateCount := childCounts[SignedInfoTag] == 1 && childCounts[KeyInfoTag] <= 1 && childCounts[SignatureValueTag] == 1
	if !validateCount {
		return ErrInvalidSignature
	}
	return nil
}

// findSignature searches for a Signature element referencing the passed root element.
// otherwise, it returns the first found Signature in the tree, RootRef will be nil in this case
func (ctx *ValidationContext) findSignature(root *etree.Element) (*types.Signature, error) {
	idAttrEl := root.SelectAttr(ctx.IdAttribute)
	idAttr := ""
	if idAttrEl != nil {
		idAttr = idAttrEl.Value
	}

	var sig *types.Signature

	// Traverse the tree looking for a Signature element
	err := etreeutils.NSFindIterate(root, Namespace, SignatureTag, func(ctx etreeutils.NSContext, signatureEl *etree.Element) error {
		err := validateShape(signatureEl)
		if err != nil {
			return err
		}
		found := false
		err = etreeutils.NSFindChildrenIterateCtx(ctx, signatureEl, Namespace, SignedInfoTag,
			func(ctx etreeutils.NSContext, signedInfo *etree.Element) error {
				detachedSignedInfo, err := etreeutils.NSDetatch(ctx, signedInfo)
				if err != nil {
					return err
				}

				c14NMethod, err := etreeutils.NSFindOneChildCtx(ctx, detachedSignedInfo, Namespace, CanonicalizationMethodTag)
				if err != nil {
					return err
				}

				if c14NMethod == nil {
					return errors.New("missing CanonicalizationMethod")
				}

				c14NAlgorithm := c14NMethod.SelectAttrValue(AlgorithmAttr, "")

				var canonicalSignedInfo *etree.Element

				switch alg := AlgorithmID(c14NAlgorithm); alg {
				case CanonicalXML10ExclusiveAlgorithmId, CanonicalXML10ExclusiveWithCommentsAlgorithmId:
					err := etreeutils.TransformExcC14n(detachedSignedInfo, "", alg == CanonicalXML10ExclusiveWithCommentsAlgorithmId)
					if err != nil {
						return err
					}

					// NOTE: TransformExcC14n transforms the element in-place,
					// while canonicalPrep isn't meant to. Once we standardize
					// this behavior we can drop this, as well as the adding and
					// removing of elements below.
					canonicalSignedInfo = detachedSignedInfo

				case CanonicalXML11AlgorithmId, CanonicalXML10RecAlgorithmId:
					canonicalSignedInfo = canonicalPrep(detachedSignedInfo, map[string]struct{}{}, true, false)

				case CanonicalXML11WithCommentsAlgorithmId, CanonicalXML10WithCommentsAlgorithmId:
					canonicalSignedInfo = canonicalPrep(detachedSignedInfo, map[string]struct{}{}, true, true)

				default:
					return fmt.Errorf("%w: canonicalization: %s", ErrUnsupportedMethod, c14NAlgorithm)
				}

				signatureEl.RemoveChild(signedInfo)
				signatureEl.AddChild(canonicalSignedInfo)

				found = true

				return etreeutils.ErrTraversalHalted
			})
		if err != nil {
			return err
		}

		if !found {
			return errors.New("missing SignedInfo")
		}

		// Unmarshal the signature into a structured Signature type
		_sig := &types.Signature{}
		err = etreeutils.NSUnmarshalElement(ctx, root, signatureEl, _sig)
		if err != nil {
			return err
		}

		// Traverse references in the signature to determine whether it has at least
		// one reference to the top level element. If so, conclude the search.
		for idx := range _sig.SignedInfo.References {
			ref := &_sig.SignedInfo.References[idx]
			if ref.URI == "" || uriRegexp.MatchString(ref.URI) {
				if ref.URI == "" || ref.URI[1:] == idAttr {
					sig = _sig
					sig.RootRef = ref
					return etreeutils.ErrTraversalHalted
				}
			} else {
				return fmt.Errorf("%w: reference: %s", ErrUnsupportedMethod, ref.URI)
			}
		}
		sig = _sig
		return nil
	})

	if err != nil {
		return nil, wrapError(err)
	}

	if sig == nil {
		return nil, ErrMissingSignature
	}

	return sig, nil
}

func (ctx *ValidationContext) verifyCertificate(sig *types.Signature) (*x509.Certificate, error) {
	now := ctx.Clock.Now()

	roots, err := ctx.CertificateStore.Certificates()
	if err != nil {
		return nil, err
	}

	var cert *x509.Certificate

	if sig.KeyInfo != nil {
		// If the Signature includes KeyInfo, extract the certificate from there
		if len(sig.KeyInfo.X509Data.X509Certificates) == 0 || sig.KeyInfo.X509Data.X509Certificates[0].Data == "" {
			return nil, fmt.Errorf("%w: missing X509Certificate within KeyInfo", ErrInvalidSignature)
		}

		certData, err := base64.StdEncoding.DecodeString(
			whiteSpace.ReplaceAllString(sig.KeyInfo.X509Data.X509Certificates[0].Data, ""))
		if err != nil {
			return nil, fmt.Errorf("%w: failed to decode certificate: %v", ErrInvalidSignature, err)
		}

		cert, err = x509.ParseCertificate(certData)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse certificate: %v", ErrInvalidSignature, err)
		}
	} else {
		// If the Signature doesn't have KeyInfo, Use the root certificate if there is only one
		if len(roots) == 1 {
			cert = roots[0]
		} else {
			return nil, fmt.Errorf("%w: missing x509 Element", ErrInvalidSignature)
		}
	}

	// Verify that the certificate is one we trust
	if !contains(roots, cert) {
		return nil, fmt.Errorf("%w: could not verify against trusted certs", ErrBadCertificate)
	}

	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fmt.Errorf("%w: cert is not valid at this time", ErrBadCertificate)
	}

	return cert, nil
}

func (ctx *ValidationContext) validateEx(root *etree.Element, sig *types.Signature, cert *x509.Certificate) (*types.Manifest, error) {

	var manifest *types.Manifest

	// First get the context surrounding the element we are verifying.
	rootNSCtx, err := etreeutils.NSBuildParentContext(root)
	if err != nil {
		return nil, err
	}

	// then capture any declarations on the Signature itself.
	sigNSCtx, err := rootNSCtx.SubContext(sig.UnderlyingElement())
	if err != nil {
		return nil, err
	}

	// pass through all references of Signature
	for idx := range sig.SignedInfo.References {

		var el *etree.Element
		ref := &sig.SignedInfo.References[idx]

		if !uriRegexp.MatchString(ref.URI) {
			return nil, fmt.Errorf("%w: reference: %s", ErrUnsupportedMethod, ref.URI)
		}
		// looking for referenced element
		pstr := ref.URI
		if pstr[0] == '#' {
			pstr = fmt.Sprintf("//[@%s='%s']", ctx.IdAttribute, ref.URI[1:])
		}
		if path, err := etree.CompilePath(pstr); err == nil {
			el = root.FindElementPath(path)
		}
		if el == nil {
			return nil, fmt.Errorf("could not find reference: %s", ref.URI)
		}

		// detach this element from the root tree and make transformations
		detached, err := etreeutils.NSDetatch(sigNSCtx, el)
		if err != nil {
			return nil, err
		}

		// TODO: support more that one transformation
		detached, canonicalizer, err := ctx.transform(detached, sig, ref)
		if err != nil {
			return nil, err
		}
		transformed, err := canonicalizer.Canonicalize(detached)
		if err != nil {
			return nil, err
		}

		// caclculate and compare digest of referenced element
		err = ctx.VerifyReference(ref, transformed)
		if err != nil {
			return nil, err
		}

		// Process manifest reference - unmarshal it into a structured Manifest type
		if ref.Type == ManifestRefType {
			if manifest != nil {
				return nil, errors.New("more that one manifest reference")
			}
			manifest = &types.Manifest{}
			err = xml.Unmarshal(transformed, manifest)
			if err != nil {
				return nil, err
			}
		}
	}

	// Actually verify the 'SignedInfo' was signed by a trusted source
	err = ctx.verifySignedInfo(sig, cert)
	if err != nil {
		return nil, err
	}

	return manifest, nil
}

// Validate verifies that the passed element contains a valid enveloped signature
// matching a currently-valid certificate in the context's CertificateStore.
func (ctx *ValidationContext) Validate(el *etree.Element) (*etree.Element, error) {
	// Make a copy of the element to avoid mutating the one we were passed.
	el = el.Copy()

	sig, err := ctx.findSignature(el)
	if err != nil {
		return nil, err
	}

	cert, err := ctx.verifyCertificate(sig)
	if err != nil {
		return nil, err
	}

	return ctx.validateSignature(el, sig, cert)
}

// Validate verifies that the passed element contains a valid signatures
// matching a currently-valid certificate in the context's CertificateStore.
func (ctx *ValidationContext) ValidateManifest(el *etree.Element) (*types.Manifest, error) {

	for {
		// Make a copy of the element to avoid mutating the one we were passed.
		sig, err := ctx.findSignature(el.Copy())
		if err != nil {
			return nil, err
		}

		cert, err := ctx.verifyCertificate(sig)
		if err != nil {
			return nil, err
		}

		if sig.RootRef == nil {
			manifest, err := ctx.validateEx(el, sig, cert)
			if err != nil {
				return nil, wrapError(err)
			}
			return manifest, nil
		}
		el, err = ctx.validateSignature(el, sig, cert)
		if err != nil {
			return nil, wrapError(err)
		}
	}
}

// Caclculate and compare digest of referenced element
func (ctx *ValidationContext) VerifyReference(ref *types.Reference, data []byte) error {

	digestAlgorithm, ok := digestAlgorithmsByIdentifier[ref.DigestAlgo.Algorithm]
	if !ok {
		return fmt.Errorf("%w: digest: %s", ErrUnsupportedMethod, ref.DigestAlgo.Algorithm)
	}

	decodedDigestValue, err := base64.StdEncoding.DecodeString(ref.DigestValue)
	if err != nil {
		return fmt.Errorf("could not decode reference: %w", ErrInvalidDigest)
	}

	hash := digestAlgorithm.New()
	_, err = hash.Write(data)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsupportedMethod, err)
	}

	if bytes.Equal(decodedDigestValue, hash.Sum(nil)) {
		return nil
	}
	return fmt.Errorf("reference could not be verified: %w", ErrInvalidDigest)
}

func (ctx *ValidationContext) DecodeRef(ref *types.Reference) (crypto.Hash, []byte, error) {

	hash_id, ok := digestAlgorithmsByIdentifier[ref.DigestAlgo.Algorithm]
	if !ok {
		return 0, nil, fmt.Errorf("%w: digest: %s", ErrUnsupportedMethod, ref.DigestAlgo.Algorithm)
	}
	digest, err := base64.StdEncoding.DecodeString(ref.DigestValue)
	if err != nil {
		return 0, nil, fmt.Errorf("could not decode reference: %w", ErrInvalidDigest)
	}
	return hash_id, digest, nil
}
