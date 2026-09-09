package dsig

import (
	"runtime"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

const (
	assertion              = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_88a93ebe-abdf-48cd-9ed0-b0dd1b252909" Version="2.0" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="https://saml2.test.astuart.co/sso/saml2" AssertionConsumerServiceIndex="0" AttributeConsumingServiceIndex="0" IssueInstant="2016-04-28T15:37:17" Destination="http://idp.astuart.co/idp/profile/SAML2/Redirect/SSO"><!-- Some Comment --><saml:Issuer>https://saml2.test.astuart.co/sso/saml2</saml:Issuer><samlp:NameIDPolicy AllowCreate="true" Format=""/><samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>`
	c14n11                 = `<samlp:AuthnRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceIndex="0" AssertionConsumerServiceURL="https://saml2.test.astuart.co/sso/saml2" AttributeConsumingServiceIndex="0" Destination="http://idp.astuart.co/idp/profile/SAML2/Redirect/SSO" ID="_88a93ebe-abdf-48cd-9ed0-b0dd1b252909" IssueInstant="2016-04-28T15:37:17" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer>https://saml2.test.astuart.co/sso/saml2</saml:Issuer><samlp:NameIDPolicy AllowCreate="true" Format=""></samlp:NameIDPolicy><samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>`
	assertionC14ned        = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceIndex="0" AssertionConsumerServiceURL="https://saml2.test.astuart.co/sso/saml2" AttributeConsumingServiceIndex="0" Destination="http://idp.astuart.co/idp/profile/SAML2/Redirect/SSO" ID="_88a93ebe-abdf-48cd-9ed0-b0dd1b252909" IssueInstant="2016-04-28T15:37:17" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://saml2.test.astuart.co/sso/saml2</saml:Issuer><samlp:NameIDPolicy AllowCreate="true" Format=""></samlp:NameIDPolicy><samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>`
	c14n11Comment          = `<samlp:AuthnRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceIndex="0" AssertionConsumerServiceURL="https://saml2.test.astuart.co/sso/saml2" AttributeConsumingServiceIndex="0" Destination="http://idp.astuart.co/idp/profile/SAML2/Redirect/SSO" ID="_88a93ebe-abdf-48cd-9ed0-b0dd1b252909" IssueInstant="2016-04-28T15:37:17" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><!-- Some Comment --><saml:Issuer>https://saml2.test.astuart.co/sso/saml2</saml:Issuer><samlp:NameIDPolicy AllowCreate="true" Format=""></samlp:NameIDPolicy><samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>`
	assertionC14nedComment = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceIndex="0" AssertionConsumerServiceURL="https://saml2.test.astuart.co/sso/saml2" AttributeConsumingServiceIndex="0" Destination="http://idp.astuart.co/idp/profile/SAML2/Redirect/SSO" ID="_88a93ebe-abdf-48cd-9ed0-b0dd1b252909" IssueInstant="2016-04-28T15:37:17" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><!-- Some Comment --><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://saml2.test.astuart.co/sso/saml2</saml:Issuer><samlp:NameIDPolicy AllowCreate="true" Format=""></samlp:NameIDPolicy><samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>`
)

const (
	xmldoc                             = `<Foo ID="id1619705532971228558789260" xmlns:bar="urn:bar" xmlns="urn:foo"><bar:Baz></bar:Baz></Foo>`
	xmldocC14N10ExclusiveCanonicalized = `<Foo xmlns="urn:foo" ID="id1619705532971228558789260"><bar:Baz xmlns:bar="urn:bar"></bar:Baz></Foo>`
	xmldocC14N11Canonicalized          = `<Foo xmlns="urn:foo" xmlns:bar="urn:bar" ID="id1619705532971228558789260"><bar:Baz></bar:Baz></Foo>`
)

func runCanonicalizationTest(t *testing.T, canonicalizer Canonicalizer, xmlstr string, canonicalXmlstr string) {
	raw := etree.NewDocument()
	err := raw.ReadFromString(xmlstr)
	require.NoError(t, err)

	canonicalized, err := canonicalizer.Canonicalize(raw.Root())
	require.NoError(t, err)
	require.Equal(t, canonicalXmlstr, string(canonicalized))
}

func TestExcC14N10(t *testing.T) {
	runCanonicalizationTest(t, MakeC14N10ExclusiveCanonicalizerWithPrefixList(""), assertion, assertionC14ned)
}

func TestExcC14N10WithComments(t *testing.T) {
	runCanonicalizationTest(t, MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(""), assertion, assertionC14nedComment)
}

func TestC14N11(t *testing.T) {
	runCanonicalizationTest(t, MakeC14N11Canonicalizer(), assertion, c14n11)
}

func TestC14N11WithComments(t *testing.T) {
	runCanonicalizationTest(t, MakeC14N11WithCommentsCanonicalizer(), assertion, c14n11Comment)
}

func TestXmldocC14N10Exclusive(t *testing.T) {
	runCanonicalizationTest(t, MakeC14N10ExclusiveCanonicalizerWithPrefixList(""), xmldoc, xmldocC14N10ExclusiveCanonicalized)
}

func TestXmldocC14N11(t *testing.T) {
	runCanonicalizationTest(t, MakeC14N11Canonicalizer(), xmldoc, xmldocC14N11Canonicalized)
}

func TestNestedExcC14N11(t *testing.T) {
	input := `<X xmlns:x="x" xmlns:y="y"><Y xmlns:x="x" xmlns:y="y" xmlns:z="z"/></X>`
	expected := `<X xmlns:x="x" xmlns:y="y"><Y xmlns:z="z"></Y></X>`
	runCanonicalizationTest(t, MakeC14N11Canonicalizer(), input, expected)
}

func TestExcC14nDefaultNamespace(t *testing.T) {
	input := `<foo:Foo xmlns="urn:baz" xmlns:foo="urn:foo"><foo:Bar></foo:Bar></foo:Foo>`
	expected := `<foo:Foo xmlns:foo="urn:foo"><foo:Bar></foo:Bar></foo:Foo>`
	runCanonicalizationTest(t, MakeC14N10ExclusiveCanonicalizerWithPrefixList(""), input, expected)
}

func TestExcC14nWithPrefixList(t *testing.T) {
	input := `<foo:Foo xmlns:foo="urn:foo" xmlns:xs="http://www.w3.org/2001/XMLSchema"><foo:Bar xmlns:xs="http://www.w3.org/2001/XMLSchema"></foo:Bar></foo:Foo>`
	expected := `<foo:Foo xmlns:foo="urn:foo" xmlns:xs="http://www.w3.org/2001/XMLSchema"><foo:Bar></foo:Bar></foo:Foo>`
	canonicalizer := MakeC14N10ExclusiveCanonicalizerWithPrefixList("xs")
	runCanonicalizationTest(t, canonicalizer, input, expected)
}

func TestExcC14nRedeclareDefaultNamespace(t *testing.T) {
	input := `<Foo xmlns="urn:foo"><Bar xmlns="uri:bar"></Bar></Foo>`
	expected := `<Foo xmlns="urn:foo"><Bar xmlns="uri:bar"></Bar></Foo>`
	canonicalizer := MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	runCanonicalizationTest(t, canonicalizer, input, expected)
}

func TestC14N10RecCanonicalizer(t *testing.T) {
	// From https://www.w3.org/TR/2001/REC-xml-c14n-20010315#Example-SETags
	input := `<doc>
   <e1   />
   <e2   ></e2>
   <e3   name = "elem3"   id="elem3"   />
   <e4   name="elem4"   id="elem4"   ></e4>
   <e5 a:attr="out" b:attr="sorted" attr2="all" attr="I'm"
      xmlns:b="http://www.ietf.org"
      xmlns:a="http://www.w3.org"
      xmlns="http://example.org"/>
   <e6 xmlns="" xmlns:a="http://www.w3.org">
      <e7 xmlns="http://www.ietf.org">
         <e8 xmlns="" xmlns:a="http://www.w3.org">
            <e9 xmlns="" xmlns:a="http://www.ietf.org"/>
         </e8>
      </e7>
   </e6>
</doc>`
	expected := `<doc>
   <e1></e1>
   <e2></e2>
   <e3 id="elem3" name="elem3"></e3>
   <e4 id="elem4" name="elem4"></e4>
   <e5 xmlns="http://example.org" xmlns:a="http://www.w3.org" xmlns:b="http://www.ietf.org" attr="I'm" attr2="all" b:attr="sorted" a:attr="out"></e5>
   <e6 xmlns:a="http://www.w3.org">
      <e7 xmlns="http://www.ietf.org">
         <e8 xmlns="">
            <e9 xmlns:a="http://www.ietf.org"></e9>
         </e8>
      </e7>
   </e6>
</doc>`

	canonicalizer := MakeC14N10RecCanonicalizer()
	runCanonicalizationTest(t, canonicalizer, input, expected)
}

func TestC14N10RecCanonicalizerWithNamespaceInheritance(t *testing.T) {
	input := `<RootElement xmlns="http://www.example.com/ns1" xmlns:ns2="http://www.example.com/ns2">
		<ns2:ChildElement>
			<ns2:GrandChildElement>Hello, World!</ns2:GrandChildElement>
		</ns2:ChildElement>
	</RootElement>`

	expected := `<ns2:ChildElement xmlns="http://www.example.com/ns1" xmlns:ns2="http://www.example.com/ns2">
			<ns2:GrandChildElement>Hello, World!</ns2:GrandChildElement>
		</ns2:ChildElement>`

	doc := etree.NewDocument()
	if err := doc.ReadFromString(input); err != nil {
		t.Fatalf("Error parsing input XML: %v", err)
	}

	childElement := doc.FindElement(".//ns2:ChildElement")
	if childElement == nil {
		t.Fatal("Error: childElement not found")
	}

	canonicalizer := MakeC14N10RecCanonicalizer()
	canonicalized, err := canonicalizer.Canonicalize(childElement)
	require.NoError(t, err)
	require.Equal(t, strings.TrimSpace(expected), strings.TrimSpace(string(canonicalized)))

}

// Inputs exercising the namespace bookkeeping that canonicalPrepInner performs:
// prefix redeclaration (to the same and to a different URI), resetting the
// default namespace, attribute ordering next to mixed content and comments, and
// prefixes declared on an ancestor but first used further down.
const (
	nsRedeclaredSameURIInput = `<p:a xmlns:p="urn:x"><p:b xmlns:p="urn:x">t</p:b></p:a>`
	nsRedeclaredNewURIInput  = `<p:a xmlns:p="urn:x"><p:b xmlns:p="urn:y">t</p:b></p:a>`
	defaultNSResetInput      = `<a xmlns="urn:x"><b xmlns="">t</b></a>`
	mixedContentInput        = `<a xmlns="urn:x" z="1" a="2">lead<!-- c --><b xml:lang="en">t</b>tail</a>`
	multiPrefixNestedInput   = `<p:a xmlns:p="urn:x" xmlns:q="urn:y"><q:b><p:c/></q:b></p:a>`
)

// TestInclusiveCanonicalizationGoldens pins the output of the inclusive
// canonicalizers. canonicalPrepInner rewrites a tree in place, so these guard
// against a change in canonical form, which would silently invalidate every
// signature produced or verified against it.
func TestInclusiveCanonicalizationGoldens(t *testing.T) {
	tests := []struct {
		name          string
		canonicalizer Canonicalizer
		input         string
		want          string
	}{
		{"nsRedeclaredSameURI/C14N11", MakeC14N11Canonicalizer(), nsRedeclaredSameURIInput, `<p:a xmlns:p="urn:x"><p:b>t</p:b></p:a>`},
		{"nsRedeclaredSameURI/C14N11WithComments", MakeC14N11WithCommentsCanonicalizer(), nsRedeclaredSameURIInput, `<p:a xmlns:p="urn:x"><p:b>t</p:b></p:a>`},
		{"nsRedeclaredSameURI/C14N10Rec", MakeC14N10RecCanonicalizer(), nsRedeclaredSameURIInput, `<p:a xmlns:p="urn:x"><p:b>t</p:b></p:a>`},
		{"nsRedeclaredSameURI/C14N10WithComments", MakeC14N10WithCommentsCanonicalizer(), nsRedeclaredSameURIInput, `<p:a xmlns:p="urn:x"><p:b>t</p:b></p:a>`},
		{"nsRedeclaredNewURI/C14N11", MakeC14N11Canonicalizer(), nsRedeclaredNewURIInput, `<p:a xmlns:p="urn:x"><p:b xmlns:p="urn:y">t</p:b></p:a>`},
		{"nsRedeclaredNewURI/C14N11WithComments", MakeC14N11WithCommentsCanonicalizer(), nsRedeclaredNewURIInput, `<p:a xmlns:p="urn:x"><p:b xmlns:p="urn:y">t</p:b></p:a>`},
		{"nsRedeclaredNewURI/C14N10Rec", MakeC14N10RecCanonicalizer(), nsRedeclaredNewURIInput, `<p:a xmlns:p="urn:x"><p:b xmlns:p="urn:y">t</p:b></p:a>`},
		{"nsRedeclaredNewURI/C14N10WithComments", MakeC14N10WithCommentsCanonicalizer(), nsRedeclaredNewURIInput, `<p:a xmlns:p="urn:x"><p:b xmlns:p="urn:y">t</p:b></p:a>`},
		{"defaultNSReset/C14N11", MakeC14N11Canonicalizer(), defaultNSResetInput, `<a xmlns="urn:x"><b xmlns="">t</b></a>`},
		{"defaultNSReset/C14N11WithComments", MakeC14N11WithCommentsCanonicalizer(), defaultNSResetInput, `<a xmlns="urn:x"><b xmlns="">t</b></a>`},
		{"defaultNSReset/C14N10Rec", MakeC14N10RecCanonicalizer(), defaultNSResetInput, `<a xmlns="urn:x"><b xmlns="">t</b></a>`},
		{"defaultNSReset/C14N10WithComments", MakeC14N10WithCommentsCanonicalizer(), defaultNSResetInput, `<a xmlns="urn:x"><b xmlns="">t</b></a>`},
		{"mixedContent/C14N11", MakeC14N11Canonicalizer(), mixedContentInput, `<a xmlns="urn:x" a="2" z="1">lead<b xml:lang="en">t</b>tail</a>`},
		{"mixedContent/C14N11WithComments", MakeC14N11WithCommentsCanonicalizer(), mixedContentInput, `<a xmlns="urn:x" a="2" z="1">lead<!-- c --><b xml:lang="en">t</b>tail</a>`},
		{"mixedContent/C14N10Rec", MakeC14N10RecCanonicalizer(), mixedContentInput, `<a xmlns="urn:x" a="2" z="1">lead<b xml:lang="en">t</b>tail</a>`},
		{"mixedContent/C14N10WithComments", MakeC14N10WithCommentsCanonicalizer(), mixedContentInput, `<a xmlns="urn:x" a="2" z="1">lead<!-- c --><b xml:lang="en">t</b>tail</a>`},
		{"multiPrefixNested/C14N11", MakeC14N11Canonicalizer(), multiPrefixNestedInput, `<p:a xmlns:p="urn:x" xmlns:q="urn:y"><q:b><p:c></p:c></q:b></p:a>`},
		{"multiPrefixNested/C14N11WithComments", MakeC14N11WithCommentsCanonicalizer(), multiPrefixNestedInput, `<p:a xmlns:p="urn:x" xmlns:q="urn:y"><q:b><p:c></p:c></q:b></p:a>`},
		{"multiPrefixNested/C14N10Rec", MakeC14N10RecCanonicalizer(), multiPrefixNestedInput, `<p:a xmlns:p="urn:x" xmlns:q="urn:y"><q:b><p:c></p:c></q:b></p:a>`},
		{"multiPrefixNested/C14N10WithComments", MakeC14N10WithCommentsCanonicalizer(), multiPrefixNestedInput, `<p:a xmlns:p="urn:x" xmlns:q="urn:y"><q:b><p:c></p:c></q:b></p:a>`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runCanonicalizationTest(t, test.canonicalizer, test.input, test.want)
		})
	}
}

// TestCanonicalPrepDoesNotMutateInput covers the contract the NullCanonicalizer
// and c14N11Canonicalizer rely on: they hand canonicalPrep an element that the
// caller still owns.
func TestCanonicalPrepDoesNotMutateInput(t *testing.T) {
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(mixedContentInput))

	before, err := canonicalSerialize(doc.Root())
	require.NoError(t, err)

	_ = canonicalPrep(doc.Root(), true, false)

	after, err := canonicalSerialize(doc.Root())
	require.NoError(t, err)
	require.Equal(t, string(before), string(after))
}

// nestedChain builds an element containing a chain `depth` levels deep. It is
// built rather than parsed so the depth is independent of etree's
// ReadSettings.MaxDepth.
func nestedChain(depth int) *etree.Element {
	doc := etree.NewDocument()
	root := doc.CreateElement("root")
	root.CreateAttr("xmlns", "urn:x")

	el := root
	for i := 0; i < depth; i++ {
		el = el.CreateElement("a")
	}
	el.SetText("leaf")

	return root
}

func allocsFor(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)

	return after.TotalAlloc - before.TotalAlloc
}

// TestInclusiveCanonicalizationIsLinearInDepth guards the memory behaviour of
// canonicalPrepInner. Copying at every node made a chain cost O(depth^2), so
// quadrupling the depth quadrupled the allocations four times over. In place it
// is linear, and quadrupling the depth should roughly quadruple allocations.
func TestInclusiveCanonicalizationIsLinearInDepth(t *testing.T) {
	const shallow, deep = 200, 800

	small := allocsFor(func() { canonicalPrep(nestedChain(shallow), true, false) })
	large := allocsFor(func() { canonicalPrep(nestedChain(deep), true, false) })
	require.NotZero(t, small)

	growth := float64(large) / float64(small)
	t.Logf("depth %d: %d bytes, depth %d: %d bytes, growth %.1fx", shallow, small, deep, large, growth)
	require.Less(t, growth, 8.0, "allocations should grow about linearly with depth, not quadratically")
}
