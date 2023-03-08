package types

import (
	"encoding/xml"

	"github.com/beevik/etree"
)

type InclusiveNamespaces struct {
	XMLName    xml.Name `xml:"http://www.w3.org/2001/10/xml-exc-c14n# InclusiveNamespaces"`
	PrefixList string   `xml:"PrefixList,attr"`
}

type Transform struct {
	XMLName             xml.Name             `xml:"http://www.w3.org/2000/09/xmldsig# Transform"`
	Algorithm           string               `xml:"Algorithm,attr"`
	InclusiveNamespaces *InclusiveNamespaces `xml:"InclusiveNamespaces"`
}

type Transforms struct {
	XMLName    xml.Name    `xml:"http://www.w3.org/2000/09/xmldsig# Transforms"`
	Transforms []Transform `xml:"Transform"`
}

type DigestMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

type Reference struct {
	XMLName     xml.Name     `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
	URI         string       `xml:"URI,attr"`
	Type        string       `xml:"Type,attr"`
	DigestValue string       `xml:"DigestValue"`
	DigestAlgo  DigestMethod `xml:"DigestMethod"`
	Transforms  Transforms   `xml:"Transforms"`
}

type Manifest struct {
	XMLName    xml.Name    `xml:"http://www.w3.org/2000/09/xmldsig# Manifest"`
	References []Reference `xml:"Reference"`
}

type CanonicalizationMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

type SignatureMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

type SignedInfo struct {
	XMLName                xml.Name               `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	CanonicalizationMethod CanonicalizationMethod `xml:"CanonicalizationMethod"`
	SignatureMethod        SignatureMethod        `xml:"SignatureMethod"`
	References             []Reference            `xml:"Reference"`
}

type SignatureValue struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignatureValue"`
	Data    string   `xml:",chardata"`
}

type KeyInfo struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	X509Data X509Data `xml:"X509Data"`
}

type X509Data struct {
	XMLName          xml.Name          `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	X509Certificates []X509Certificate `xml:"X509Certificate"`
}

type X509Certificate struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
	Data    string   `xml:",chardata"`
}

type Signature struct {
	XMLName        xml.Name        `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	SignedInfo     *SignedInfo     `xml:"SignedInfo"`
	SignatureValue *SignatureValue `xml:"SignatureValue"`
	KeyInfo        *KeyInfo        `xml:"KeyInfo"`
	el             *etree.Element
	path           []int
	RootRef        *Reference
}

// SetUnderlyingElement will be called with a reference to the Element this Signature
// was unmarshaled from.
func (s *Signature) SetUnderlyingElement(root, el *etree.Element) {
	s.el = el
	// map the path to the passed signature relative to the passed root, in order
	// to enable removal of the signature by an enveloped signature transform
	s.path = mapPathToElement(root, el)
}

// UnderlyingElement returns a reference to the Element this signature was unmarshaled
// from, where applicable.
func (s *Signature) UnderlyingElement() *etree.Element {
	return s.el
}

func (s *Signature) RemoveUnderlyingElement(el *etree.Element) bool {
	return removeElementAtPath(el, s.path)
}

func mapPathToElement(tree, el *etree.Element) []int {
	for i, child := range tree.Child {
		if child == el {
			return []int{i}
		}
	}

	for i, child := range tree.Child {
		if childElement, ok := child.(*etree.Element); ok {
			childPath := mapPathToElement(childElement, el)
			if childPath != nil {
				return append([]int{i}, childPath...)
			}
		}
	}

	return nil
}

func removeElementAtPath(el *etree.Element, path []int) bool {

	if len(path) == 0 {
		return false
	}

	if path[0] < len(el.Child) {

		if len(path) == 1 {
			el.RemoveChildAt(path[0])
			return true
		}

		childElement, ok := el.Child[path[0]].(*etree.Element)
		if ok {
			return removeElementAtPath(childElement, path[1:])
		}
	}
	return false
}
