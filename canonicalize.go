package dsig

import (
	"fmt"
	"sort"

	"github.com/beevik/etree"
)

type attrsByKey []etree.Attr

func composeAttr(space, key string) string {
	if space != "" {
		return space + ":" + key
	}

	return key
}

func (a attrsByKey) Len() int {
	return len(a)
}

func (a attrsByKey) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a attrsByKey) Less(i, j int) bool {
	// As I understand it: any "xmlns" attribute should come first, followed by any
	// any "xmlns:prefix" attributes, presumably ordered by prefix. Lastly any other
	// attributes in lexicographical order.
	if a[i].Space == "" && a[i].Key == "xmlns" {
		return true
	}

	if a[i].Space == "xmlns" {
		if a[j].Space == "xmlns" {
			return a[i].Key < a[j].Key
		}
		return true
	}

	if a[j].Space == "xmlns" {
		return false
	}

	return composeAttr(a[i].Space, a[i].Key) < composeAttr(a[j].Space, a[j].Key)
}

func _canonicalHack(el *etree.Element, seenSoFar map[string]struct{}) *etree.Element {
	_seenSoFar := make(map[string]struct{})
	for k, v := range seenSoFar {
		_seenSoFar[k] = v
	}

	ne := el.Copy()
	sort.Sort(attrsByKey(ne.Attr))
	if len(ne.Attr) != 0 {
		for _, attr := range ne.Attr {
			if attr.Space != "xmlns" {
				continue
			}
			key := attr.Space + ":" + attr.Key
			if _, seen := _seenSoFar[key]; seen {
				ne.RemoveAttr(attr.Space + ":" + attr.Key)
			} else {
				_seenSoFar[key] = struct{}{}
			}
		}
	}

	for i, token := range ne.Child {
		childElement, ok := token.(*etree.Element)
		if ok {
			ne.Child[i] = _canonicalHack(childElement, _seenSoFar)
		}
	}

	return ne
}

// NOTE(russell_h): It looks like etree's canonical XML support doesn't
// re-order attributes. This call is an opportunity to do that, and correct
// any other other shortcomings until I can get the fixes upstream.
// NOTE(phoebe): Looks like etree also doesn't remove attributes that are
// duplicate namespaces. They should be removed if a parent has a matching one
func canonicalHack(el *etree.Element) *etree.Element {
	attrMap := make(map[string]struct{})
	return _canonicalHack(el, attrMap)
}

func getNsDecl(a etree.Attr) string {
	return fmt.Sprintf("xmlns:%s", a.Key)
}

type c14nSpace struct {
	a    etree.Attr
	used bool
}

const nsSpace = "xmlns"

func _excCanonicalPrep(el *etree.Element, _nsAlreadyDeclared map[string]c14nSpace) *etree.Element {
	//Copy alreadyDeclared map (only contains namespaces)
	nsAlreadyDeclared := make(map[string]c14nSpace, len(_nsAlreadyDeclared))
	for k := range _nsAlreadyDeclared {
		nsAlreadyDeclared[k] = _nsAlreadyDeclared[k]
	}

	//Track the namespaces used on the current element
	nsUsedHere := make(map[string]struct{})

	//Make sure to track the element namespace for the case:
	//<foo:bar xmlns:foo="..."/>
	if el.Space != "" {
		nsUsedHere[el.Space] = struct{}{}
	}

	toRemove := make([]string, 0, 0)

	for _, a := range el.Attr {
		switch a.Space {
		case nsSpace:
			//For simplicity, remove all xmlns attribues; to be added in one pass
			//later.  Otherwise, we need another map/set to track xmlns attributes
			//that we left alone.
			toRemove = append(toRemove, a.Space+":"+a.Key)
			if _, ok := nsAlreadyDeclared[a.Key]; !ok {
				//If we're not tracking ancestor state already for this namespace, add
				//it to the map
				nsAlreadyDeclared[a.Key] = c14nSpace{a: a, used: false}
			}
		default:
			//We only track namespaces, so ignore attributes without one.
			if a.Space != "" {
				nsUsedHere[a.Space] = struct{}{}
			}
		}
	}
	//Remove all attributes so that we can add them with much-simpler logic
	for _, attrK := range toRemove {
		el.RemoveAttr(attrK)
	}

	//For all namespaces used on the current element, declare them if they were
	//not declared (and used) in an ancestor.
	for k := range nsUsedHere {
		spc := nsAlreadyDeclared[k]
		//If previously unused, mark as used
		if !spc.used {
			el.Attr = append(el.Attr, spc.a)
			spc.used = true

			//Assignment here is only to update the pre-existing `used` tracking value
			nsAlreadyDeclared[k] = spc
		}
	}

	//Canonicalize all children, passing down the ancestor tracking map
	for _, child := range el.ChildElements() {
		_excCanonicalPrep(child, nsAlreadyDeclared)
	}

	//Sort attributes lexicographically
	sort.Sort(attrsByKey(el.Attr))

	return el.Copy()
}

func excCanonicalPrep(el *etree.Element) *etree.Element {
	return _excCanonicalPrep(el, make(map[string]c14nSpace))
}

func canonicalize(el *etree.Element, canonicalizationMethod SignatureAlgorithm, isOkta bool) *etree.Element {
	if isOkta {
		return canonicalHack(el)
	}

	switch canonicalizationMethod {
	case CanonicalXML10AlgorithmId:
		return excCanonicalPrep(el)
	default:
		return canonicalHack(el)
	}

}
