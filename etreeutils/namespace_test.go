package etreeutils

import (
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

// nestedElement builds the tree directly rather than parsing it, so that the
// depth under test stays independent of etree's ReadSettings.MaxDepth.
func nestedElement(t *testing.T, depth int) *etree.Element {
	t.Helper()

	doc := etree.NewDocument()
	root := doc.CreateElement("root")
	root.CreateAttr("xmlns", "http://example.org")

	el := root
	for i := 0; i < depth; i++ {
		el = el.CreateElement("a")
	}

	return root
}

// TestNSSelectOneCtxReturnsErrorWhenNotFound verifies #80: NSSelectOneCtx
// (and NSSelectOne, which wraps it) must return a non-nil error when no
// matching element is found, not silently return (nil, nil). Callers that
// only check the error (a natural read of the signature) would otherwise
// go on to dereference the nil *etree.Element and panic -- exactly the
// production crash reported against dexidp/dex#1823.
func TestNSSelectOneCtxReturnsErrorWhenNotFound(t *testing.T) {
	doc := etree.NewDocument()
	root := doc.CreateElement("root")
	root.CreateAttr("xmlns", "http://example.org")
	root.CreateElement("present")

	found, err := NSSelectOneCtx(NewDefaultNSContext(), root, "http://example.org", "absent")
	require.Error(t, err, "expected an error when no element matches, got (nil, nil)")
	require.Nil(t, found)
}

func TestNSSelectOneCtxFindsExistingElement(t *testing.T) {
	doc := etree.NewDocument()
	root := doc.CreateElement("root")
	root.CreateAttr("xmlns", "http://example.org")
	root.CreateElement("present")

	found, err := NSSelectOneCtx(NewDefaultNSContext(), root, "http://example.org", "present")
	require.NoError(t, err)
	require.NotNil(t, found)
	require.Equal(t, "present", found.Tag)
}

// TestNSFindOneCtxReturnsNilNilWhenNotFound locks in NSFindOneCtx's actual,
// intentional contract: unlike NSSelectOneCtx (#80) and NSFindOneChildCtx,
// both of which share the exact same code shape but were fixed to return
// ErrElementNotFound, NSFindOneCtx deliberately returns (nil, nil) when
// nothing matches -- validate_test.go's TestMapPathAndRemove depends on
// this to check whether an element still exists after removal. Found (and
// almost "fixed" the same way, before this test caught it) while fixing
// #80 -- kept as a regression test against the same mistake happening
// again, not as a statement that this is the ideal API shape.
func TestNSFindOneCtxReturnsNilNilWhenNotFound(t *testing.T) {
	doc := etree.NewDocument()
	root := doc.CreateElement("root")
	root.CreateAttr("xmlns", "http://example.org")
	root.CreateElement("present")

	found, err := NSFindOneCtx(NewDefaultNSContext(), root, "http://example.org", "absent")
	require.NoError(t, err)
	require.Nil(t, found)
}

func TestNSFindOneCtxFindsExistingElement(t *testing.T) {
	doc := etree.NewDocument()
	root := doc.CreateElement("root")
	root.CreateAttr("xmlns", "http://example.org")
	root.CreateElement("present")

	found, err := NSFindOneCtx(NewDefaultNSContext(), root, "http://example.org", "present")
	require.NoError(t, err)
	require.NotNil(t, found)
	require.Equal(t, "present", found.Tag)
}

// TestNSFindOneChildCtxReturnsErrorWhenNotFound covers the same #80
// pattern in NSSelectOneCtx's other sibling, found while fixing it: it
// also returned (nil, nil) instead of an error when nothing matched.
// Unlike NSFindOneCtx above, no caller depends on the (nil, nil) shape --
// validate.go's three call sites all already guard with their own
// `if x == nil` check treating it as an error -- so fixing it here is
// backward compatible with every known usage.
func TestNSFindOneChildCtxReturnsErrorWhenNotFound(t *testing.T) {
	doc := etree.NewDocument()
	root := doc.CreateElement("root")
	root.CreateAttr("xmlns", "http://example.org")
	root.CreateElement("present")

	found, err := NSFindOneChildCtx(NewDefaultNSContext(), root, "http://example.org", "absent")
	require.Error(t, err, "expected an error when no child matches, got (nil, nil)")
	require.Nil(t, found)
}

func TestNSFindOneChildCtxFindsExistingElement(t *testing.T) {
	doc := etree.NewDocument()
	root := doc.CreateElement("root")
	root.CreateAttr("xmlns", "http://example.org")
	root.CreateElement("present")

	found, err := NSFindOneChildCtx(NewDefaultNSContext(), root, "http://example.org", "present")
	require.NoError(t, err)
	require.NotNil(t, found)
	require.Equal(t, "present", found.Tag)
}

func TestNSDetatchLimit(t *testing.T) {
	detached, err := NSDetatch(NewDefaultNSContext(), nestedElement(t, 10))
	require.NoError(t, err)
	require.NotNil(t, detached)

	_, err = NSDetatch(NewDefaultNSContext(), nestedElement(t, 5000))
	require.ErrorIs(t, err, ErrTraversalLimit)
}
