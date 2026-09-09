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

func TestNSDetatchLimit(t *testing.T) {
	detached, err := NSDetatch(NewDefaultNSContext(), nestedElement(t, 10))
	require.NoError(t, err)
	require.NotNil(t, detached)

	_, err = NSDetatch(NewDefaultNSContext(), nestedElement(t, 5000))
	require.ErrorIs(t, err, ErrTraversalLimit)
}

// wideElement builds an element with `siblings` direct children, so that the
// tree grows in breadth while its depth stays constant.
func wideElement(t *testing.T, siblings int) *etree.Element {
	t.Helper()

	doc := etree.NewDocument()
	root := doc.CreateElement("root")
	root.CreateAttr("xmlns", "http://example.org")

	for i := 0; i < siblings; i++ {
		root.CreateElement("a")
	}

	return root
}

// TestTraversalLimitBoundsDepthNotBreadth documents which dimension the
// traversal budget constrains. Each level of recursion spends its own copy of
// the budget, so breadth is free and depth is what gets refused. That matters
// for callers such as SAML, where a single attribute legitimately carries
// hundreds of sibling values but nesting stays shallow.
func TestTraversalLimitBoundsDepthNotBreadth(t *testing.T) {
	noop := func(NSContext, *etree.Element) error { return nil }

	for _, siblings := range []int{defaultDepthLimit, defaultDepthLimit * 50} {
		detached, err := NSDetatch(NewDefaultNSContext(), wideElement(t, siblings))
		require.NoError(t, err)
		require.NotNil(t, detached)

		require.NoError(t, NSTraverse(NewDefaultNSContext(), wideElement(t, siblings), noop))
	}

	_, err := NSDetatch(NewDefaultNSContext(), nestedElement(t, defaultDepthLimit-100))
	require.NoError(t, err)

	_, err = NSDetatch(NewDefaultNSContext(), nestedElement(t, defaultDepthLimit+100))
	require.ErrorIs(t, err, ErrTraversalLimit)

	err = NSTraverse(NewDefaultNSContext(), nestedElement(t, defaultDepthLimit+100), noop)
	require.ErrorIs(t, err, ErrTraversalLimit)
}

// TestEmptyNSContextIsUnlimited covers the zero value of NSContext, which
// carries no budget at all rather than an exhausted one.
func TestEmptyNSContextIsUnlimited(t *testing.T) {
	ctx := EmptyNSContext
	require.NoError(t, ctx.CheckLimit())

	require.NoError(t, NSTraverse(EmptyNSContext, nestedElement(t, defaultDepthLimit*2),
		func(NSContext, *etree.Element) error { return nil }))
}
