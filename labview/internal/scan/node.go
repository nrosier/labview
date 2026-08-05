// Package scan reads a compose tree and produces the scanned half of the payload (§6).
//
// Nothing here touches the network and nothing writes to the tree it reads (I5). Anything
// it cannot understand becomes a stack warning or a service note rather than an error: a
// stack whose compose file will not parse is still listed (§6, I4).
package scan

import "gopkg.in/yaml.v3"

// Compose files are read through yaml.Node rather than decoded into structs, for two
// reasons that both cost correctness if ignored.
//
// The first is that half of Compose's keys are union-typed — `command` is a string or a
// list, `depends_on` a list or a mapping, `labels` either — and a struct field can only
// be one of them. The second is that a resolved YAML value is the wrong value. `ports:
// [8096:8096]` and `labels: {traefik.enable: true}` are text to Compose; decoding the
// first into anything numeric or the second into a string would fail or lie, and §6
// requires the evidence as written. Reading Node.Value gives the document's own text
// every time, whatever tag the resolver picked.

const (
	// maxAliasDepth bounds alias following. yaml.v3 hands aliases over unexpanded, so a
	// document whose anchors reference each other in a cycle is representable and this
	// walk is the thing that has to refuse to follow it forever (I8).
	maxAliasDepth = 32

	// maxMergeDepth bounds how deep a chain of `<<:` merge keys is spliced.
	maxMergeDepth = 8
)

// docRoot unwraps a document node to the value it holds.
func docRoot(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		return n.Content[0]
	}
	return n
}

// deref follows an alias to the node it names, and returns nil for a cycle.
func deref(n *yaml.Node) *yaml.Node {
	for i := 0; i < maxAliasDepth; i++ {
		if n == nil || n.Kind != yaml.AliasNode {
			return n
		}
		n = n.Alias
	}
	return nil
}

func isMapping(n *yaml.Node) bool {
	n = deref(n)
	return n != nil && n.Kind == yaml.MappingNode
}

func isSequence(n *yaml.Node) bool {
	n = deref(n)
	return n != nil && n.Kind == yaml.SequenceNode
}

// isScalar excludes null, because a null is a key with no value rather than a value.
func isScalar(n *yaml.Node) bool {
	n = deref(n)
	return n != nil && n.Kind == yaml.ScalarNode && n.Tag != "!!null"
}

// isNull reports whether a node says nothing: absent, an explicit null, or — the case an
// empty file produces — a node the parser never filled in. `networks: {backend: }`
// declares a network with a null body, which differs from a missing key only in that the
// key is there, and that difference is the declaration.
func isNull(n *yaml.Node) bool {
	n = deref(n)
	return n == nil || n.Kind == 0 || (n.Kind == yaml.ScalarNode && n.Tag == "!!null")
}

// text is a scalar's text exactly as the document spells it, and "" for anything else.
func text(n *yaml.Node) string {
	if !isScalar(n) {
		return ""
	}
	return deref(n).Value
}

// entry is one key/value pair of a mapping, with the key as text.
type entry struct {
	Key  string
	Node *yaml.Node
}

// entries lists a mapping's pairs in document order, with `<<:` merge keys spliced in.
//
// Merging is not decoration: an operator who factors shared service settings into an
// `x-common: &common` block and merges it into six services has written six services
// with those settings, and a reader that skips the merge reports six services without
// them. An explicit key wins over a merged one and an earlier merge over a later, which
// is what YAML says.
func entries(n *yaml.Node) []entry { return mergedEntries(n, 0) }

func mergedEntries(n *yaml.Node, depth int) []entry {
	n = deref(n)
	if n == nil || n.Kind != yaml.MappingNode || depth > maxMergeDepth {
		return nil
	}
	var own, merged []entry
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Tag == "!!merge" {
			for _, src := range mergeSources(v) {
				merged = append(merged, mergedEntries(src, depth+1)...)
			}
			continue
		}
		if k.Kind != yaml.ScalarNode {
			continue // a complex key names no Compose setting
		}
		own = append(own, entry{Key: k.Value, Node: v})
	}

	out := make([]entry, 0, len(own)+len(merged))
	seen := make(map[string]bool, len(own)+len(merged))
	for _, e := range own {
		if !seen[e.Key] {
			seen[e.Key] = true
			out = append(out, e)
		}
	}
	for _, e := range merged {
		if !seen[e.Key] {
			seen[e.Key] = true
			out = append(out, e)
		}
	}
	return out
}

// mergeSources is the one or many mappings a `<<:` names.
func mergeSources(v *yaml.Node) []*yaml.Node {
	if d := deref(v); d != nil && d.Kind == yaml.SequenceNode {
		return d.Content
	}
	return []*yaml.Node{v}
}

// field is one key of a mapping, or nil when the key or the mapping is absent.
func field(n *yaml.Node, key string) *yaml.Node {
	for _, e := range entries(n) {
		if e.Key == key {
			return e.Node
		}
	}
	return nil
}

// items is a sequence's elements. Use isSequence to tell an empty sequence from a node
// that is not one.
func items(n *yaml.Node) []*yaml.Node {
	n = deref(n)
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	return n.Content
}
