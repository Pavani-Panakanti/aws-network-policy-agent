// Package fwruleprocessor builds eBPF firewall map entries from PolicyEndpoint specs.
//
// # CIDR Trie: Storage Layout and Debugging
//
// The cidrTrie accelerates the "which CIDRs contain this IP?" query that runs once
// per firewall rule during reconcile. Without it, the lookup was O(rules × CIDRs)
// with a net.ParseCIDR call per pair; with the trie it is O(address-bits) per lookup.
//
// ## IP Storage Format
//
// IPs are stored as raw byte slices in their canonical form:
//   - IPv4: 4 bytes (net.IP.To4)
//   - IPv6: 16 bytes (net.IP.To16)
//   - v4-mapped IPv6 (::ffff:x.x.x.x): normalized to 4-byte IPv4 form
//
// This normalization (see normalizeIP) ensures that a v4-mapped address matches
// against v4 CIDRs in the v4 sub-trie, not the v6 sub-trie.
//
// ## Trie Layout
//
// The trie has two independent roots: v4Root and v6Root. Each node has:
//   - children [2]*cidrTrieNode — left (bit=0) and right (bit=1)
//   - cidrKey  string              — canonical CIDR string stored at this prefix depth
//
// Insertion walks the network prefix bits (MSB-first) from root, creating nodes
// as needed, and appends the CIDR string key at the node corresponding to the
// last prefix bit. For example, inserting "10.0.0.0/8" stores the key at depth 8
// in the v4 sub-trie.
//
// The CIDR is stored in canonical form (ipNet.String() — host bits masked).
// ComputeMapEntriesFromEndpointRules canonicalizes each rule's IPCidr before
// insertion, and insert() itself calls net.ParseCIDR which masks host bits, so the
// stored key always matches what the nonHostCIDRs map uses as its key.
//
// ## Query Semantics (findContainingKeys)
//
// Given an IP, the trie walks from root along the IP's bits, collecting cidrKey
// at every node visited, ordered from shortest prefix (most general) to longest
// (most specific).
//
// This is NOT the same as "every CIDR that contains the IP". The walk spans the full
// address width, so it also returns keys that are strict SUBNETS of the queried
// prefix whenever they share its network address: querying 10.0.0.0/8 also yields
// 10.0.0.0/24. A subnet does not contain the query, and letting one donate its ports
// would allow them across the whole enclosing prefix, so
// checkAndDeriveL4InfoFromAnyMatchingCIDRsTrie discards any returned key whose
// prefix is longer than the query's. That filter is load-bearing, not redundant.
//
// The caller then looks up each returned key in nonHostCIDRs, which holds a SLICE of
// rules per CIDR rather than one merged rule. Each rule is tested independently: it
// donates its ports only if its own Except list covers neither the query nor a
// broader prefix than it. Several rules can share a CIDR with different port sets and
// different Except lists, so a merged view would pair one rule's ports with another
// rule's excepts.
//
// Each query costs a net.ParseCIDR per returned key for that prefix-length filter,
// which is a small constant beside the O(N) scan the trie replaces.
//
// ## Lifecycle
//
// The trie is built once per reconcile (in ComputeMapEntriesFromEndpointRules) from
// the non-host CIDR rules in the PolicyEndpoint spec, and queried twice: once for
// every rule whose CIDR falls inside a broader one, and again for every ipBlock
// Except CIDR, which inherits the ports of containing rules that do not except it.
// It is discarded after reconcile completes and is never shared across goroutines.
package fwruleprocessor
