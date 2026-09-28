package fwruleprocessor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

// trieEntry is one decoded 12-byte slot of a value built by utils.ComputeTrieValue.
type trieEntry struct {
	protocol  int
	startPort int
	endPort   int
}

// decodeTrieValueEntries decodes the populated slots of a TRIE value. Slots the
// encoder did not write are left zeroed, and protocol 0 is not a value the
// encoder ever emits, so a zero protocol marks the unused tail.
func decodeTrieValueEntries(value []byte) []trieEntry {
	var entries []trieEntry
	for off := 0; off+12 <= len(value); off += 12 {
		protocol := int(binary.LittleEndian.Uint32(value[off : off+4]))
		if protocol == 0 {
			continue
		}
		entries = append(entries, trieEntry{
			protocol:  protocol,
			startPort: int(binary.LittleEndian.Uint32(value[off+4 : off+8])),
			endPort:   int(binary.LittleEndian.Uint32(value[off+8 : off+12])),
		})
	}
	return entries
}

func hasDenyAll(entries []trieEntry) bool {
	for _, e := range entries {
		if e.protocol == utils.RESERVED_IP_PROTOCOL_NUMBER {
			return true
		}
	}
	return false
}

func hasCatchAll(entries []trieEntry) bool {
	for _, e := range entries {
		if e.protocol == utils.ANY_IP_PROTOCOL && e.startPort == 0 {
			return true
		}
	}
	return false
}

func hasPortProtocol(entries []trieEntry, protocol, startPort int) bool {
	for _, e := range entries {
		if e.protocol == protocol && e.startPort == startPort {
			return true
		}
	}
	return false
}

// trieKeyFor builds the map key the processor emits for a CIDR.
func trieKeyFor(t *testing.T, cidr string, enableIPv6 bool) string {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(cidr)
	assert.NoErrorf(t, err, "test setup: cannot parse %s", cidr)
	return string(utils.ComputeTrieKey(*ipNet, enableIPv6))
}

// entriesForCIDR returns the decoded entries of the map entry for cidr.
func entriesForCIDR(t *testing.T, got map[string][]byte, cidr string, enableIPv6 bool) []trieEntry {
	t.Helper()
	value, ok := got[trieKeyFor(t, cidr, enableIPv6)]
	assert.Truef(t, ok, "expected a map entry for %s", cidr)
	return decodeTrieValueEntries(value)
}

func tcpPort(port int32) v1alpha1.Port {
	p := corev1.ProtocolTCP
	return v1alpha1.Port{Protocol: &p, Port: &port}
}

func udpPort(port int32) v1alpha1.Port {
	p := corev1.ProtocolUDP
	return v1alpha1.Port{Protocol: &p, Port: &port}
}

// TestFWRuleProcessor_ExceptInheritsPortsFromNonExceptingRule is the core of the
// ipBlock `except` overlap fix. An `except` is scoped to the rule that lists it,
// and rules are additive (a union of allows), so a rule that contains the excepted
// CIDR and does NOT except it still allows its ports there.
//
// Previously the excepted CIDR was given an unconditional deny-all entry and
// inherited nothing, so port 53 to the excepted range was denied even though the
// port-53 rule carried no except. That breaks policies of the form "DNS to
// everywhere, everything else only to public IPs", because the cluster DNS service
// sits inside the excepted range.
func TestFWRuleProcessor_ExceptInheritsPortsFromNonExceptingRule(t *testing.T) {
	tests := []struct {
		name  string
		rules []EbpfFirewallRules
	}{
		{
			name: "ported rule authored first",
			rules: []EbpfFirewallRules{
				{IPCidr: "0.0.0.0/0", L4Info: []v1alpha1.Port{udpPort(53), tcpPort(53)}},
				{IPCidr: "0.0.0.0/0", Except: []v1alpha1.NetworkAddress{"10.0.0.0/8", "172.16.0.0/12"}},
			},
		},
		{
			// The pre-merge snapshot of each rule is what makes this order work:
			// rules sharing a CIDR are merged for emission, and a merged entry
			// would pair the ported rule's ports with the other rule's except list.
			name: "except rule authored first",
			rules: []EbpfFirewallRules{
				{IPCidr: "0.0.0.0/0", Except: []v1alpha1.NetworkAddress{"10.0.0.0/8", "172.16.0.0/12"}},
				{IPCidr: "0.0.0.0/0", L4Info: []v1alpha1.Port{udpPort(53), tcpPort(53)}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewFirewallRuleProcessor("192.168.1.1", "/32", false).
				ComputeMapEntriesFromEndpointRules(tt.rules)
			assert.NoError(t, err)

			for _, excepted := range []string{"10.0.0.0/8", "172.16.0.0/12"} {
				entries := entriesForCIDR(t, got, excepted, false)
				assert.Truef(t, hasPortProtocol(entries, utils.UDP_PROTOCOL_NUMBER, 53),
					"%s must inherit UDP/53 from the rule that does not except it; got %+v", excepted, entries)
				assert.Truef(t, hasPortProtocol(entries, utils.TCP_PROTOCOL_NUMBER, 53),
					"%s must inherit TCP/53; got %+v", excepted, entries)
				assert.Falsef(t, hasDenyAll(entries),
					"%s must not carry a deny-all entry once it has inherited allows: the datapath "+
						"returns DENY on sight of it and would drop the inherited ports; got %+v", excepted, entries)
				assert.Falsef(t, hasCatchAll(entries),
					"%s must not inherit the all-ports catch-all from the rule that DOES except it; got %+v",
					excepted, entries)
			}
		})
	}
}

// TestFWRuleProcessor_ExceptWithNothingToInheritIsDenyAll covers the other half:
// when no other rule allows anything at the excepted CIDR it gets a deny-all
// entry. That entry is what keeps the map value non-empty, since ComputeTrieValue
// treats an empty value as allow-all.
func TestFWRuleProcessor_ExceptWithNothingToInheritIsDenyAll(t *testing.T) {
	rules := []EbpfFirewallRules{
		{IPCidr: "0.0.0.0/0", Except: []v1alpha1.NetworkAddress{"10.0.0.0/8"}},
	}
	got, err := NewFirewallRuleProcessor("192.168.1.1", "/32", false).
		ComputeMapEntriesFromEndpointRules(rules)
	assert.NoError(t, err)

	entries := entriesForCIDR(t, got, "10.0.0.0/8", false)
	assert.Truef(t, hasDenyAll(entries),
		"an excepted CIDR with nothing to inherit must carry a deny-all entry; got %+v", entries)
}

// TestFWRuleProcessor_ExceptDoesNotInheritFromItsOwnSubnet guards a policy bypass.
// The containment lookup walks the full address width, so querying 10.0.0.0/8 also
// returns 10.0.0.0/24 when they share a network address. A subnet does not contain
// the query, and letting it donate allowed its ports across the whole excepted block.
func TestFWRuleProcessor_ExceptDoesNotInheritFromItsOwnSubnet(t *testing.T) {
	tests := []struct {
		name       string
		enableIPv6 bool
		nodeIP     string
		hostMask   string
		except     string
		subnet     string
	}{
		{"v4 /8 except with /24 subnet", false, "192.168.1.1", "/32", "10.0.0.0/8", "10.0.0.0/24"},
		{"v4 /9 except with /16 subnet", false, "192.168.1.1", "/32", "10.0.0.0/9", "10.0.0.0/16"},
		{"v4 /12 except with /24 subnet", false, "8.8.4.4", "/32", "172.16.0.0/12", "172.16.0.0/24"},
		{"v6 /16 except with /64 subnet", true, "2001:db8::1", "/128", "fd00::/16", "fd00::/64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := []EbpfFirewallRules{
				{IPCidr: "0.0.0.0/0", Except: []v1alpha1.NetworkAddress{v1alpha1.NetworkAddress(tt.except)}},
				{IPCidr: v1alpha1.NetworkAddress(tt.subnet), L4Info: []v1alpha1.Port{tcpPort(80)}},
			}
			if tt.enableIPv6 {
				rules[0].IPCidr = "::/0"
			}
			got, err := NewFirewallRuleProcessor(tt.nodeIP, tt.hostMask, tt.enableIPv6).
				ComputeMapEntriesFromEndpointRules(rules)
			assert.NoError(t, err)

			entries := entriesForCIDR(t, got, tt.except, tt.enableIPv6)
			assert.Falsef(t, hasPortProtocol(entries, utils.TCP_PROTOCOL_NUMBER, 80),
				"%s must not inherit TCP/80 from its own subnet %s: that allows the subnet's port "+
					"across the whole excepted block; got %+v", tt.except, tt.subnet, entries)
			assert.Truef(t, hasDenyAll(entries),
				"%s has nothing legitimate to inherit so it must be deny-all; got %+v", tt.except, entries)

			// The explicit allow on the subnet itself must still stand.
			subnetEntries := entriesForCIDR(t, got, tt.subnet, tt.enableIPv6)
			assert.Truef(t, hasPortProtocol(subnetEntries, utils.TCP_PROTOCOL_NUMBER, 80),
				"the explicit allow on %s must survive; got %+v", tt.subnet, subnetEntries)
		})
	}
}

// TestFWRuleProcessor_ExceptNarrowerThanQueryDoesNotSuppressDonor is the mirror of
// the subnet case, on the except operand. A containment test against one address
// cannot tell "this except covers the whole query" from "this except is a small
// hole inside the query". Treating the second as the first suppressed a donor
// across an entire block, denying traffic the union of allows permits.
func TestFWRuleProcessor_ExceptNarrowerThanQueryDoesNotSuppressDonor(t *testing.T) {
	rules := []EbpfFirewallRules{
		{IPCidr: "0.0.0.0/0", Except: []v1alpha1.NetworkAddress{"10.1.0.0/24"}},
		{IPCidr: "10.0.0.0/8", L4Info: []v1alpha1.Port{udpPort(443)}},
		{IPCidr: "10.1.0.0/16", L4Info: []v1alpha1.Port{udpPort(3306)}},
	}
	got, err := NewFirewallRuleProcessor("192.168.1.1", "/32", false).
		ComputeMapEntriesFromEndpointRules(rules)
	assert.NoError(t, err)

	// 10.1.0.0/16 is not covered by the /24 except as a whole, so it still
	// inherits the catch-all from the allow-all rule.
	entries := entriesForCIDR(t, got, "10.1.0.0/16", false)
	assert.Truef(t, hasCatchAll(entries),
		"10.1.0.0/16 must inherit the all-ports allow: the /24 except is a strict subset of it, "+
			"so it does not carve out the /16 as a whole; got %+v", entries)
	// No assertion on UDP/3306 here: the inherited catch-all subsumes it, so the
	// value legitimately collapses to the single unconditional allow.
	assert.Lenf(t, entries, 1,
		"an inherited all-ports allow subsumes the rule's own ports, so the value collapses to it; got %+v",
		entries)

	// The /24 gets its own longer-prefix entry, which is what carves it out.
	exceptEntries := entriesForCIDR(t, got, "10.1.0.0/24", false)
	assert.Falsef(t, hasCatchAll(exceptEntries),
		"the excepted 10.1.0.0/24 must not carry the all-ports allow; got %+v", exceptEntries)
	// It still inherits from the two rules that contain it and do NOT except it.
	assert.Truef(t, hasPortProtocol(exceptEntries, utils.UDP_PROTOCOL_NUMBER, 443),
		"the excepted /24 must inherit UDP/443 from 10.0.0.0/8, which does not except it; got %+v", exceptEntries)
	assert.Truef(t, hasPortProtocol(exceptEntries, utils.UDP_PROTOCOL_NUMBER, 3306),
		"the excepted /24 must inherit UDP/3306 from 10.1.0.0/16, which does not except it; got %+v", exceptEntries)
}

// TestFWRuleProcessor_DenyAllIsNeverMixedWithAllows pins an invariant the datapath
// depends on: evaluateNamespacePolicyByLookUp returns DENY the moment it sees a
// deny-all entry, so a value holding both it and an allow would silently drop the
// allow, and the slot order is not part of the contract.
func TestFWRuleProcessor_DenyAllIsNeverMixedWithAllows(t *testing.T) {
	cases := []struct {
		name  string
		rules []EbpfFirewallRules
	}{
		{
			name:  "except with nothing to inherit",
			rules: []EbpfFirewallRules{{IPCidr: "0.0.0.0/0", Except: []v1alpha1.NetworkAddress{"10.0.0.0/8"}}},
		},
		{
			name: "except inheriting from a non-excepting rule",
			rules: []EbpfFirewallRules{
				{IPCidr: "0.0.0.0/0", L4Info: []v1alpha1.Port{udpPort(53)}},
				{IPCidr: "0.0.0.0/0", Except: []v1alpha1.NetworkAddress{"10.0.0.0/8", "172.16.0.0/12"}},
			},
		},
		{
			name: "except alongside an explicit allow on a subnet",
			rules: []EbpfFirewallRules{
				{IPCidr: "0.0.0.0/0", Except: []v1alpha1.NetworkAddress{"10.0.0.0/8"}},
				{IPCidr: "10.0.0.0/24", L4Info: []v1alpha1.Port{tcpPort(80)}},
			},
		},
		{
			name: "nested excepts on separate rules",
			rules: []EbpfFirewallRules{
				{IPCidr: "10.0.0.0/8", Except: []v1alpha1.NetworkAddress{"10.1.0.0/16"},
					L4Info: []v1alpha1.Port{tcpPort(3306)}},
				{IPCidr: "0.0.0.0/0", Except: []v1alpha1.NetworkAddress{"10.0.0.0/8"}},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewFirewallRuleProcessor("192.168.1.1", "/32", false).
				ComputeMapEntriesFromEndpointRules(tc.rules)
			assert.NoError(t, err)

			for key, value := range got {
				entries := decodeTrieValueEntries(value)
				if !hasDenyAll(entries) {
					continue
				}
				assert.Lenf(t, entries, 1,
					"key %x mixes a deny-all entry with allows, which the datapath would resolve as "+
						"DENY and drop the allows; got %+v", []byte(key), entries)
			}
		})
	}
}

// TestFWRuleProcessor_ExceptWithoutMaskIsNormalized covers excepts authored without
// a prefix length, which the CRD permits. Left un-normalized they fail to parse, so
// they neither suppress inherited ports nor produce a usable key, and the emit loop
// dereferences a nil *net.IPNet.
func TestFWRuleProcessor_ExceptWithoutMaskIsNormalized(t *testing.T) {
	t.Run("malformed excepts are skipped, not fatal", func(t *testing.T) {
		for _, except := range []string{"10.1.1.1", "not-a-cidr", "", "10.1.1.1/33"} {
			rules := []EbpfFirewallRules{
				{IPCidr: "0.0.0.0/0", Except: []v1alpha1.NetworkAddress{v1alpha1.NetworkAddress(except)},
					L4Info: []v1alpha1.Port{tcpPort(443)}},
			}
			assert.NotPanicsf(t, func() {
				_, err := NewFirewallRuleProcessor("192.168.1.1", "/32", false).
					ComputeMapEntriesFromEndpointRules(rules)
				assert.NoError(t, err)
			}, "except %q must not panic", except)
		}
	})

	t.Run("a bare address is honoured as a host except", func(t *testing.T) {
		rules := []EbpfFirewallRules{
			{IPCidr: "0.0.0.0/0", Except: []v1alpha1.NetworkAddress{"10.1.1.1"},
				L4Info: []v1alpha1.Port{tcpPort(443)}},
		}
		got, err := NewFirewallRuleProcessor("192.168.1.1", "/32", false).
			ComputeMapEntriesFromEndpointRules(rules)
		assert.NoError(t, err)

		entries := entriesForCIDR(t, got, "10.1.1.1/32", false)
		assert.Truef(t, hasDenyAll(entries),
			"a bare except address must be treated as a host route and denied; got %+v", entries)
		assert.Falsef(t, hasPortProtocol(entries, utils.TCP_PROTOCOL_NUMBER, 443),
			"the bare except must not inherit the very port its own rule allows; got %+v", entries)
	})
}

// TestFWRuleProcessor_WrongFamilyExceptEmitsNoKey asserts on the address FAMILY of
// the emitted keys. A prefix-length bound alone does not catch this: a v4 except
// like 10.0.0.0/8 reinterpreted in a v6 cluster yields a /8, which is a legal v6
// prefix length, so the bogus key passes a length check while hard-denying a
// 1-in-256 slice of the v6 address space.
func TestFWRuleProcessor_WrongFamilyExceptEmitsNoKey(t *testing.T) {
	t.Run("v4 excepts in a v6 cluster", func(t *testing.T) {
		rules := []EbpfFirewallRules{
			{IPCidr: "::/0", Except: []v1alpha1.NetworkAddress{"10.0.0.0/8", "192.168.0.0/16"},
				L4Info: []v1alpha1.Port{tcpPort(443)}},
		}
		got, err := NewFirewallRuleProcessor("2001:db8::1", "/128", true).
			ComputeMapEntriesFromEndpointRules(rules)
		assert.NoError(t, err)

		for _, bogus := range []string{"a00::/8", "c0a8::/16"} {
			_, ok := got[trieKeyFor(t, bogus, true)]
			assert.Falsef(t, ok, "a v4 except must not be reinterpreted as the v6 key %s", bogus)
		}
	})

	t.Run("v6 excepts in a v4 cluster", func(t *testing.T) {
		rules := []EbpfFirewallRules{
			{IPCidr: "0.0.0.0/0", Except: []v1alpha1.NetworkAddress{"fd00::/16"},
				L4Info: []v1alpha1.Port{tcpPort(443)}},
		}
		got, err := NewFirewallRuleProcessor("192.168.1.1", "/32", false).
			ComputeMapEntriesFromEndpointRules(rules)
		assert.NoError(t, err)

		// Assert the key is absent rather than bounding its prefix length: a leaked
		// fd00::/16 encodes to prefix length 16, which is a legal v4 length, so a
		// length bound passes whether or not the except leaked.
		_, ok := got[trieKeyFor(t, "253.0.0.0/16", false)]
		assert.False(t, ok, "a v6 except must not be reinterpreted as the v4 key 253.0.0.0/16")
	})
}

// TestFWRuleProcessor_ExceptSharingNodeIPNetworkAddressIsKept guards a bypass in the
// node-IP gate. The node-IP test compares against a CIDR's network address, so an
// except whose FIRST address is the node IP looks like the node's own route. Dropping
// it deleted the whole excepted block and left the enclosing rule's ports allowed
// across it. Only a host route can collide with the seeded node entry, because only a
// host route produces the same key.
func TestFWRuleProcessor_ExceptSharingNodeIPNetworkAddressIsKept(t *testing.T) {
	nodeIP := "10.0.1.128"

	t.Run("a broader except at the node IP is still emitted", func(t *testing.T) {
		rules := []EbpfFirewallRules{
			{IPCidr: "10.0.0.0/8", Except: []v1alpha1.NetworkAddress{"10.0.1.128/25"},
				L4Info: []v1alpha1.Port{tcpPort(443)}},
		}
		got, err := NewFirewallRuleProcessor(nodeIP, "/32", false).
			ComputeMapEntriesFromEndpointRules(rules)
		assert.NoError(t, err)

		entries := entriesForCIDR(t, got, "10.0.1.128/25", false)
		assert.Truef(t, hasDenyAll(entries),
			"the excepted 10.0.1.128/25 must be emitted and denied even though its network address "+
				"is the node IP, otherwise TCP/443 is allowed across the whole block; got %+v", entries)

		// The node's own allow-all must survive; it wins by longest prefix.
		nodeEntries := entriesForCIDR(t, got, nodeIP+"/32", false)
		assert.Truef(t, hasCatchAll(nodeEntries),
			"the node allow-all must remain intact; got %+v", nodeEntries)
	})

	t.Run("the node host route as an except does not clobber the node allow-all", func(t *testing.T) {
		for _, except := range []string{"10.0.1.128", "10.0.1.128/32"} {
			rules := []EbpfFirewallRules{
				{IPCidr: "10.0.0.0/8", Except: []v1alpha1.NetworkAddress{v1alpha1.NetworkAddress(except)},
					L4Info: []v1alpha1.Port{tcpPort(80)}},
			}
			got, err := NewFirewallRuleProcessor(nodeIP, "/32", false).
				ComputeMapEntriesFromEndpointRules(rules)
			assert.NoError(t, err)

			nodeEntries := entriesForCIDR(t, got, nodeIP+"/32", false)
			assert.Truef(t, hasCatchAll(nodeEntries),
				"except %q must not overwrite the node allow-all, which kubelet probes depend on; got %+v",
				except, nodeEntries)
		}
	})
}

// TestFWRuleProcessor_IPv6Slash32RuleCanDonatePorts covers a family-blind prefix
// check that classified an IPv6 /32 as a host route, keeping it out of the
// containment lookup entirely. /32 is the standard IPv6 allocation size, so the
// except fix silently did not apply to it.
func TestFWRuleProcessor_IPv6Slash32RuleCanDonatePorts(t *testing.T) {
	rules := []EbpfFirewallRules{
		{IPCidr: "2001:db8::/32", L4Info: []v1alpha1.Port{udpPort(53)}},
		{IPCidr: "2001:db8::/32", Except: []v1alpha1.NetworkAddress{"2001:db8:9::/48"}},
	}
	got, err := NewFirewallRuleProcessor("2001:db8:ffff::1", "/128", true).
		ComputeMapEntriesFromEndpointRules(rules)
	assert.NoError(t, err)

	entries := entriesForCIDR(t, got, "2001:db8:9::/48", true)
	assert.Truef(t, hasPortProtocol(entries, utils.UDP_PROTOCOL_NUMBER, 53),
		"the excepted /48 must inherit UDP/53 from the /32 rule that does not except it; "+
			"an IPv6 /32 is a 2^96 block, not a host route; got %+v", entries)
}

// TestFWRuleProcessor_ComputeMapEntriesIsByteIdentical asserts identical input
// yields identical bytes. Values longer than the ebpf slot cap are truncated, so an
// unstable order would change which ports are ENFORCED between reconciles.
func TestFWRuleProcessor_ComputeMapEntriesIsByteIdentical(t *testing.T) {
	var manyPorts []v1alpha1.Port
	for port := int32(8000); port < 8030; port++ {
		manyPorts = append(manyPorts, tcpPort(port))
	}
	rules := []EbpfFirewallRules{
		{IPCidr: "10.0.68.60/32", L4Info: []v1alpha1.Port{udpPort(53)}},
		{IPCidr: "10.254.0.0/16", L4Info: manyPorts},
		{IPCidr: "0.0.0.0/0", Except: []v1alpha1.NetworkAddress{"10.254.0.0/16", "169.254.0.0/16"}},
	}

	f := NewFirewallRuleProcessor("10.0.1.1", "/32", false)
	want, err := f.ComputeMapEntriesFromEndpointRules(append([]EbpfFirewallRules{}, rules...))
	assert.NoError(t, err)

	for i := 0; i < 100; i++ {
		got, err := f.ComputeMapEntriesFromEndpointRules(append([]EbpfFirewallRules{}, rules...))
		assert.NoError(t, err)
		assert.Lenf(t, got, len(want), "iteration %d: key count changed", i)
		for key, wantValue := range want {
			gotValue, ok := got[key]
			assert.Truef(t, ok, "iteration %d: key %x disappeared", i, []byte(key))
			assert.Truef(t, bytes.Equal(wantValue, gotValue),
				"iteration %d: value bytes differ for key %x", i, []byte(key))
		}
	}
}

// TestMergeDuplicateL4Info_CollapsesCatchAll covers the collapse of a fully
// unconditional allow. Such an entry matches every flow, so the others in the same
// value are dead weight, and keeping them risks the slot cap truncating the
// broadest allow. The test drives all three Port spellings that encode to it.
func TestMergeDuplicateL4Info_CollapsesCatchAll(t *testing.T) {
	var manyPorts []v1alpha1.Port
	for port := int32(8000); port < 8030; port++ {
		manyPorts = append(manyPorts, tcpPort(port))
	}
	zero := int32(0)

	tests := []struct {
		name     string
		catchAll v1alpha1.Port
	}{
		{"nil Port", v1alpha1.Port{Protocol: &CATCH_ALL_PROTOCOL}},
		{"Port pointing at 0", v1alpha1.Port{Protocol: &CATCH_ALL_PROTOCOL, Port: &zero}},
		{"nil Protocol", v1alpha1.Port{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := append([]v1alpha1.Port{tt.catchAll}, manyPorts...)
			got := mergeDuplicateL4Info(in)
			assert.Lenf(t, got, 1,
				"a fully unconditional allow subsumes every other entry, so the value must collapse "+
					"to it rather than risk truncation dropping it; got %d entries", len(got))
			assert.Equal(t, utils.ANY_IP_PROTOCOL, encodedProtocol(got[0]))
		})
	}

	t.Run("a deny-all entry blocks the collapse", func(t *testing.T) {
		in := []v1alpha1.Port{
			{Protocol: &CATCH_ALL_PROTOCOL},
			tcpPort(80),
			{Protocol: &DENY_ALL_PROTOCOL},
		}
		got := mergeDuplicateL4Info(in)
		assert.Lenf(t, got, 3,
			"collapsing past a deny-all entry would turn a deny into an allow; got %d entries", len(got))
	})
}

// TestEncodedProtocol_MatchesTrieEncoding pins encodedProtocol against the byte
// ComputeTrieValue actually writes. The slot ordering and the catch-all collapse
// both key off encodedProtocol while the datapath compares what ComputeTrieValue
// wrote, so the two must not drift.
func TestEncodedProtocol_MatchesTrieEncoding(t *testing.T) {
	unknown := corev1.Protocol("NOT_A_REAL_PROTOCOL")
	tests := []struct {
		name string
		port v1alpha1.Port
		want int
	}{
		{"nil protocol", v1alpha1.Port{}, utils.ANY_IP_PROTOCOL},
		{"TCP", tcpPort(80), utils.TCP_PROTOCOL_NUMBER},
		{"UDP", udpPort(53), utils.UDP_PROTOCOL_NUMBER},
		{"SCTP", v1alpha1.Port{Protocol: func() *corev1.Protocol { p := corev1.ProtocolSCTP; return &p }()}, utils.SCTP_PROTOCOL_NUMBER},
		{"catch all", v1alpha1.Port{Protocol: &CATCH_ALL_PROTOCOL}, utils.ANY_IP_PROTOCOL},
		{"deny all", v1alpha1.Port{Protocol: &DENY_ALL_PROTOCOL}, utils.RESERVED_IP_PROTOCOL_NUMBER},
		{"unrecognised protocol", v1alpha1.Port{Protocol: &unknown}, utils.ANY_IP_PROTOCOL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, encodedProtocol(tt.port))

			entries := decodeTrieValueEntries(utils.ComputeTrieValue([]v1alpha1.Port{tt.port}, false, false))
			assert.NotEmpty(t, entries)
			assert.Equalf(t, tt.want, entries[0].protocol,
				"ComputeTrieValue wrote protocol %d but encodedProtocol reports %d",
				entries[0].protocol, tt.want)
		})
	}
}

// TestMergeDuplicateL4Info_OrdersByBreadth pins the emitted ORDER. Order decides
// which entries survive the ebpf slot cap, so the broadest allow must come first
// and the deny-all entry last.
func TestMergeDuplicateL4Info_OrdersByBreadth(t *testing.T) {
	sctp := corev1.ProtocolSCTP
	in := []v1alpha1.Port{
		{Protocol: &DENY_ALL_PROTOCOL},
		{Protocol: &sctp, Port: func() *int32 { p := int32(9); return &p }()},
		tcpPort(80),
		udpPort(53),
		// A FULL catch-all (nil Port). With a non-zero port it would not qualify for
		// the collapse at all, and the assertion below would pass for the wrong
		// reason instead of pinning the deny-marker guard.
		{Protocol: &CATCH_ALL_PROTOCOL},
	}
	got := mergeDuplicateL4Info(in)
	assert.Len(t, got, len(in),
		"the deny-all entry must block the catch-all collapse, so every entry survives")

	var order []int
	for _, p := range got {
		order = append(order, encodedProtocol(p))
	}
	assert.Equal(t, []int{
		utils.ANY_IP_PROTOCOL,
		utils.TCP_PROTOCOL_NUMBER,
		utils.UDP_PROTOCOL_NUMBER,
		utils.SCTP_PROTOCOL_NUMBER,
		utils.RESERVED_IP_PROTOCOL_NUMBER,
	}, order, "entries must be ordered broadest-allow first, deny-all last")

	// Same start port, differing protocol: breadth still decides, not input order.
	got = mergeDuplicateL4Info([]v1alpha1.Port{
		tcpPort(443),
		{Protocol: &CATCH_ALL_PROTOCOL, Port: func() *int32 { p := int32(443); return &p }()},
	})
	assert.Len(t, got, 2)
	assert.Equalf(t, utils.ANY_IP_PROTOCOL, encodedProtocol(got[0]),
		"on an equal start port the ANY-protocol entry is broader and must sort first; got %+v", got)
}

func tcpRange(port, endPort int32) v1alpha1.Port {
	p := corev1.ProtocolTCP
	return v1alpha1.Port{Protocol: &p, Port: &port, EndPort: &endPort}
}

// TestFWRuleProcessor_BroadestAllowSurvivesSlotCap asserts the OUTCOME the breadth
// ordering exists for, rather than the ordering itself. ComputeTrieValue keeps the
// leading slots and drops the rest, so ordering only matters through that
// composition: with more entries than slots, the broadest allow must be among the
// survivors and the deny-all entry must be what falls off the end.
func TestFWRuleProcessor_BroadestAllowSurvivesSlotCap(t *testing.T) {
	// One rule far exceeding the 24-slot cap, carrying an ANY-protocol allow on a
	// specific port (broader than any TCP entry beside it) and a deny-all entry.
	l4 := []v1alpha1.Port{
		{Protocol: &CATCH_ALL_PROTOCOL, Port: func() *int32 { p := int32(9999); return &p }()},
		{Protocol: &DENY_ALL_PROTOCOL},
	}
	for port := int32(8000); port < 8040; port++ {
		l4 = append(l4, tcpPort(port))
	}
	rules := []EbpfFirewallRules{{IPCidr: "10.0.0.0/8", L4Info: l4}}

	got, err := NewFirewallRuleProcessor("192.168.1.1", "/32", false).
		ComputeMapEntriesFromEndpointRules(rules)
	assert.NoError(t, err)

	entries := entriesForCIDR(t, got, "10.0.0.0/8", false)
	assert.Truef(t, hasPortProtocol(entries, utils.ANY_IP_PROTOCOL, 9999),
		"the ANY-protocol allow is the broadest entry here and must survive truncation; got %+v", entries)
	assert.Falsef(t, hasDenyAll(entries),
		"the deny-all entry must be the one truncated away, never an allow; got %+v", entries)
}

// TestFWRuleProcessor_OverlappingPortRangesAreDeterministic covers the endPort term
// of the sort key. Two ports sharing protocol and start port but differing in
// EndPort are distinct entries, so without endPort in the comparator the ordering is
// a tie that Go's unstable sort resolves from map iteration order, and which entries
// survive the slot cap then varies between reconciles of identical input.
func TestFWRuleProcessor_OverlappingPortRangesAreDeterministic(t *testing.T) {
	rules := []EbpfFirewallRules{
		{IPCidr: "10.20.0.0/16", L4Info: []v1alpha1.Port{
			tcpRange(8000, 8010),
			tcpRange(8000, 8020),
			tcpRange(8000, 8030),
		}},
	}

	f := NewFirewallRuleProcessor("192.168.1.1", "/32", false)
	want, err := f.ComputeMapEntriesFromEndpointRules(append([]EbpfFirewallRules{}, rules...))
	assert.NoError(t, err)

	for i := 0; i < 200; i++ {
		got, err := f.ComputeMapEntriesFromEndpointRules(append([]EbpfFirewallRules{}, rules...))
		assert.NoError(t, err)
		for key, wantValue := range want {
			assert.Truef(t, bytes.Equal(wantValue, got[key]),
				"iteration %d: overlapping port ranges encoded differently for key %x; "+
					"the sort key must order on endPort as well as start port", i, []byte(key))
		}
	}

	// All three ranges must be present and distinguishable by their end port.
	entries := entriesForCIDR(t, want, "10.20.0.0/16", false)
	var ends []int
	for _, e := range entries {
		if e.protocol == utils.TCP_PROTOCOL_NUMBER && e.startPort == 8000 {
			ends = append(ends, e.endPort)
		}
	}
	assert.Equalf(t, []int{8010, 8020, 8030}, ends,
		"the three ranges must be retained and ordered by end port; got entries %+v", entries)
}

// TestFWRuleProcessor_DoesNotMutateCallerExceptSlice pins the zero-capacity reslice
// used when normalizing except lists. With a plain [:0] the normalizer writes the
// canonicalized entries back through the caller's backing array, mutating the
// PolicyEndpoint-derived rules it was handed.
func TestFWRuleProcessor_DoesNotMutateCallerExceptSlice(t *testing.T) {
	except := []v1alpha1.NetworkAddress{"10.1.1.1", "10.2.2.2"}
	before := append([]v1alpha1.NetworkAddress{}, except...)
	rules := []EbpfFirewallRules{
		{IPCidr: "0.0.0.0/0", Except: except, L4Info: []v1alpha1.Port{tcpPort(443)}},
	}

	_, err := NewFirewallRuleProcessor("192.168.1.1", "/32", false).
		ComputeMapEntriesFromEndpointRules(rules)
	assert.NoError(t, err)

	assert.Equalf(t, before, except,
		"the caller's except slice must not be rewritten in place; got %v, want %v", except, before)
}

// TestMergeDuplicateL4Info_CollapseIsCanonical covers the collapse's output shape.
// The predicate does not look at EndPort, so more than one entry can qualify while
// encoding to different bytes. Returning whichever qualifying entry came last in map
// order made identical input encode differently between reconciles.
func TestMergeDuplicateL4Info_CollapseIsCanonical(t *testing.T) {
	endPort := int32(100)
	rules := []EbpfFirewallRules{
		{IPCidr: "10.0.0.0/8"},
		{IPCidr: "10.0.0.0/8", L4Info: []v1alpha1.Port{{EndPort: &endPort}}},
	}

	f := NewFirewallRuleProcessor("192.168.1.1", "/32", false)
	seen := map[string]int{}
	for i := 0; i < 300; i++ {
		got, err := f.ComputeMapEntriesFromEndpointRules(append([]EbpfFirewallRules{}, rules...))
		assert.NoError(t, err)
		seen[fmt.Sprint(entriesForCIDR(t, got, "10.0.0.0/8", false))]++
	}
	assert.Lenf(t, seen, 1,
		"two entries qualify as the catch-all here and encode differently, so the collapse must "+
			"emit a canonical entry rather than whichever won the map-iteration race; saw %v", seen)
	for encoding := range seen {
		assert.Equalf(t, fmt.Sprint([]trieEntry{{protocol: utils.ANY_IP_PROTOCOL}}), encoding,
			"the collapsed entry must be the canonical unconditional allow")
	}
}
