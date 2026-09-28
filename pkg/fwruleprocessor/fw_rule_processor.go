package fwruleprocessor

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	corev1 "k8s.io/api/core/v1"
)

func log() logger.Logger {
	return logger.Get()
}

var (
	CATCH_ALL_PROTOCOL            corev1.Protocol = "ANY_IP_PROTOCOL"
	DENY_ALL_PROTOCOL             corev1.Protocol = "RESERVED_IP_PROTOCOL_NUMBER"
	BASELINE_TIER_PRIORITY_OFFSET int             = 2000 // Baseline cluster policy rules will have priority offset of 2000
)

type EbpfFirewallRules struct {
	Priority   int
	Action     v1alpha1.ClusterNetworkPolicyRuleAction
	DomainName string
	IPCidr     v1alpha1.NetworkAddress
	Except     []v1alpha1.NetworkAddress
	L4Info     []v1alpha1.Port
}

type FirewallRuleProcessor struct {
	// Primary IP of the node
	nodeIP   string
	hostMask string
	// Flag to track the IPv6 mode
	enableIPv6 bool
}

func NewFirewallRuleProcessor(nodeIP string, hostMask string, enableIPv6 bool) *FirewallRuleProcessor {
	fwrp := &FirewallRuleProcessor{
		nodeIP:     nodeIP,
		hostMask:   hostMask,
		enableIPv6: enableIPv6,
	}
	return fwrp
}

// computeMapEntriesFromEndpointRules generates a map of IP prefix keys to encoded L4 rules that will
// be used to update ebpf maps
//
// How it works:
//   1. A default allow-all entry is added for the node IP to ensure local node traffic is always permitted.
//   2. The list of firewall rules is sorted by prefix length in ascending order. This is crucial for
//      handling overlapping CIDRs because longest-prefix matches win in LPM TRIE.
//   3. Each rule is normalized:
//        - Ensures all entries contain a /mask (using hostMask if omitted).
//        - Filters out IPv4 rules in IPv6 clusters and vice versa.
//        - For rules without any L4 port info, a catch-all rule is inserted to match all traffic.
//        - Normalizes the rule's `except` list the same way (mask defaulted, canonicalized,
//          unparseable entries dropped), so every later consumer sees canonical CIDRs.
//   4. For any rule whose CIDR is more specific (e.g., /24) and falls within a broader one (e.g., /16),
//      we walk a containment trie for every CIDR that contains it. Each rule recorded against a
//      containing CIDR is tested INDEPENDENTLY: that rule donates its ports only if its own
//      "except" list does not cover the current CIDR. Testing per rule matters because several
//      rules can share one CIDR with different port sets and different except lists, so a merged
//      view would pair one rule's ports with another rule's excepts.
//   5. We then handle all `except` CIDRs at the end. An `except` is scoped to the rule
//      that lists it, and rules are additive (a union of allows), so an except CIDR
//      inherits the ports of every OTHER rule that contains it and does not itself
//      except it. It gets a deny-all L4 entry only when there is nothing to inherit,
//      which keeps the entry non-empty so ComputeTrieValue does not fall back to
//      allow-all. Either way its longer prefix wins the LPM match over the broader
//      rule, which is what carves it out.
//   6. Finally, all CIDRs are encoded into trie keys and their corresponding merged/derived L4 info is encoded
//      into the values, forming the output map.

func (f *FirewallRuleProcessor) ComputeMapEntriesFromEndpointRules(firewallRules []EbpfFirewallRules) (map[string][]byte, error) {

	firewallMap := make(map[string][]byte)
	cidrsMap := make(map[string]EbpfFirewallRules)
	exceptCidrs := make(map[string]struct{})
	// Every rule seen for a given CIDR is kept separately, un-merged: a CIDR can
	// appear in several rules with different port sets AND different except
	// lists, and inheritance has to test each (ports, except) pair on its own.
	nonHostCIDRs := make(map[string][]EbpfFirewallRules)
	containmentTrie := newCIDRTrie()

	//Traffic from the local node should always be allowed. Add NodeIP by default to map entries.
	_, mapKey, _ := net.ParseCIDR(f.nodeIP + f.hostMask)
	key := utils.ComputeTrieKey(*mapKey, f.enableIPv6)
	value := utils.ComputeTrieValue([]v1alpha1.Port{}, true, false)
	firewallMap[string(key)] = value

	//Sort the rules
	sortFirewallRulesByPrefixLength(firewallRules, f.hostMask)

	for _, firewallRule := range firewallRules {
		var cidrL4Info []v1alpha1.Port

		if !strings.Contains(string(firewallRule.IPCidr), "/") {
			firewallRule.IPCidr += v1alpha1.NetworkAddress(f.hostMask)
		}

		// Canonicalize the CIDR (mask off host bits) before it is used as the
		// cidrsMap key. A rule expressed with host bits set - e.g. 10.161.0.0/8,
		// which a /8 mask reduces to the network 10.0.0.0/8 - would otherwise be
		// keyed by its raw string and treated as distinct from 10.0.0.0/8. Their
		// L4 (port) sets would never be merged, and because both encode to the
		// identical LPM trie key, the final map write silently overwrites one
		// with the other in Go's randomized map-iteration order, producing
		// non-deterministic port enforcement across reconciliations. Masking here
		// makes such rules share a key so their ports are merged deterministically.
		if _, ipNet, err := net.ParseCIDR(string(firewallRule.IPCidr)); err == nil {
			firewallRule.IPCidr = v1alpha1.NetworkAddress(ipNet.String())
		}

		if f.shouldSkipRule(string(firewallRule.IPCidr)) {
			continue
		}

		// Normalize the except list in place before anything consumes it. An except
		// may be authored as a bare address (the CRD does not require a mask). Left
		// raw it breaks two things: net.ParseCIDR fails in the except-match
		// predicate below, so the entry silently fails to suppress inherited ports,
		// and the map-emit loop dereferences a nil *net.IPNet -> agent panic.
		normalizedExcept := firewallRule.Except[:0:0]
		for _, exceptCidr := range firewallRule.Except {
			e := string(exceptCidr)
			if !strings.Contains(e, "/") {
				e += f.hostMask
			}
			_, eNet, err := net.ParseCIDR(e)
			if err != nil || eNet == nil {
				log().Warnf("Skipping unparseable except CIDR %q on rule %s", string(exceptCidr), string(firewallRule.IPCidr))
				continue
			}
			normalizedExcept = append(normalizedExcept, v1alpha1.NetworkAddress(eNet.String()))
		}
		firewallRule.Except = normalizedExcept

		// Track this rule's except CIDRs to handle later.
		for _, exceptCidr := range firewallRule.Except {
			exceptCidrs[string(exceptCidr)] = struct{}{}
		}

		// If no L4 specified add catch all entry
		if len(firewallRule.L4Info) == 0 {
			log().Debugf("No L4 specified. Add Catch all entry CIDR: %s", string(firewallRule.IPCidr))
			addCatchAllL4Entry(&firewallRule)
		}

		// Snapshot the rule exactly as authored (before any cross-rule merging)
		// so inheritance can later pair this rule's ports with this rule's own
		// except list.
		ownRule := firewallRule
		ownRule.L4Info = append([]v1alpha1.Port{}, firewallRule.L4Info...)
		ownRule.Except = append([]v1alpha1.NetworkAddress{}, firewallRule.Except...)

		if existingFirewallRuleInfo, ok := cidrsMap[string(firewallRule.IPCidr)]; ok {
			// Only L4Info is merged. The except lists are deliberately NOT merged:
			// suppression reads the per-rule ownRule snapshots in nonHostCIDRs so that
			// each rule's ports are tested against that same rule's excepts. Merging
			// them here is what previously paired one rule's ports with another rule's
			// excepts and defeated inheritance.
			firewallRule.L4Info = append(firewallRule.L4Info, existingFirewallRuleInfo.L4Info...)
		} else {
			cidrL4Info = checkAndDeriveL4InfoFromAnyMatchingCIDRsTrie(string(firewallRule.IPCidr), containmentTrie, nonHostCIDRs)
			if len(cidrL4Info) > 0 {
				firewallRule.L4Info = append(firewallRule.L4Info, cidrL4Info...)
			}
		}
		cidrsMap[string(firewallRule.IPCidr)] = firewallRule
		if utils.IsNonHostCIDR(string(firewallRule.IPCidr)) {
			_, alreadyInTrie := nonHostCIDRs[string(firewallRule.IPCidr)]
			nonHostCIDRs[string(firewallRule.IPCidr)] = append(nonHostCIDRs[string(firewallRule.IPCidr)], ownRule)
			if !alreadyInTrie {
				containmentTrie.insert(string(firewallRule.IPCidr))
			}
		}
	}

	// Go through except CIDRs and append DENY all rule to the L4 info
	for exceptCidr := range exceptCidrs {
		// Already normalized and canonical at ingestion.
		// Same gates the rule loop applies: a wrong-family except would otherwise
		// be reinterpreted in the cluster's family (a v4 except in a v6 cluster
		// emitted keys like a00::/8, hard-denying unrelated v6 space), and an
		// except naming the node IP would overwrite the unconditional node
		// allow-all seeded above and break kubelet probes.
		if f.shouldSkipExcept(exceptCidr) {
			log().Debugf("Skipping except CIDR (wrong family, or it is the node's host route): %s", exceptCidr)
			continue
		}
		if _, ok := cidrsMap[exceptCidr]; !ok {
			exceptFirewall := EbpfFirewallRules{
				IPCidr: v1alpha1.NetworkAddress(exceptCidr),
				Except: []v1alpha1.NetworkAddress{},
				L4Info: []v1alpha1.Port{},
			}
			// An except CIDR is only carved out of the rule that listed it.
			// Any *other* rule whose CIDR contains this one and which does not
			// except it still allows its ports here, because egress rules are
			// additive (a union of allows), so inherit those first.
			inherited := checkAndDeriveL4InfoFromAnyMatchingCIDRsTrie(exceptCidr, containmentTrie, nonHostCIDRs)
			if len(inherited) > 0 {
				// Emit only the inherited allows. Ports not listed here fall
				// through the datapath loop to its default, DENY, so the
				// deny-all marker is not needed -- and must not be added,
				// because the datapath returns DENY the moment it sees it.
				// Caveat: that fallthrough is not absolute for IP protocol 0.
				// ComputeTrieValue zero-fills the unused slots of every value, a zero
				// slot decodes as {protocol:0, start_port:0}, and the datapath compares
				// trie_val->protocol against the packet's IP protocol, so a protocol-0
				// packet matches the tail. handle_egress assigns flow_key.protocol
				// unconditionally and its protocol switch has no default arm, so such a
				// packet does reach the evaluator. This is a pre-existing property of
				// every non-except entry on main, not one introduced here, and closing
				// it needs a datapath change.
				exceptFirewall.L4Info = append(exceptFirewall.L4Info, inherited...)
			} else {
				// Nothing to allow here. The deny-all marker keeps the entry
				// non-empty so ComputeTrieValue does not fall back to allow-all.
				addDenyAllL4Entry(&exceptFirewall)
			}
			cidrsMap[exceptCidr] = exceptFirewall
		}
		log().Debugf("Parsed Except CIDR (already canonical): %s", exceptCidr)
	}

	for key, value := range cidrsMap {
		log().Infof("Updating Map with IP Key: %s", string(key))
		_, firewallMapKey, _ := net.ParseCIDR(string(key))
		// Key format: Prefix length (4 bytes) followed by 4/16byte IP address
		firewallKey := utils.ComputeTrieKey(*firewallMapKey, f.enableIPv6)

		if len(value.L4Info) != 0 {
			value.L4Info = mergeDuplicateL4Info(value.L4Info)
		}
		firewallMap[string(firewallKey)] = utils.ComputeTrieValue(value.L4Info, false, false)
	}

	return firewallMap, nil
}

// sorting Firewall Rules in Ascending Order of Prefix length
// SliceStable is used so that rules sharing the same prefix length retain a
// deterministic relative order; this keeps the L4-info inheritance in
// checkAndDeriveL4InfoFromAnyMatchingCIDRs stable across runs.
func sortFirewallRulesByPrefixLength(rules []EbpfFirewallRules, prefixLenStr string) {
	sort.SliceStable(rules, func(i, j int) bool {

		prefixSplit := strings.Split(prefixLenStr, "/")
		prefixLen, _ := strconv.Atoi(prefixSplit[1])
		prefixLenIp1 := prefixLen
		prefixLenIp2 := prefixLen

		if strings.Contains(string(rules[i].IPCidr), "/") {
			prefixIp1 := strings.Split(string(rules[i].IPCidr), "/")
			prefixLenIp1, _ = strconv.Atoi(prefixIp1[1])

		}

		if strings.Contains(string(rules[j].IPCidr), "/") {

			prefixIp2 := strings.Split(string(rules[j].IPCidr), "/")
			prefixLenIp2, _ = strconv.Atoi(prefixIp2[1])
		}

		return prefixLenIp1 < prefixLenIp2
	})
}

func addCatchAllL4Entry(firewallRule *EbpfFirewallRules) {
	catchAllL4Entry := v1alpha1.Port{
		Protocol: &CATCH_ALL_PROTOCOL,
	}
	firewallRule.L4Info = append(firewallRule.L4Info, catchAllL4Entry)
}

func addDenyAllL4Entry(firewallRule *EbpfFirewallRules) {
	denyAllL4Entry := v1alpha1.Port{
		Protocol: &DENY_ALL_PROTOCOL,
	}
	firewallRule.L4Info = append(firewallRule.L4Info, denyAllL4Entry)
}

func checkAndDeriveL4InfoFromAnyMatchingCIDRsTrie(firewallRule string,
	trie *cidrTrie, nonHostCIDRs map[string][]EbpfFirewallRules) []v1alpha1.Port {
	var matchingCIDRL4Info []v1alpha1.Port

	_, ipToCheck, err := net.ParseCIDR(firewallRule)
	if err != nil || ipToCheck == nil {
		return matchingCIDRL4Info
	}

	// findContainingKeys walks the full address width, so it also returns keys
	// that are strict SUBNETS of the query when they share its network address
	// (e.g. querying 10.0.0.0/8 returns 10.0.0.0/24). A subnet does not contain
	// the query and must never donate ports to it - doing so would allow the
	// subnet's ports across the whole enclosing block. The guard is applied
	// unconditionally at both call sites rather than relying on processing order:
	// sortFirewallRulesByPrefixLength splits the raw IPCidr string without
	// canonicalizing, so a v4-mapped form like ::ffff:10.0.0.0/104 sorts as 104 and
	// would be processed after v4 prefixes that are its own subnets.
	queryOnes, _ := ipToCheck.Mask.Size()
	containingKeys := trie.findContainingKeys(ipToCheck.IP)

	for _, cidrKey := range containingKeys {
		_, keyNet, keyErr := net.ParseCIDR(cidrKey)
		if keyErr != nil || keyNet == nil {
			continue
		}
		keyOnes, _ := keyNet.Mask.Size()
		if keyOnes > queryOnes || !keyNet.Contains(ipToCheck.IP) {
			continue
		}
		// Each rule on this CIDR is tested independently: its except list only
		// suppresses the ports that same rule contributed.
		for _, cidrFirewallInfo := range nonHostCIDRs[cidrKey] {
			foundInExcept := false
			for _, except := range cidrFirewallInfo.Except {
				_, exceptEntry, _ := net.ParseCIDR(string(except))
				if exceptEntry == nil {
					continue
				}
				// Mirror of the donor-side guard above. Contains() tests a single
				// representative address, so an except that is a strict subset of
				// the query - aligned at the query's network address - would
				// otherwise suppress this donor across the whole query block. Only
				// an except that covers the query as a whole carves it out; a
				// narrower except gets its own longer-prefix key in the except pass.
				exceptOnes, _ := exceptEntry.Mask.Size()
				if exceptOnes <= queryOnes && exceptEntry.Contains(ipToCheck.IP) {
					foundInExcept = true
					break
				}
			}
			if !foundInExcept {
				matchingCIDRL4Info = append(matchingCIDRL4Info, cidrFirewallInfo.L4Info...)
			}
		}
	}
	return matchingCIDRL4Info
}

func mergeDuplicateL4Info(ports []v1alpha1.Port) []v1alpha1.Port {
	type portKey struct {
		protocol string
		port     int
		endPort  int
	}
	uniquePorts := make(map[portKey]v1alpha1.Port, len(ports))
	result := make([]v1alpha1.Port, 0, len(ports))

	for _, p := range ports {

		pk := portKey{}

		if p.Port != nil {
			pk.port = int(*p.Port)
		}

		if p.EndPort != nil {
			pk.endPort = int(*p.EndPort)
		}
		if p.Protocol != nil {
			pk.protocol = string(*p.Protocol)
		}

		if _, ok := uniquePorts[pk]; ok {
			continue
		} else {
			uniquePorts[pk] = p
		}
	}

	for _, port := range uniquePorts {
		result = append(result, port)
	}

	// An entry encoding to ANY_IP_PROTOCOL with start port 0 matches unconditionally
	// in the datapath, so every other allow in the same value is dead weight. The
	// predicate deliberately ignores EndPort: the datapath tests start_port ==
	// ANY_PORT as its first disjunct and short-circuits, so end_port is never read
	// for such an entry. Collapsing keeps the broadest allow from being the entry
	// discarded when the value exceeds the ebpf 24-entry cap.
	hasDenyMarker := false
	catchAllIdx := -1
	for i, pt := range result {
		proto := encodedProtocol(pt)
		if proto == utils.RESERVED_IP_PROTOCOL_NUMBER {
			hasDenyMarker = true
			continue
		}
		startPort := int32(0)
		if pt.Port != nil {
			startPort = *pt.Port
		}
		// Test the ENCODED triple rather than the Go representation: a nil Port and
		// a pointer to 0 both encode to start_port 0, and a nil Protocol encodes to
		// ANY_IP_PROTOCOL, so all three are unconditional allows.
		if proto == utils.ANY_IP_PROTOCOL && startPort == 0 {
			catchAllIdx = i
		}
	}
	if catchAllIdx >= 0 && !hasDenyMarker {
		// Return a canonical entry rather than result[catchAllIdx]. The predicate does
		// not look at EndPort, so more than one entry can qualify while encoding to
		// different bytes (e.g. {nil Protocol, EndPort:100} alongside the synthesized
		// catch-all), and catchAllIdx keeps whichever came last in map order. Emitting
		// the canonical form keeps the output byte-stable for every qualifying shape.
		return []v1alpha1.Port{{Protocol: &CATCH_ALL_PROTOCOL}}
	}

	// Sort so the emitted order is stable. uniquePorts is a Go map, and values
	// longer than the ebpf 24-entry cap get truncated by ComputeTrieValue, so an
	// unstable order would make the ENFORCED subset differ between reconciles of
	// identical input.
	sort.SliceStable(result, func(i, j int) bool {
		pi, pj := portSortKey(result[i]), portSortKey(result[j])
		if pi[0] != pj[0] {
			return pi[0] < pj[0]
		}
		if pi[1] != pj[1] {
			return pi[1] < pj[1]
		}
		return pi[2] < pj[2]
	})

	return result
}

// encodedProtocol returns the protocol byte ComputeTrieValue will write for this
// Port. It mirrors utils.deriveProtocolValue, including its treatment of a nil or
// unrecognised Protocol as ANY_IP_PROTOCOL, so the sort key and the catch-all test
// can never disagree with what the datapath actually compares.
func encodedProtocol(p v1alpha1.Port) int {
	if p.Protocol == nil {
		return utils.ANY_IP_PROTOCOL
	}
	switch *p.Protocol {
	case corev1.ProtocolTCP:
		return utils.TCP_PROTOCOL_NUMBER
	case corev1.ProtocolUDP:
		return utils.UDP_PROTOCOL_NUMBER
	case corev1.ProtocolSCTP:
		return utils.SCTP_PROTOCOL_NUMBER
	case DENY_ALL_PROTOCOL:
		return utils.RESERVED_IP_PROTOCOL_NUMBER
	default:
		// CATCH_ALL_PROTOCOL and anything unrecognised.
		return utils.ANY_IP_PROTOCOL
	}
}

// portSortKey yields a total order over a Port: breadth, then start, then end.
//
// The primary key is a BREADTH rank, not the encoded protocol byte. Truncation at
// the ebpf 24-entry cap drops whatever sorts last, so the order has to put the
// broadest allows out of harm's way: an ANY-protocol entry covers strictly more
// traffic than a TCP/UDP/SCTP one on the same port, and the deny-all marker must
// sort last of all so a truncation never discards an allow in favour of it. Using
// the raw protocol byte inverted this, because ANY_IP_PROTOCOL is 254 and so ranked
// second-to-last, making the broadest allow the first entry discarded.
//
// encodedProtocol stays the single source of truth for what the datapath compares;
// only this ordering is remapped.
func portSortKey(p v1alpha1.Port) [3]int {
	k := [3]int{}
	switch proto := encodedProtocol(p); proto {
	case utils.ANY_IP_PROTOCOL:
		k[0] = 0 // broadest allow: sorts first, truncated last
	case utils.RESERVED_IP_PROTOCOL_NUMBER:
		k[0] = 1 << 16 // deny marker: sorts last
	default:
		k[0] = proto // 6, 17, 132 - all above ANY, all below the marker
	}
	if p.Port != nil {
		k[1] = int(*p.Port)
	}
	if p.EndPort != nil {
		k[2] = int(*p.EndPort)
	}
	return k
}

func (f *FirewallRuleProcessor) ComputeClusterPolicyMapEntriesFromEndpointRules(firewallRules []EbpfFirewallRules) (map[string][]byte, error) {
	firewallMap := make(map[string][]byte)
	cidrL4Rules := make(map[string][]utils.L4Rule)
	processedCIDRs := make([]string, 0)

	// Traffic from the local node should always be allowed. Add NodeIP by default to map entries.
	// This ensures kubelet liveness/readiness probes are never blocked by cluster network policies.
	_, mapKey, _ := net.ParseCIDR(f.nodeIP + f.hostMask)
	key := utils.ComputeTrieKey(*mapKey, f.enableIPv6)
	nodeIPL4Rule := []utils.L4Rule{
		{
			Action:   "Accept",
			Priority: 0, // Highest priority — node-IP allow must not be overridden
		},
	}
	value := utils.ComputeTrieValueForCPE(nodeIPL4Rule)
	firewallMap[string(key)] = value

	// Step 1: Sort by CIDR length
	f.sortByCIDRLength(firewallRules)

	// Step 2-3: Process each CIDR and handle overlaps
	for _, rule := range firewallRules {

		cidr := f.normalizeCIDR(string(rule.IPCidr))
		if f.shouldSkipRule(cidr) {
			continue
		}

		// Find the most specific overlapping CIDR
		overlappingCIDR := f.findMostSpecificOverlap(cidr, processedCIDRs)

		// Copy L4 rules from overlapping CIDR if found
		if overlappingCIDR != "" {
			cidrL4Rules[cidr] = append(cidrL4Rules[cidr], cidrL4Rules[overlappingCIDR]...)
		}

		// If this current rule doesn't have any port/protocol, the rule is not specific to any port/protocol
		if len(rule.L4Info) == 0 {
			log().Info("cluster policy endpoint rule processsing: No rule for port so adding catch all ports")
			cidrL4Rules[cidr] = append(cidrL4Rules[cidr], utils.L4Rule{
				Action:   rule.Action,
				Priority: rule.Priority,
			})
		}

		// Add current rule's L4 info
		for _, port := range rule.L4Info {
			l4Rule := utils.L4Rule{
				L4PortProtocolInfo: port,
				Action:             rule.Action,
				Priority:           rule.Priority,
			}
			cidrL4Rules[cidr] = append(cidrL4Rules[cidr], l4Rule)
		}
		processedCIDRs = append(processedCIDRs, cidr)
	}

	// Step 4: Resolve conflicts and create final map entries
	for cidr, l4Rules := range cidrL4Rules {
		log().Infof("cluster policy firewall rule processing complete: CIDR: %+v, Rules Count: %d", cidr, len(l4Rules))
		resolvedL4Rules := f.removeDuplicateL4Rules(l4Rules)

		_, firewallMapKey, _ := net.ParseCIDR(cidr)
		firewallKey := utils.ComputeTrieKey(*firewallMapKey, f.enableIPv6)

		firewallValue := utils.ComputeTrieValueForCPE(resolvedL4Rules)
		firewallMap[string(firewallKey)] = firewallValue
	}

	return firewallMap, nil
}

func (f *FirewallRuleProcessor) normalizeCIDR(cidr string) string {
	if !strings.Contains(cidr, "/") {
		cidr = cidr + f.hostMask
	}
	if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
		return ipNet.String()
	}
	return cidr
}

// shouldSkipExcept gates the except pass. It deliberately does NOT reuse
// shouldSkipRule, because utils.IsNodeIP compares the node IP against a CIDR's
// NETWORK address with no host-route check. Reusing it dropped every except whose
// first address happened to be the node IP - on a node at 10.0.1.128 the except
// 10.0.1.128/25 was deleted entirely, leaving the enclosing rule's ports allowed
// across all 127 other addresses in the excepted block.
//
// Only an except that is exactly the node's host route can collide with the node
// allow-all seeded at the top of ComputeMapEntriesFromEndpointRules, because only
// that one encodes to the same LPM key. Anything broader loses to the /32 (or
// /128) by longest-prefix match, so it is safe - and necessary - to emit.
func (f *FirewallRuleProcessor) shouldSkipExcept(cidr string) bool {
	if f.enableIPv6 != isIPv6(cidr) {
		return true
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil || ipNet == nil {
		return true
	}
	ones, bits := ipNet.Mask.Size()
	return ones == bits && utils.IsNodeIP(f.nodeIP, cidr)
}

func (f *FirewallRuleProcessor) shouldSkipRule(cidr string) bool {
	if utils.IsNodeIP(f.nodeIP, cidr) {
		return true
	}
	isIPv6CIDR := isIPv6(cidr)
	if f.enableIPv6 && !isIPv6CIDR {
		log().Debugf("Skipping ipv4 rule in ipv6 cluster CIDR: %s", cidr)
		return true
	}
	if !f.enableIPv6 && isIPv6CIDR {
		log().Debugf("Skipping ipv6 rule in ipv4 cluster CIDR: %s", cidr)
		return true
	}
	return false
}

func (f *FirewallRuleProcessor) sortByCIDRLength(rules []EbpfFirewallRules) {
	sort.SliceStable(rules, func(i, j int) bool {
		cidrI := f.normalizeCIDR(string(rules[i].IPCidr))
		cidrJ := f.normalizeCIDR(string(rules[j].IPCidr))

		prefixI := f.getPrefixLength(cidrI)
		prefixJ := f.getPrefixLength(cidrJ)

		return prefixI < prefixJ // Bigger to smaller (/16 before /32)
	})
}

func (f *FirewallRuleProcessor) getPrefixLength(cidr string) int {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return 32 // Default for IPv4
	}
	prefixLen, _ := strconv.Atoi(parts[1])
	return prefixLen
}

func (f *FirewallRuleProcessor) findMostSpecificOverlap(currentCIDR string, processedCIDRs []string) string {
	_, currentNet, _ := net.ParseCIDR(currentCIDR)

	// Loop from end to start since CIDRs are sorted in ascending order
	for i := len(processedCIDRs) - 1; i >= 0; i-- {
		processedCIDR := processedCIDRs[i]
		_, processedNet, _ := net.ParseCIDR(processedCIDR)

		// Check if current CIDR is contained within processed CIDR
		if processedNet.Contains(currentNet.IP) {
			return processedCIDR
		}
	}

	return ""
}

func (f *FirewallRuleProcessor) removeDuplicateL4Rules(l4Rules []utils.L4Rule) []utils.L4Rule {

	uniquePorts := make(map[string]utils.L4Rule)
	var result []utils.L4Rule
	var key string

	for _, p := range l4Rules {

		portKey := 0
		endPortKey := 0

		if p.L4PortProtocolInfo.Port != nil {
			portKey = int(*p.L4PortProtocolInfo.Port)
		}

		if p.L4PortProtocolInfo.EndPort != nil {
			endPortKey = int(*p.L4PortProtocolInfo.EndPort)
		}

		if p.L4PortProtocolInfo.Protocol == nil {
			key = fmt.Sprintf("%s-%d-%d-%d-%s", "TCP", portKey, endPortKey, p.Priority, p.Action)
		} else {
			key = fmt.Sprintf("%v-%d-%d-%d-%s", p.L4PortProtocolInfo.Protocol, portKey, endPortKey, p.Priority, p.Action)
		}

		if _, ok := uniquePorts[key]; ok {
			continue
		} else {
			uniquePorts[key] = p
		}
	}

	for _, rule := range uniquePorts {
		result = append(result, rule)
	}

	return result
}

// isIPv6 returns true if the given CIDR or IP address is IPv6.
func isIPv6(cidr string) bool {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		ip = net.ParseIP(cidr)
	}
	return ip != nil && ip.To4() == nil
}
