package policy

import (
	"fmt"
	"net"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
)

func printNetworkPolicyYAML(np *network.NetworkPolicy) {
	bytes, err := yaml.Marshal(np)
	if err != nil {
		fmt.Printf("ERROR: Failed to marshal NetworkPolicy: %v\n", err)
		return
	}
	fmt.Printf("Applied NetworkPolicy YAML:\n%s\n", string(bytes))
}

// probeAttempts bounds the retry in tcpProbeWithRetry below.
const probeAttempts = 3

// tcpProbeWithRetry retries the exec, not the verdict. TCPProbe reaches the kubelet
// through the apiserver and fails transiently, and a non-nil error inside a
// Consistently window fails the whole window immediately, reporting an enforcement
// change that never happened. Only a successful probe's verdict is returned, so a
// retry can never turn a real CLOSE into an OPEN. Mirrors execInPod in
// test/integration/ebpf/conntrack_poisoning_test.go, keeping the retry local to the
// spec rather than changing the shared PodManager used by other suites.
func tcpProbeWithRetry(ns, pod, ip string, port int) (string, error) {
	var out string
	var err error
	for attempt := 1; attempt <= probeAttempts; attempt++ {
		out, err = fw.PodManager.TCPProbe(ns, pod, ip, port)
		if err == nil {
			return out, nil
		}
		GinkgoWriter.Printf("TCPProbe to %s:%d attempt %d/%d failed: %v\n", ip, port, attempt, probeAttempts, err)
		time.Sleep(utils.ProbeInterval)
	}
	return "", err
}

type ipFamilyConfig struct {
	maskLen    int
	catchAll   string
	extProbeIP string
	hostMask   string
}

// ipFamilyConfigForIP derives the except-block settings from the server pod IP.
// EKS clusters are single-stack, so the pod IP's family is the cluster's family.
func ipFamilyConfigForIP(ip string) ipFamilyConfig {
	if net.ParseIP(ip).To4() == nil {
		return ipFamilyConfig{
			maskLen:    64,
			catchAll:   "::/0",
			extProbeIP: "2001:4860:4860::8888",
			hostMask:   "/128",
		}
	}
	return ipFamilyConfig{
		maskLen:    16,
		catchAll:   "0.0.0.0/0",
		extProbeIP: "8.8.8.8",
		hostMask:   "/32",
	}
}

// getPrefix computes the network prefix for the given IP and mask length,
// masking against the address's native bit width (32 for IPv4, 128 for IPv6).
func getPrefix(ipStr string, maskLen int) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %s", ipStr)
	}
	bits := 128
	if v4 := ip.To4(); v4 != nil {
		ip = v4
		bits = 32
	}
	mask := net.CIDRMask(maskLen, bits)
	network := ip.Mask(mask)
	return fmt.Sprintf("%s/%d", network.String(), maskLen), nil
}

// hostMask returns the single-host CIDR suffix for the cluster's IP family —
// "/32" for IPv4, "/128" for IPv6. A "/32" suffix is rejected by the API server
// on IPv6 addresses.
func hostMask(ipFamily string) string {
	if ipFamily == "IPv6" {
		return "/128"
	}
	return "/32"
}

var _ = Describe("IPBlock Except Test Cases", func() {
	var (
		serverPod       *v1.Pod
		clientPod       *v1.Pod
		serverIP        string
		serverName      = "ipblock-server"
		clientName      = "ipblock-client"
		serverNamespace = "server"
		clientNamespace = "client"
		policy          *network.NetworkPolicy
		allowPort       int = 3306
		blockPort       int = 3307
	)

	BeforeEach(func() {
		By("Deploying a sample TCP server on ports 3306 & 3307", func() {
			err := fw.NamespaceManager.CreateNamespace(ctx, serverNamespace)
			Expect(err).ToNot(HaveOccurred())
			// Per-port re-listen loop: busybox nc -l exits after one connection.
			cmd := fmt.Sprintf(
				"while true; do nc -l -p %d; done & while true; do nc -l -p %d; done & wait",
				allowPort, blockPort,
			)
			srv := manifest.NewBusyBoxContainerBuilder().
				ImageRepository(fw.Options.TestImageRegistry).
				Command([]string{"/bin/sh", "-c"}).
				Args([]string{cmd}).
				Build()

			serverPod = manifest.NewDefaultPodBuilder().
				Name(serverName).
				Namespace(serverNamespace).
				AddLabel("app", serverName).
				Container(srv).
				Build()

			pod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, serverPod, 1*time.Minute)
			Expect(err).ToNot(HaveOccurred())
			serverIP = pod.Status.PodIP
		})
	})

	// deployClient creates an idle pod we exec probes into via Eventually.
	deployClient := func(clientName string) *v1.Pod {
		ctnr := manifest.NewBusyBoxContainerBuilder().
			ImageRepository(fw.Options.TestImageRegistry).
			Command([]string{"/bin/sh", "-c"}).
			Args([]string{"sleep 1000000"}).
			Build()

		clientPod = manifest.NewDefaultPodBuilder().
			Name(clientName).
			Namespace(clientNamespace).
			AddLabel("app", clientName).
			Container(ctnr).
			Build()

		pod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, 2*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		return pod
	}

	Context("CIDR and Except overlap: server-prefix allow on 3306 + catch-all except server-prefix", func() {
		BeforeEach(func() {
			By("Applying network policy with server-prefix allow and except rule")
			err := fw.NamespaceManager.CreateNamespace(ctx, clientNamespace)
			Expect(err).ToNot(HaveOccurred())
			cfg := ipFamilyConfigForIP(serverIP)
			prefix, err := getPrefix(serverIP, cfg.maskLen)
			Expect(err).ToNot(HaveOccurred())

			firstRule := manifest.NewEgressRuleBuilder().
				AddPeer(nil, nil, prefix).
				AddPort(allowPort, v1.ProtocolTCP).
				Build()

			secondRule := manifest.NewEgressRuleBuilder().
				AddPeer(nil, nil, cfg.catchAll, prefix).
				Build()

			policy = manifest.NewNetworkPolicyBuilder().
				Namespace(clientNamespace).
				Name("egress-policy").
				PodSelector("app", clientName).
				AddEgressRule(firstRule).
				AddEgressRule(secondRule).
				Build()

			printNetworkPolicyYAML(policy)
			Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, policy)).To(Succeed())

			fmt.Printf("Creating client pod %s in namespace %s\n", clientName, clientNamespace)
			clientPod = deployClient(clientName)
		})

		It("should allow on server prefix and 3306 port, deny on rest server-prefix ports, allow all on rest of endpoints", func() {
			cfg := ipFamilyConfigForIP(serverIP)

			// Deny converging first proves enforcement is active.
			By(fmt.Sprintf("denying egress to the server on excepted port %d", blockPort), func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(clientNamespace, clientName, serverIP, blockPort)
				}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("CLOSE"),
					"expected deny to server on excepted port %d", blockPort)
			})

			By(fmt.Sprintf("allowing egress to the server on allowed port %d", allowPort), func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(clientNamespace, clientName, serverIP, allowPort)
				}, utils.ProbeTimeout, utils.ProbeInterval).Should(Equal("OPEN"),
					"expected allow to server on port %d", allowPort)
			})

			By("allowing egress to endpoints outside the excepted prefix", func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(clientNamespace, clientName, cfg.extProbeIP, 53)
				}, utils.ProbeTimeout, utils.ProbeInterval).Should(Equal("OPEN"),
					"expected allow to external endpoint outside the excepted prefix")
			})

			// Consistently (not Eventually) ensures the deny didn't flap.
			By(fmt.Sprintf("confirming deny on excepted port %d still holds", blockPort), func() {
				Consistently(func() (string, error) {
					return fw.PodManager.TCPProbe(clientNamespace, clientName, serverIP, blockPort)
				}, utils.StabilityWindow, utils.ProbeInterval).Should(Equal("CLOSE"),
					"deny on excepted port %d did not persist through the allow probes", blockPort)
			})
		})
	})

	// Regression for github.com/aws/aws-network-policy-agent#180.
	//
	// Two egress rules on the SAME catch-all CIDR: one carries a port and NO
	// except, the other carries an except covering the server. Kubernetes rules
	// are additive (a union of allows) and an ipBlock `except` is scoped to the
	// rule that lists it, so the ported rule must still reach the server.
	//
	// Before the fix the except CIDR was given an unconditional deny-all entry
	// and inherited nothing, so the allowed port to the server was DENIED. That
	// broke real policies of the form "DNS to everywhere, everything else only to
	// public IPs", because the cluster DNS service sits inside the excepted range.
	Context("Additive semantics: ported catch-all rule with no except, plus a catch-all rule excepting the server", func() {
		BeforeEach(func() {
			By("Applying two catch-all egress rules, only one of which excepts the server")
			err := fw.NamespaceManager.CreateNamespace(ctx, clientNamespace)
			Expect(err).ToNot(HaveOccurred())
			cfg := ipFamilyConfigForIP(serverIP)
			// Derive the host mask from the same source as the catch-all, the server
			// pod IP, rather than from the -ip-family flag: the two disagreeing would
			// build a /32 on a v6 address, which the API server rejects.
			serverHostRoute := serverIP + cfg.hostMask

			// Rule 1: allowPort to EVERYTHING, no except. The union of allows means
			// this must reach the server even though rule 2 excepts it.
			portedRule := manifest.NewEgressRuleBuilder().
				AddPeer(nil, nil, cfg.catchAll).
				AddPort(allowPort, v1.ProtocolTCP).
				Build()

			// Rule 2: all ports to everything EXCEPT the server.
			exceptRule := manifest.NewEgressRuleBuilder().
				AddPeer(nil, nil, cfg.catchAll, serverHostRoute).
				Build()

			policy = manifest.NewNetworkPolicyBuilder().
				Namespace(clientNamespace).
				Name("egress-additive-except-policy").
				PodSelector("app", clientName).
				AddEgressRule(portedRule).
				AddEgressRule(exceptRule).
				Build()

			printNetworkPolicyYAML(policy)
			Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, policy)).To(Succeed())

			fmt.Printf("Creating client pod %s in namespace %s\n", clientName, clientNamespace)
			clientPod = deployClient(clientName)
		})

		It("should allow the ported rule to reach the excepted server, deny its other ports, and allow all ports elsewhere", func() {
			cfg := ipFamilyConfigForIP(serverIP)

			// Deny converging first proves enforcement is active, so a later
			// ALLOW cannot be mistaken for "no policy programmed yet".
			By(fmt.Sprintf("denying egress to the excepted server on port %d", blockPort), func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(clientNamespace, clientName, serverIP, blockPort)
				}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal("CLOSE"),
					"expected deny to the excepted server on port %d, which no rule allows", blockPort)
			})

			// The regression itself: the ported rule has no except, so the union
			// of allows must let it through to the excepted server.
			By(fmt.Sprintf("allowing egress to the excepted server on port %d from the rule with no except", allowPort), func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(clientNamespace, clientName, serverIP, allowPort)
				}, utils.ProbeTimeout, utils.ProbeInterval).Should(Equal("OPEN"),
					"expected allow to the excepted server on port %d: the ported rule lists no except, "+
						"so an except on another rule must not suppress it", allowPort)
			})

			By("allowing all ports to endpoints outside the except", func() {
				Eventually(func() (string, error) {
					return fw.PodManager.TCPProbe(clientNamespace, clientName, cfg.extProbeIP, 53)
				}, utils.ProbeTimeout, utils.ProbeInterval).Should(Equal("OPEN"),
					"expected allow to an external endpoint, which only the all-ports rule covers")
			})

			By(fmt.Sprintf("confirming the allow on port %d holds and did not flap", allowPort), func() {
				Consistently(func() (string, error) {
					return tcpProbeWithRetry(clientNamespace, clientName, serverIP, allowPort)
				}, utils.StabilityWindow, utils.ProbeInterval).Should(Equal("OPEN"),
					"allow to the excepted server on port %d did not persist", allowPort)
			})

			// Hold the deny as well. An allow-only window cannot tell "the policy still
			// holds" from "the policy was dropped and everything is allowed now", and
			// the latter is exactly the failure mode this spec exists to catch.
			By(fmt.Sprintf("confirming the deny on port %d still holds", blockPort), func() {
				Consistently(func() (string, error) {
					return tcpProbeWithRetry(clientNamespace, clientName, serverIP, blockPort)
				}, utils.StabilityWindow, utils.ProbeInterval).Should(Equal("CLOSE"),
					"deny on port %d did not persist, so the allow above may reflect a dropped policy "+
						"rather than correct enforcement", blockPort)
			})
		})
	})

	AfterEach(func() {
		if clientPod != nil {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)
		}
		if serverPod != nil {
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, serverPod)
		}
		if policy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, policy)
		}
		fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, serverNamespace)
		fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, clientNamespace)
	})
})
