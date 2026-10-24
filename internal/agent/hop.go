package agent

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"nodehub/internal/proto"
)

// Port hopping: UDP sent to any port in a node's hop range is redirected to the node's real port.
// All rules live in our own nat chain, rebuilt from scratch on every apply, so stale rules never
// accumulate. The jumps only match packets addressed to this host (addrtype LOCAL): without that,
// the OUTPUT jump would also capture proxied UDP that users send to remote servers on those ports.
const hopChain = "NODEHUB_HOP"

type hopRule struct {
	lo, hi, to int
}

func hopRules(nodes []proto.NodeConfig) []hopRule {
	var out []hopRule
	for _, n := range nodes {
		r := strings.TrimSpace(n.Settings.HopPorts)
		if r == "" || n.Protocol != "hysteria2" || len(n.Users) == 0 {
			continue
		}
		parts := strings.SplitN(strings.ReplaceAll(r, ":", "-"), "-", 2)
		if len(parts) != 2 {
			continue
		}
		lo, e1 := strconv.Atoi(parts[0])
		hi, e2 := strconv.Atoi(parts[1])
		if e1 != nil || e2 != nil || lo < 1 || hi > 65535 || lo >= hi || (n.Port >= lo && n.Port <= hi) {
			continue
		}
		out = append(out, hopRule{lo, hi, n.Port})
	}
	return out
}

func ipt(bin string, args ...string) error {
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v %s", bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// applyHopRules makes the kernel state match the desired hop rules (for iptables and ip6tables).
func applyHopRules(nodes []proto.NodeConfig) error {
	rules := hopRules(nodes)
	var errs []string
	for _, bin := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(bin); err != nil {
			if bin == "iptables" && len(rules) > 0 {
				errs = append(errs, "未安装 iptables，端口跳跃无法生效")
			}
			continue
		}
		// chain exists?
		if ipt(bin, "-t", "nat", "-L", hopChain, "-n") != nil {
			if len(rules) == 0 {
				continue // nothing to do and nothing to clean
			}
			if err := ipt(bin, "-t", "nat", "-N", hopChain); err != nil {
				if bin == "iptables" {
					errs = append(errs, err.Error())
				}
				continue
			}
		}
		_ = ipt(bin, "-t", "nat", "-F", hopChain)
		jump := []string{"-p", "udp", "-m", "addrtype", "--dst-type", "LOCAL", "-j", hopChain}
		for _, ch := range []string{"PREROUTING", "OUTPUT"} {
			has := ipt(bin, append([]string{"-t", "nat", "-C", ch}, jump...)...) == nil
			switch {
			case len(rules) > 0 && !has:
				if err := ipt(bin, append([]string{"-t", "nat", "-I", ch}, jump...)...); err != nil && bin == "iptables" {
					errs = append(errs, err.Error())
				}
			case len(rules) == 0 && has:
				_ = ipt(bin, append([]string{"-t", "nat", "-D", ch}, jump...)...)
			}
		}
		if len(rules) == 0 {
			_ = ipt(bin, "-t", "nat", "-X", hopChain)
			continue
		}
		for _, r := range rules {
			err := ipt(bin, "-t", "nat", "-A", hopChain, "-p", "udp", "--dport", fmt.Sprintf("%d:%d", r.lo, r.hi),
				"-j", "REDIRECT", "--to-ports", strconv.Itoa(r.to))
			if err != nil && bin == "iptables" {
				errs = append(errs, err.Error())
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("端口跳跃规则: %s", strings.Join(errs, "; "))
	}
	return nil
}

// hasIPv6Route reports whether the host has a default IPv6 route (otherwise destinations resolve to IPv4 only).
func hasIPv6Route() bool {
	for _, l := range strings.Split(readFile("/proc/net/ipv6_route"), "\n") {
		f := strings.Fields(l)
		// destination ::/0 and a non-loopback device
		if len(f) >= 10 && f[0] == "00000000000000000000000000000000" && f[1] == "00" && f[9] != "lo" {
			return true
		}
	}
	return false
}
