//go:build linux

package tun

import (
	"fmt"
	"os/exec"
	"strconv"
)

// Configure assigns an address, MTU and up state to a TUN device via iproute2.
// It is intentionally shelling out to `ip` so the data plane does not need a
// netlink dependency for this prototype.
func Configure(name, cidr string, mtu int) error {
	if name == "" || cidr == "" || mtu <= 0 {
		return fmt.Errorf("bad tun config")
	}
	steps := [][]string{
		{"ip", "addr", "replace", cidr, "dev", name},
		{"ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu)},
		{"ip", "link", "set", "dev", name, "up"},
	}
	for _, args := range steps {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %w: %s", args, err, out)
		}
	}
	return nil
}
