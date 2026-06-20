package discovery

import (
	"net"
	"sync"
)

var (
	localSubnets     []*net.IPNet
	localSubnetsOnce sync.Once
)

func getLocalIPNets() []*net.IPNet {
	localSubnetsOnce.Do(func() {
		ifaces, _ := net.Interfaces()
		for _, i := range ifaces {
			// Ignore loopback and down interfaces
			if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := i.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				_, ipnet, err := net.ParseCIDR(addr.String())
				if err == nil && ipnet != nil && ipnet.IP.To4() != nil {
					localSubnets = append(localSubnets, ipnet)
				}
			}
		}
	})
	return localSubnets
}

func isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range getLocalIPNets() {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
