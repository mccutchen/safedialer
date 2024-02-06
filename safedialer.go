/*
Package safedialer provides a [net.Dialer Control] function that permits only TCP
connections to port 80 and 443 on public IP addresses, so that an application
may safely connect to possibly-malicious URLs controlled by external clients.

This code is very lightly adapted from Andrew Ayer's excellent 2019 blog
post ["Preventing Server Side Request Forgery in Golang"], which explains
the dangers of connecting to arbitrary URLs from your own application code.

[net.Dialer Control]: https://golang.org/pkg/net/#Dialer.Control
["Preventing Server Side Request Forgery in Golang"]: https://www.agwa.name/blog/post/preventing_server_side_request_forgery_in_golang
*/
package safedialer

import (
	"errors"
	"net"
	"syscall"
)

// Errors that may be returned from Control.
var (
	ErrInvalidAddress = errors.New("invalid host/port pair in address")
	ErrInvalidIP      = errors.New("invalid IP address")
	ErrUnsafeIP       = errors.New("unsafe IP address")
	ErrUnsafeNetwork  = errors.New("unsafe network type")
	ErrUnsafePort     = errors.New("unsafe port number")
)

// Control permits only TCP connections to port 80 and 443 on public
// IP addresses. It is intended for use as a net.Dialer's Control function.
func Control(network string, address string, _ syscall.RawConn) error {
	if !(network == "tcp4" || network == "tcp6") {
		return ErrUnsafeNetwork
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return ErrInvalidAddress
	}

	if !(port == "80" || port == "443") {
		return ErrUnsafePort
	}

	ipaddress := net.ParseIP(host)
	if ipaddress == nil {
		return ErrInvalidIP
	}

	if !isPublicIPAddress(ipaddress) {
		return ErrUnsafeIP
	}

	return nil
}

func ipv4Net(a, b, c, d byte, subnetPrefixLen int) net.IPNet {
	return net.IPNet{
		IP:   net.IPv4(a, b, c, d),
		Mask: net.CIDRMask(96+subnetPrefixLen, 128),
	}
}

var reservedIPv4Nets = []net.IPNet{
	ipv4Net(0, 0, 0, 0, 8),       // Current network
	ipv4Net(10, 0, 0, 0, 8),      // Private
	ipv4Net(100, 64, 0, 0, 10),   // RFC6598
	ipv4Net(127, 0, 0, 0, 8),     // Loopback
	ipv4Net(169, 254, 0, 0, 16),  // Link-local
	ipv4Net(172, 16, 0, 0, 12),   // Private
	ipv4Net(192, 0, 0, 0, 24),    // RFC6890
	ipv4Net(192, 0, 2, 0, 24),    // Test, doc, examples
	ipv4Net(192, 88, 99, 0, 24),  // IPv6 to IPv4 relay
	ipv4Net(192, 168, 0, 0, 16),  // Private
	ipv4Net(198, 18, 0, 0, 15),   // Benchmarking tests
	ipv4Net(198, 51, 100, 0, 24), // Test, doc, examples
	ipv4Net(203, 0, 113, 0, 24),  // Test, doc, examples
	ipv4Net(224, 0, 0, 0, 4),     // Multicast
	ipv4Net(240, 0, 0, 0, 4),     // Reserved (includes broadcast / 255.255.255.255)
}

var globalUnicastIPv6Net = net.IPNet{
	IP:   net.IP{0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	Mask: net.CIDRMask(3, 128),
}

func isIPv6GlobalUnicast(address net.IP) bool {
	return globalUnicastIPv6Net.Contains(address)
}

func isIPv4Reserved(address net.IP) bool {
	for _, reservedNet := range reservedIPv4Nets {
		if reservedNet.Contains(address) {
			return true
		}
	}
	return false
}

func isPublicIPAddress(address net.IP) bool {
	if address.To4() != nil {
		return !isIPv4Reserved(address)
	}
	return isIPv6GlobalUnicast(address)
}
