package normalize

import (
	"net/netip"
	"net/url"
	"strings"
)

func refererHost(value string) *string {
	if value == "" || value == "-" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return nil
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" {
			return nil
		}
		host = address.Unmap().String()
		return &host
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return nil
		}
		for _, r := range label {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
				continue
			}
			return nil
		}
	}
	return &host
}
