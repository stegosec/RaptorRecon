package enrichment

import (
	"testing"
)

func TestParseBanner(t *testing.T) {
	tests := []struct {
		banner   string
		expected string
	}{
		{"Apache/2.4.41 (Ubuntu)", "apache http_server 2.4.41"},
		{"OpenSSH_8.2p1 Ubuntu-4ubuntu0.1", "openbsd openssh 8.2p1"},
		{"Microsoft-IIS/10.0", "microsoft internet_information_services 10.0"},
		{"vsFTPd 3.0.3", "beasts vsftpd 3.0.3"},
		{"Unknown Service", ""},
	}

	for _, tt := range tests {
		actualSlice := ParseBanner(tt.banner)
		actual := ""
		if len(actualSlice) > 0 {
			actual = actualSlice[0].QueryString()
		}
		if actual != tt.expected {
			t.Errorf("ParseBanner(%q) = %q; want %q", tt.banner, actual, tt.expected)
		}
	}
}
