// Copyright 2026 Tassok Imam Wasi

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crypto

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ToNetIP parses a single IP address string.
func ToNetIP(addr string) (net.IP, error) {
	parsedIP := net.ParseIP(addr)
	if parsedIP == nil {
		return nil, errors.New("unknown or invalid ip address")
	}

	return parsedIP, nil
}

// ToNetIPs parses a list of IP address strings.
func ToNetIPs(addrs []string) ([]net.IP, error) {
	var netIPs []net.IP

	for _, ipStr := range addrs {
		netIP, err := ToNetIP(ipStr)
		if err != nil {
			return nil, fmt.Errorf("invalid IP address %q: %w", ipStr, err)
		}
		netIPs = append(netIPs, netIP)
	}
	return netIPs, nil
}

// ToURL parses a single absolute URL string.
func ToURL(s string) (*url.URL, error) {
	trimmed := strings.TrimSpace(s)
	parsedURL, err := url.Parse(trimmed)
	if err != nil {
		return nil, errors.New("unknown or invalid url")
	}
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, errors.New("unknown or invalid url")
	}
	if parsedURL.User != nil {
		return nil, errors.New("unknown or invalid url")
	}

	return parsedURL, nil
}

// ToURLs parses a list of absolute URL strings.
func ToURLs(urls []string) ([]*url.URL, error) {
	var urlURLs []*url.URL

	for _, urlStr := range urls {
		u, err := ToURL(urlStr)
		if err != nil {
			return nil, fmt.Errorf("invalid URL %q: %w", urlStr, err)
		}
		urlURLs = append(urlURLs, u)
	}
	return urlURLs, nil
}

// IpSlicesEqual reports whether two IP slices are element-wise equal.
func IpSlicesEqual(ips1, ips2 []net.IP) bool {
	if len(ips1) != len(ips2) {
		return false
	}
	for i := range ips1 {
		if !ips1[i].Equal(ips2[i]) {
			return false
		}
	}
	return true
}

// FormatIPs renders a list of IPs as a comma-separated string.
func FormatIPs(ips []net.IP) string {
	var strIPs []string
	for _, ip := range ips {
		strIPs = append(strIPs, ip.String())
	}
	return strings.Join(strIPs, ", ")
}

// UriSlicesEqual reports whether two URL slices are element-wise equal.
func UriSlicesEqual(u1, u2 []*url.URL) bool {
	if len(u1) != len(u2) {
		return false
	}
	for i := range u1 {
		if u1[i].String() != u2[i].String() {
			return false
		}
	}
	return true
}

// FormatURIs renders a list of URLs as a comma-separated string.
func FormatURIs(uris []*url.URL) string {
	var strURIs []string
	for _, u := range uris {
		strURIs = append(strURIs, u.String())
	}
	return strings.Join(strURIs, ", ")
}
