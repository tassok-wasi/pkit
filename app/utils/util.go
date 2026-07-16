package utils

import (
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func ToNetIP(addr string) (net.IP, error) {
	parsedIP := net.ParseIP(addr)
	if parsedIP == nil {
		return nil, errors.New("unknown or invalid ip address")
	}

	return parsedIP, nil
}

func ToNetIPs(addrs []string) []net.IP {
	var netIPs []net.IP

	for _, ip := range addrs {
		netIP, err := ToNetIP(ip)
		if err != nil {
			log.Printf("skipping invalid IP string: %s\n", ip)
			continue
		}
		netIPs = append(netIPs, netIP)
	}
	return netIPs
}

func ToURL(s string) (*url.URL, error) {
	parsedUrl, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("unknown or invalid url")
	}

	return parsedUrl, nil
}

func ToURLs(urls []string) []*url.URL {
	var urlURLs []*url.URL

	for _, urlStr := range urls {
		u, err := ToURL(urlStr)
		if err != nil {
			log.Printf("skipping invalid URL string: %s\n", urlStr)
			continue
		}
		urlURLs = append(urlURLs, u)
	}
	return urlURLs
}

func ToPem(bytes []byte, blockType string) []byte {
	block := pem.Block{
		Bytes: bytes,
		Type:  blockType,
	}
	pemBytes := pem.EncodeToMemory(&block)

	return pemBytes
}

func GetSerialNumber() (*big.Int, error) {
	sNumLim := new(big.Int).Lsh(big.NewInt(1), 128)
	sNum, err := rand.Int(rand.Reader, sNumLim)
	if err != nil {
		return nil, fmt.Errorf("cannot generate serial number: %w", err)
	}
	return sNum, nil
}

func JoinHomeDir(filePath string) (string, error) {
	if strings.HasPrefix(filePath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot get home directory: %w", err)
		}
		resolvedPath := filepath.Join(home, filePath[2:])
		return resolvedPath, nil
	}
	return filePath, nil
}

func SplitCSV(in string) []string {
	if strings.TrimSpace(in) == "" {
		return nil
	}
	var out []string
	for segment := range strings.SplitSeq(in, ",") {
		if trimmed := strings.TrimSpace(segment); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// FindDir walks rootDir to find targetDirName.
func FindDir(rootDir, targetDirName string) (string, error) {
	var foundPath string

	// Walk the directory tree
	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Prevent panicking on permission errors, just skip those directories
			return nil
		}

		if d.IsDir() && d.Name() == targetDirName {
			foundPath = path
			// Return filepath.SkipDir to stop searching once we find the first match
			return filepath.SkipDir
		}

		return nil
	})
	if err != nil {
		return "", fmt.Errorf("cannot walk path: %w", err)
	}

	if foundPath == "" {
		return "", fmt.Errorf("target directory '%s' not found", targetDirName)
	}

	return foundPath, nil
}

// ToSnakeCase converts a string to lowercase and replaces spaces/special characters with underscores.
func ToSnakeCase(str string) string {
	lower := strings.ToLower(strings.TrimSpace(str))

	// 2. Replace one or more consecutive spaces, hyphens, or special chars with a single underscore
	reg := regexp.MustCompile(`[\s\-_]+`)
	snake := reg.ReplaceAllString(lower, "_")

	return snake
}

// GetDeterministicPath returns the path where a certificate *should* reside instantly.
func GetDeterministicPath(subjectCN, issuerCN string, isRootCA bool) (string, error) {
	sub := ToSnakeCase(subjectCN)
	iss := ToSnakeCase(issuerCN)

	if isRootCA && sub == iss {
		return JoinHomeDir(filepath.Join("~/certman/certificates/roots", sub))
	}
	return JoinHomeDir(filepath.Join("~/certman/certificates/issued_by", iss, sub))
}
