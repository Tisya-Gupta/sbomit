package network

import (
	"sort"
	"testing"
)

func TestJavaScriptNetworkResolverScopedAndNonScoped(t *testing.T) {
	r := NewJavaScriptNetworkResolver()

	domains := r.Domains()
	sort.Strings(domains)
	expectedDomains := []string{"npm.pkg.github.com", "registry.npmjs.org"}
	if len(domains) != len(expectedDomains) || domains[0] != expectedDomains[0] || domains[1] != expectedDomains[1] {
		t.Errorf("unexpected domains: %v", domains)
	}

	conn := NetworkConnection{
		Hostname: "registry.npmjs.org",
		IP:       "104.16.0.0",
		Exchanges: []NetworkExchange{
			// Non-scoped tarball
			{
				URL:        "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
				StatusCode: 200,
				BodyHash:   "lodash-hash",
			},
			// Scoped tarball
			{
				URL:        "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz",
				StatusCode: 200,
				BodyHash:   "babel-hash",
			},
			// Metadata endpoint (e.g. npm view / install metadata)
			{
				URL:        "https://registry.npmjs.org/express/4.18.2",
				StatusCode: 200,
			},
			// Scoped metadata endpoint
			{
				URL:        "https://registry.npmjs.org/@types/node/20.5.0",
				StatusCode: 200,
			},
			// 404 response should be ignored
			{
				URL:        "https://registry.npmjs.org/missing/-/missing-1.0.0.tgz",
				StatusCode: 404,
			},
			// Duplicate package exchange should be deduplicated
			{
				URL:        "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
				StatusCode: 200,
			},
		},
	}

	packages := r.Resolve(conn)
	if len(packages) != 4 {
		t.Fatalf("expected 4 resolved javascript packages, got %d", len(packages))
	}

	pkgsByPURL := make(map[string]bool)
	for _, p := range packages {
		pkgsByPURL[p.PURL] = true
		if p.Ecosystem != "npm" {
			t.Errorf("expected npm ecosystem, got: %s", p.Ecosystem)
		}
		if p.DownloadIP != "104.16.0.0" {
			t.Errorf("expected download IP 104.16.0.0, got: %s", p.DownloadIP)
		}
	}

	expectedPURLs := []string{
		"pkg:npm/lodash@4.17.21",
		"pkg:npm/@babel/core@7.24.0",
		"pkg:npm/express@4.18.2",
		"pkg:npm/@types/node@20.5.0",
	}

	for _, expected := range expectedPURLs {
		if !pkgsByPURL[expected] {
			t.Errorf("expected package %q in resolved list", expected)
		}
	}

	// Verify hash was populated on package with BodyHash
	for _, p := range packages {
		if p.Name == "lodash" {
			if p.Hashes["sha256"] != "lodash-hash" {
				t.Errorf("expected lodash sha256 hash, got: %v", p.Hashes)
			}
		}
	}
}

func TestRustNetworkResolverStaticAndAPIDownloads(t *testing.T) {
	r := NewRustNetworkResolver()

	domains := r.Domains()
	if len(domains) != 3 {
		t.Fatalf("expected 3 rust domains, got %d", len(domains))
	}

	conn := NetworkConnection{
		Hostname: "static.crates.io",
		IP:       "13.35.14.39",
		Exchanges: []NetworkExchange{
			// Static crate tarball
			{
				URL:        "https://static.crates.io/crates/serde/serde-1.0.197.crate",
				StatusCode: 200,
				BodyHash:   "serde-hash",
			},
			// API download endpoint
			{
				URL:        "https://crates.io/api/v1/crates/tokio/1.36.0/download",
				StatusCode: 200,
			},
			// Failed status should be skipped
			{
				URL:        "https://static.crates.io/crates/failed/failed-0.1.0.crate",
				StatusCode: 500,
			},
			// Duplicate URL in same connection should be deduplicated
			{
				URL:        "https://static.crates.io/crates/serde/serde-1.0.197.crate",
				StatusCode: 200,
			},
		},
	}

	packages := r.Resolve(conn)
	if len(packages) != 2 {
		t.Fatalf("expected 2 resolved rust crates, got %d", len(packages))
	}

	pkgsByPURL := make(map[string]bool)
	for _, p := range packages {
		pkgsByPURL[p.PURL] = true
		if p.Ecosystem != "cargo" {
			t.Errorf("expected cargo ecosystem, got: %s", p.Ecosystem)
		}
		if p.DownloadIP != "13.35.14.39" {
			t.Errorf("expected download IP 13.35.14.39, got: %s", p.DownloadIP)
		}
	}

	if !pkgsByPURL["pkg:cargo/serde@1.0.197"] {
		t.Errorf("expected serde package resolved")
	}
	if !pkgsByPURL["pkg:cargo/tokio@1.36.0"] {
		t.Errorf("expected tokio package resolved")
	}
}
