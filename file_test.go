package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
)

func testConfig(t *testing.T) *Config {
	t.Helper()
	logger := zerolog.New(zerolog.NewTestWriter(t))
	return &Config{
		Concurrency:    5,
		DomainNameFile: "",
		HTTPTimeout:    5,
		LogLevel:       zerolog.InfoLevel,
		Logger:         logger,
	}
}

func TestParseFile(t *testing.T) {
	t.Run("parses domains from file", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "domains.txt")
		err := os.WriteFile(f, []byte("example.com\nexample.org\nexample.net\n"), 0644)
		if err != nil {
			t.Fatal(err)
		}

		c := testConfig(t)
		c.DomainNameFile = f

		domains, err := parseFile(c)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(domains) != 3 {
			t.Fatalf("expected 3 domains, got %d", len(domains))
		}
		if domains[0] != "example.com" {
			t.Errorf("expected example.com, got %s", domains[0])
		}
		if domains[1] != "example.org" {
			t.Errorf("expected example.org, got %s", domains[1])
		}
		if domains[2] != "example.net" {
			t.Errorf("expected example.net, got %s", domains[2])
		}
	})

	t.Run("skips wildcard domains", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "domains.txt")
		err := os.WriteFile(f, []byte("example.com\n*.example.org\nexample.net\n"), 0644)
		if err != nil {
			t.Fatal(err)
		}

		c := testConfig(t)
		c.DomainNameFile = f

		domains, err := parseFile(c)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(domains) != 2 {
			t.Fatalf("expected 2 domains (wildcard skipped), got %d", len(domains))
		}
		if domains[0] != "example.com" {
			t.Errorf("expected example.com, got %s", domains[0])
		}
		if domains[1] != "example.net" {
			t.Errorf("expected example.net, got %s", domains[1])
		}
	})

	t.Run("returns error for missing file", func(t *testing.T) {
		c := testConfig(t)
		c.DomainNameFile = "/nonexistent/path/domains.txt"

		_, err := parseFile(c)
		if err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("handles empty file", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "domains.txt")
		err := os.WriteFile(f, []byte(""), 0644)
		if err != nil {
			t.Fatal(err)
		}

		c := testConfig(t)
		c.DomainNameFile = f

		domains, err := parseFile(c)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(domains) != 0 {
			t.Fatalf("expected 0 domains, got %d", len(domains))
		}
	})
}

func TestWriteFile(t *testing.T) {
	t.Run("writes results to JSON file", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "results.json")

		results := []result{
			{Domain: "example.com", Cnames: []string{"example.cdn.com"}, Nxdomain: true, Status: 3},
			{Domain: "example.org", Cnames: []string{"other.cdn.com"}, Nxdomain: false, Status: 0},
		}

		err := writeFile(f, results)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		var decoded []result
		err = json.Unmarshal(data, &decoded)
		if err != nil {
			t.Fatalf("failed to parse JSON: %v", err)
		}

		if len(decoded) != 2 {
			t.Fatalf("expected 2 results, got %d", len(decoded))
		}
		if decoded[0].Domain != "example.com" {
			t.Errorf("expected example.com, got %s", decoded[0].Domain)
		}
		if decoded[1].Domain != "example.org" {
			t.Errorf("expected example.org, got %s", decoded[1].Domain)
		}
	})

	t.Run("returns nil for empty results", func(t *testing.T) {
		err := writeFile("should-not-be-created.json", []result{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestWriteStats(t *testing.T) {
	t.Run("writes stats to JSON file", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "stats.json")

		s := stats{
			TotalDomains: 42,
			Elapsed:      "1m30s",
		}

		err := writeStats(f, s)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		var decoded stats
		err = json.Unmarshal(data, &decoded)
		if err != nil {
			t.Fatalf("failed to parse JSON: %v", err)
		}

		if decoded.TotalDomains != 42 {
			t.Errorf("expected TotalDomains 42, got %d", decoded.TotalDomains)
		}
		if decoded.Elapsed != "1m30s" {
			t.Errorf("expected Elapsed 1m30s, got %s", decoded.Elapsed)
		}
	})
}
