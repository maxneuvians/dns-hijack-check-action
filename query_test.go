package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckDomain(t *testing.T) {
	t.Run("detects CNAME records", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := Response{
				Status: 0,
				Answer: []Answer{
					{Name: "example.com.", Type: 5, TTL: 300, Data: "cdn.example.com."},
				},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := http.Client{}
		cnames, nxdomain, status := checkDomainWithURL(client, "example.com", server.URL+"/resolve?name=")
		if len(cnames) != 1 {
			t.Fatalf("expected 1 CNAME, got %d", len(cnames))
		}
		if cnames[0] != "cdn.example.com" {
			t.Errorf("expected 'cdn.example.com', got '%s'", cnames[0])
		}
		if nxdomain {
			t.Error("expected nxdomain to be false")
		}
		if status != 0 {
			t.Errorf("expected status 0, got %d", status)
		}
	})

	t.Run("detects NXDOMAIN", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := Response{
				Status: 3,
				Answer: []Answer{},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := http.Client{}
		cnames, nxdomain, status := checkDomainWithURL(client, "nonexistent.example.com", server.URL+"/resolve?name=")
		if len(cnames) != 0 {
			t.Fatalf("expected 0 CNAMEs, got %d", len(cnames))
		}
		if !nxdomain {
			t.Error("expected nxdomain to be true")
		}
		if status != 3 {
			t.Errorf("expected status 3, got %d", status)
		}
	})

	t.Run("NXDOMAIN with CNAME chain", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := Response{
				Status: 3,
				Answer: []Answer{
					{Name: "example.com.", Type: 5, TTL: 300, Data: "dangling.elasticbeanstalk.com."},
				},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := http.Client{}
		cnames, nxdomain, status := checkDomainWithURL(client, "example.com", server.URL+"/resolve?name=")
		if len(cnames) != 1 {
			t.Fatalf("expected 1 CNAME, got %d", len(cnames))
		}
		if cnames[0] != "dangling.elasticbeanstalk.com" {
			t.Errorf("expected 'dangling.elasticbeanstalk.com', got '%s'", cnames[0])
		}
		if !nxdomain {
			t.Error("expected nxdomain to be true")
		}
		if status != 3 {
			t.Errorf("expected status 3, got %d", status)
		}
	})

	t.Run("ignores non-CNAME records", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := Response{
				Status: 0,
				Answer: []Answer{
					{Name: "example.com.", Type: 1, TTL: 300, Data: "1.2.3.4"},
					{Name: "example.com.", Type: 28, TTL: 300, Data: "::1"},
				},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := http.Client{}
		cnames, nxdomain, status := checkDomainWithURL(client, "example.com", server.URL+"/resolve?name=")
		if len(cnames) != 0 {
			t.Fatalf("expected 0 CNAMEs, got %d", len(cnames))
		}
		if nxdomain {
			t.Error("expected nxdomain to be false")
		}
		if status != 0 {
			t.Errorf("expected status 0, got %d", status)
		}
	})

	t.Run("returns status 2 on HTTP error", func(t *testing.T) {
		client := http.Client{}
		cnames, nxdomain, status := checkDomainWithURL(client, "example.com", "http://invalid-server:99999/resolve?name=")
		if cnames != nil {
			t.Errorf("expected nil cnames, got %v", cnames)
		}
		if nxdomain {
			t.Error("expected nxdomain to be false")
		}
		if status != 2 {
			t.Errorf("expected status 2, got %d", status)
		}
	})

	t.Run("returns status 2 on invalid JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("not json"))
		}))
		defer server.Close()

		client := http.Client{}
		cnames, nxdomain, status := checkDomainWithURL(client, "example.com", server.URL+"/resolve?name=")
		if cnames != nil {
			t.Errorf("expected nil cnames, got %v", cnames)
		}
		if nxdomain {
			t.Error("expected nxdomain to be false")
		}
		if status != 2 {
			t.Errorf("expected status 2, got %d", status)
		}
	})

	t.Run("trims trailing dots from CNAME data", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := Response{
				Status: 0,
				Answer: []Answer{
					{Name: "example.com.", Type: 5, TTL: 300, Data: "cdn.example.com."},
				},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := http.Client{}
		cnames, _, _ := checkDomainWithURL(client, "example.com", server.URL+"/resolve?name=")
		if len(cnames) != 1 {
			t.Fatalf("expected 1 CNAME, got %d", len(cnames))
		}
		if strings.HasSuffix(cnames[0], ".") {
			t.Errorf("expected trailing dot to be trimmed, got '%s'", cnames[0])
		}
	})
}

func TestCheckASUIDRecord(t *testing.T) {
	t.Run("returns true when TXT record exists", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := Response{
				Status: 0,
				Answer: []Answer{
					{Name: "asuid.example.com.", Type: 16, TTL: 300, Data: "some-verification-id"},
				},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		c := &Config{HTTPTimeout: 5}
		result := checkASUIDRecordWithURL(c, "example.com", server.URL+"/resolve?name=")
		if !result {
			t.Error("expected true when ASUID record exists")
		}
	})

	t.Run("returns false when no TXT records", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := Response{
				Status: 0,
				Answer: []Answer{},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		c := &Config{HTTPTimeout: 5}
		result := checkASUIDRecordWithURL(c, "example.com", server.URL+"/resolve?name=")
		if result {
			t.Error("expected false when no ASUID record")
		}
	})

	t.Run("returns false on HTTP error", func(t *testing.T) {
		c := &Config{HTTPTimeout: 1}
		result := checkASUIDRecordWithURL(c, "example.com", "http://invalid-server:99999/resolve?name=")
		if result {
			t.Error("expected false on HTTP error")
		}
	})
}
