package main

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
)

func TestInitConfig(t *testing.T) {
	t.Run("returns config with defaults", func(t *testing.T) {
		// Unset any env vars that might interfere
		os.Unsetenv("DNS_CHECK_CONCURRENCY")
		os.Unsetenv("DNS_CHECK_DOMAINNAMEFILE")
		os.Unsetenv("DNS_CHECK_HTTPTIMEOUT")
		os.Unsetenv("DNS_CHECK_LOGLEVEL")

		config := initConfig()

		if config.Concurrency != 20 {
			t.Errorf("expected default Concurrency 20, got %d", config.Concurrency)
		}
		if config.DomainNameFile != "domains.txt" {
			t.Errorf("expected default DomainNameFile 'domains.txt', got '%s'", config.DomainNameFile)
		}
		if config.HTTPTimeout != 5 {
			t.Errorf("expected default HTTPTimeout 5, got %d", config.HTTPTimeout)
		}
		if config.LogLevel != zerolog.InfoLevel {
			t.Errorf("expected default LogLevel Info, got %v", config.LogLevel)
		}
	})

	t.Run("respects env var overrides", func(t *testing.T) {
		t.Setenv("DNS_CHECK_CONCURRENCY", "50")
		t.Setenv("DNS_CHECK_DOMAINNAMEFILE", "custom.txt")
		t.Setenv("DNS_CHECK_HTTPTIMEOUT", "10")

		config := initConfig()

		if config.Concurrency != 50 {
			t.Errorf("expected Concurrency 50, got %d", config.Concurrency)
		}
		if config.DomainNameFile != "custom.txt" {
			t.Errorf("expected DomainNameFile 'custom.txt', got '%s'", config.DomainNameFile)
		}
		if config.HTTPTimeout != 10 {
			t.Errorf("expected HTTPTimeout 10, got %d", config.HTTPTimeout)
		}
	})

	t.Run("parses debug log level", func(t *testing.T) {
		t.Setenv("DNS_CHECK_LOGLEVEL", "debug")

		config := initConfig()

		if config.LogLevel != zerolog.DebugLevel {
			t.Errorf("expected DebugLevel, got %v", config.LogLevel)
		}
	})

	t.Run("parses error log level", func(t *testing.T) {
		t.Setenv("DNS_CHECK_LOGLEVEL", "error")

		config := initConfig()

		if config.LogLevel != zerolog.ErrorLevel {
			t.Errorf("expected ErrorLevel, got %v", config.LogLevel)
		}
	})

	t.Run("defaults to info for unknown log level", func(t *testing.T) {
		t.Setenv("DNS_CHECK_LOGLEVEL", "unknown")

		config := initConfig()

		if config.LogLevel != zerolog.InfoLevel {
			t.Errorf("expected InfoLevel for unknown log level, got %v", config.LogLevel)
		}
	})
}
