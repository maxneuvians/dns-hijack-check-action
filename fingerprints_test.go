package main

import "testing"

func TestMatchFingerprints(t *testing.T) {
	t.Run("matches AWS Elastic Beanstalk", func(t *testing.T) {
		r := result{
			Domain:   "test.example.com",
			Cnames:   []string{"myapp.elasticbeanstalk.com"},
			Nxdomain: true,
			Status:   3,
		}

		matched := matchFingerprints(r)
		if matched == nil {
			t.Fatal("expected match for Elastic Beanstalk")
		}
		if matched.Name != "AWS/Elastic Beanstalk" {
			t.Errorf("expected name 'AWS/Elastic Beanstalk', got '%s'", matched.Name)
		}
		if !matched.Immediate {
			t.Error("expected Immediate to be true (NXDOMAIN)")
		}
	})

	t.Run("matches AWS S3", func(t *testing.T) {
		r := result{
			Domain:   "static.example.com",
			Cnames:   []string{"mybucket.s3.amazonaws.com"},
			Nxdomain: false,
			Status:   0,
		}

		matched := matchFingerprints(r)
		if matched == nil {
			t.Fatal("expected match for S3")
		}
		if matched.Name != "AWS/S3" {
			t.Errorf("expected name 'AWS/S3', got '%s'", matched.Name)
		}
		if matched.Immediate {
			t.Error("expected Immediate to be false (not NXDOMAIN)")
		}
	})

	t.Run("matches Azure App Service and sets flag", func(t *testing.T) {
		r := result{
			Domain:   "app.example.com",
			Cnames:   []string{"myapp.azurewebsites.net"},
			Nxdomain: true,
			Status:   3,
		}

		matched := matchFingerprints(r)
		if matched == nil {
			t.Fatal("expected match for Azure")
		}
		if !matched.AzureAppService {
			t.Error("expected AzureAppService to be true")
		}
		if matched.AzureTrafficManager {
			t.Error("expected AzureTrafficManager to be false")
		}
		if matched.Name != "Microsoft Azure" {
			t.Errorf("expected name 'Microsoft Azure', got '%s'", matched.Name)
		}
	})

	t.Run("matches Azure Traffic Manager and sets flag", func(t *testing.T) {
		r := result{
			Domain:   "lb.example.com",
			Cnames:   []string{"myapp.trafficmanager.net"},
			Nxdomain: true,
			Status:   3,
		}

		matched := matchFingerprints(r)
		if matched == nil {
			t.Fatal("expected match for Azure Traffic Manager")
		}
		if matched.AzureAppService {
			t.Error("expected AzureAppService to be false")
		}
		if !matched.AzureTrafficManager {
			t.Error("expected AzureTrafficManager to be true")
		}
	})

	t.Run("matches other Azure services without special flags", func(t *testing.T) {
		r := result{
			Domain:   "data.example.com",
			Cnames:   []string{"mystore.blob.core.windows.net"},
			Nxdomain: true,
			Status:   3,
		}

		matched := matchFingerprints(r)
		if matched == nil {
			t.Fatal("expected match for Azure Blob")
		}
		if matched.AzureAppService {
			t.Error("expected AzureAppService to be false")
		}
		if matched.AzureTrafficManager {
			t.Error("expected AzureTrafficManager to be false")
		}
	})

	t.Run("returns nil for no match", func(t *testing.T) {
		r := result{
			Domain:   "example.com",
			Cnames:   []string{"some.random.domain.com"},
			Nxdomain: false,
			Status:   0,
		}

		matched := matchFingerprints(r)
		if matched != nil {
			t.Errorf("expected no match, got %+v", matched)
		}
	})

	t.Run("returns nil for empty cnames", func(t *testing.T) {
		r := result{
			Domain:   "example.com",
			Cnames:   []string{},
			Nxdomain: false,
			Status:   0,
		}

		matched := matchFingerprints(r)
		if matched != nil {
			t.Errorf("expected no match, got %+v", matched)
		}
	})

	t.Run("matches ghost.io", func(t *testing.T) {
		r := result{
			Domain:   "blog.example.com",
			Cnames:   []string{"myblog.ghost.io"},
			Nxdomain: false,
			Status:   0,
		}

		matched := matchFingerprints(r)
		if matched == nil {
			t.Fatal("expected match for Ghost")
		}
		if matched.Name != "Ghost" {
			t.Errorf("expected name 'Ghost', got '%s'", matched.Name)
		}
	})

	t.Run("matches wordpress.com", func(t *testing.T) {
		r := result{
			Domain:   "blog.example.com",
			Cnames:   []string{"myblog.wordpress.com"},
			Nxdomain: false,
			Status:   0,
		}

		matched := matchFingerprints(r)
		if matched == nil {
			t.Fatal("expected match for Wordpress")
		}
		if matched.Name != "Wordpress" {
			t.Errorf("expected name 'Wordpress', got '%s'", matched.Name)
		}
	})

	t.Run("domain field is set correctly", func(t *testing.T) {
		r := result{
			Domain:   "vulnerable.example.com",
			Cnames:   []string{"myblog.ghost.io"},
			Nxdomain: false,
			Status:   0,
		}

		matched := matchFingerprints(r)
		if matched == nil {
			t.Fatal("expected match")
		}
		if matched.Domain != "vulnerable.example.com" {
			t.Errorf("expected domain 'vulnerable.example.com', got '%s'", matched.Domain)
		}
	})

	t.Run("matches with multiple cnames", func(t *testing.T) {
		r := result{
			Domain:   "multi.example.com",
			Cnames:   []string{"intermediate.cdn.com", "final.ghost.io"},
			Nxdomain: false,
			Status:   0,
		}

		matched := matchFingerprints(r)
		if matched == nil {
			t.Fatal("expected match via second CNAME")
		}
		if matched.Name != "Ghost" {
			t.Errorf("expected name 'Ghost', got '%s'", matched.Name)
		}
	})
}
