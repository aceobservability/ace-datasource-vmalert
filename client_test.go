package vmalert

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNew_requiresHTTPClient(t *testing.T) {
	t.Parallel()

	client, err := New("http://localhost:8880", nil)
	if err == nil {
		t.Fatal("expected error for nil http client")
	}
	if client != nil {
		t.Fatal("expected nil client when http client is missing")
	}
	if !strings.Contains(err.Error(), "http client is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNew_requiresURL(t *testing.T) {
	t.Parallel()

	client, err := New("", http.DefaultClient)
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
	if client != nil {
		t.Fatal("expected nil client when URL is missing")
	}
}

func TestAlertsHealthAndTestConnection_againstFixtureHTTP(t *testing.T) {
	t.Parallel()

	var sawAlerts, sawRules, sawHealth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/alerts":
			sawAlerts = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"success","data":{"alerts":[{"state":"firing","name":"HighErrorRate","value":"1"}]}}`))
		case "/api/v1/rules":
			sawRules = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"success","data":{"groups":[{"name":"app","file":"app.yaml","rules":[{"name":"HighErrorRate","type":"alerting"}]}]}}`))
		case "/health":
			sawHealth = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := New(srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	alerts, err := client.GetAlerts(ctx)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	if alerts.Status != "success" || len(alerts.Data.Alerts) != 1 || alerts.Data.Alerts[0].Name != "HighErrorRate" {
		t.Fatalf("unexpected alerts %+v", alerts)
	}
	if !sawAlerts {
		t.Fatal("expected GetAlerts to hit /api/v1/alerts")
	}

	groups, err := client.GetGroups(ctx)
	if err != nil {
		t.Fatalf("GetGroups: %v", err)
	}
	if len(groups.Data.Groups) != 1 || groups.Data.Groups[0].Name != "app" {
		t.Fatalf("unexpected groups %+v", groups)
	}
	if !sawRules {
		t.Fatal("expected GetGroups to hit /api/v1/rules")
	}

	if err := client.Health(ctx); err != nil {
		t.Fatalf("Health: %v", err)
	}

	if err := client.TestConnection(ctx); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	if !sawHealth {
		t.Fatal("expected Health/TestConnection to hit /health")
	}
}

func TestTestConnection_usesHealthThenAlertsFallback(t *testing.T) {
	t.Parallel()

	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Path == "/api/v1/alerts" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"success","data":{"alerts":[]}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	client, err := New(srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.TestConnection(ctx); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	if len(paths) < 2 || paths[0] != "/health" {
		t.Fatalf("paths=%v, want /health then /api/v1/alerts", paths)
	}
}
