package vmalert

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Type is the Ace datasource type key. Ace does not register this as a query Client.
const Type = "vmalert"

// Client wraps HTTP calls to VMAlert's API.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// New constructs a VMAlert client.
// httpClient is required so Ace can inject DatasourceClient (dial/redirect policy + auth).
func New(baseURL string, httpClient *http.Client) (*Client, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("http client is required")
	}
	if baseURL == "" {
		return nil, fmt.Errorf("vmalert datasource URL is required")
	}
	return &Client{baseURL: baseURL, httpClient: httpClient}, nil
}

// HTTPClient returns the injected HTTP client. Ace SSRF tests inspect policy wiring.
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}

// Alert represents an alert returned by VMAlert.
type Alert struct {
	State       string            `json:"state"`
	Name        string            `json:"name"`
	Value       string            `json:"value"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	ActiveAt    string            `json:"activeAt"`
	Expression  string            `json:"expression,omitempty"`
}

// AlertsResponse is the response from /api/v1/alerts.
type AlertsResponse struct {
	Status string `json:"status"`
	Data   struct {
		Alerts []Alert `json:"alerts"`
	} `json:"data"`
}

// Rule represents a single rule inside a group.
type Rule struct {
	State       string            `json:"state"`
	Name        string            `json:"name"`
	Query       string            `json:"query"`
	Duration    float64           `json:"duration"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	LastError   string            `json:"lastError,omitempty"`
	Health      string            `json:"health,omitempty"`
	Type        string            `json:"type"`
	Alerts      []Alert           `json:"alerts,omitempty"`
}

// RuleGroup represents a rule group.
type RuleGroup struct {
	Name     string  `json:"name"`
	File     string  `json:"file"`
	Rules    []Rule  `json:"rules"`
	Interval float64 `json:"interval"`
}

// GroupsResponse is the response from /api/v1/groups and /api/v1/rules.
type GroupsResponse struct {
	Status string `json:"status"`
	Data   struct {
		Groups []RuleGroup `json:"groups"`
	} `json:"data"`
}

// RulesResponse is the response from /api/v1/rules.
type RulesResponse = GroupsResponse

// GetAlerts fetches active alerts from VMAlert.
func (c *Client) GetAlerts(ctx context.Context) (*AlertsResponse, error) {
	return doRequest[AlertsResponse](ctx, c, "/api/v1/alerts")
}

// GetGroups fetches rule groups from VMAlert.
func (c *Client) GetGroups(ctx context.Context) (*GroupsResponse, error) {
	return doRequest[GroupsResponse](ctx, c, "/api/v1/rules")
}

// GetRules fetches rules from VMAlert.
func (c *Client) GetRules(ctx context.Context) (*RulesResponse, error) {
	return doRequest[RulesResponse](ctx, c, "/api/v1/rules")
}

// Health checks VMAlert liveness.
func (c *Client) Health(ctx context.Context) error {
	reqURL := c.baseURL + "/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create health request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("health check returned status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func doRequest[T any](ctx context.Context, c *Client, path string) (*T, error) {
	reqURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s: %w", path, err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response from %s: %w", path, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s returned status %d: %s", path, resp.StatusCode, string(body))
	}

	var result T
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response from %s: %w", path, err)
	}
	return &result, nil
}
