package elasticapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	v1 "github.com/gopes0x00/elastic-rules-operator/api/v1"
)

type ElasticConnection struct {
	Url      string
	Username string
	Password string
}

func (a *ElasticConnection) encodedAuth() string {
	auth := a.Username + ":" + a.Password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func (a *ElasticConnection) doRequest(method, endpoint string, body []byte) ([]byte, error) {
	req, err := http.NewRequest(method, endpoint, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Shared Configuration
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("kbn-xsrf", "true")
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", a.encodedAuth()))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("kibana returned status %s: %s", resp.Status, string(respBody))
	}

	return respBody, nil
}

func (a *ElasticConnection) CreateRule(rule v1.ElasticDetectionRule) (v1.ElasticDetectionRuleStatus, error) {
	jsonData, err := json.Marshal(rule.Spec)
	if err != nil {
		return v1.ElasticDetectionRuleStatus{}, fmt.Errorf("failed to marshal spec: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/detection_engine/rules", a.Url)
	respBody, err := a.doRequest("POST", endpoint, jsonData)
	if err != nil {
		return v1.ElasticDetectionRuleStatus{}, err
	}

	var ruleResponse v1.ElasticDetectionRuleStatus
	if err := json.Unmarshal(respBody, &ruleResponse); err != nil {
		return v1.ElasticDetectionRuleStatus{}, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return ruleResponse, nil
}

func (a *ElasticConnection) DeleteRule(ruleid string) ([]byte, error) {
	endpoint := fmt.Sprintf("%s/api/detection_engine/rules?rule_id=%s", a.Url, ruleid)
	response, err := a.doRequest("DELETE", endpoint, nil)
	return response, err
}

func (a *ElasticConnection) UpdateRule(rule v1.ElasticDetectionRule) error {

	//jsonData requires the rule ID and the field(s) to be patched
	jsonData, err := json.Marshal(rule.Spec)
	if err != nil {
		return fmt.Errorf("failed to marshal spec: %w", err)
	}

	// Elastic uses PATCH for partial updates or updates via the detection engine API
	endpoint := fmt.Sprintf("%s/api/detection_engine/rules", a.Url)
	_, err = a.doRequest("PATCH", endpoint, jsonData)
	return err
}

func (a *ElasticConnection) ListRule(ruleid string) (v1.ElasticDetectionRuleSpec, error) {
	endpoint := fmt.Sprintf("%s/api/detection_engine/rules?rule_id=%s", a.Url, ruleid)

	respBody, err := a.doRequest("GET", endpoint, nil)
	if err != nil {
		return v1.ElasticDetectionRuleSpec{}, err
	}

	var ruleResponse v1.ElasticDetectionRuleSpec
	if err := json.Unmarshal(respBody, &ruleResponse); err != nil {
		return v1.ElasticDetectionRuleSpec{}, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return ruleResponse, nil
}
