package elasticapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

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

func sanitizePayload(rule v1.ElasticDetectionRule) (map[string]interface{}, error) {
	payload := make(map[string]interface{})
	specData, err := json.Marshal(rule.Spec)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal spec: %w", err)
	}
	if err := json.Unmarshal(specData, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal spec into map: %w", err)
	}

	// Normalize name
	if nameVal, ok := payload["name"].(string); !ok || nameVal == "" {
		if oldName, ok := payload["rulename"].(string); ok && oldName != "" {
			payload["name"] = oldName
		} else {
			payload["name"] = rule.Name
		}
	}
	delete(payload, "rulename")

	// Normalize risk_score
	if scoreVal, ok := payload["risk_score"].(float64); !ok || scoreVal == 0 {
		if oldScore, ok := payload["riskscore"].(float64); ok && oldScore > 0 {
			payload["risk_score"] = int(oldScore)
		} else if rule.Spec.RiskScore > 0 {
			payload["risk_score"] = rule.Spec.RiskScore
		} else {
			payload["risk_score"] = 50
		}
	}
	delete(payload, "riskscore")

	// Normalize severity (must be lowercase)
	if sev, ok := payload["severity"].(string); ok {
		payload["severity"] = strings.ToLower(sev)
	} else {
		payload["severity"] = "medium"
	}

	// Normalize rule type and query defaults
	ruleType, _ := payload["type"].(string)
	if ruleType == "" || ruleType == "foo" {
		payload["type"] = "query"
		ruleType = "query"
	}
	if ruleType == "query" {
		if q, ok := payload["query"].(string); !ok || q == "" {
			payload["query"] = "process.name : *"
		}
	}

	// Normalize index pattern (default to ["kubernetes-audit-*", "logs-*"] if omitted)
	var hasIndex bool
	if idxArr, ok := payload["index"].([]interface{}); ok && len(idxArr) > 0 {
		hasIndex = true
	} else if len(rule.Spec.Index) > 0 {
		hasIndex = true
	}
	if !hasIndex {
		payload["index"] = []string{"kubernetes-audit-*", "logs-*", "auditbeat-*"}
	}

	if rule.Status.RuleID != "" {
		payload["rule_id"] = rule.Status.RuleID
	} else if rule.Name != "" {
		payload["rule_id"] = rule.Name
	}

	return payload, nil
}

func (a *ElasticConnection) CreateRule(rule v1.ElasticDetectionRule) (string, error) {
	payload, err := sanitizePayload(rule)
	if err != nil {
		return "", err
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/detection_engine/rules", a.Url)
	respBody, err := a.doRequest("POST", endpoint, jsonData)
	if err != nil {
		return "", err
	}

	var respStruct struct {
		RuleID string `json:"rule_id"`
		ID     string `json:"id"`
	}
	if err := json.Unmarshal(respBody, &respStruct); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	ruleID := respStruct.RuleID
	if ruleID == "" {
		ruleID = respStruct.ID
	}

	return ruleID, nil
}

func (a *ElasticConnection) DeleteRule(ruleid string) ([]byte, error) {
	endpoint := fmt.Sprintf("%s/api/detection_engine/rules?rule_id=%s", a.Url, ruleid)
	response, err := a.doRequest("DELETE", endpoint, nil)
	return response, err
}

func (a *ElasticConnection) UpdateRule(rule v1.ElasticDetectionRule) error {
	payload, err := sanitizePayload(rule)
	if err != nil {
		return err
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal update payload: %w", err)
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
