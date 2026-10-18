package attestation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleValidSRACJSON() string {
	return `{
  "schemaVersion": "0.2-draft",
  "assertionId": "srac-synthetic-brake-monitor-001",
  "subject": {
    "name": "synthetic-brake-monitor",
    "purl": "pkg:generic/synthetic-brake-monitor@1.0.0",
    "version": "1.0.0",
    "repository": "https://example.com/srac/synthetic-brake-monitor"
  },
  "safetyRelevance": {
    "status": "safety-related",
    "classification": "ASIL-B"
  },
  "rationale": "Synthetic component demonstrating reviewed SRAC assertion for safety-critical brake control path.",
  "requirements": [
    {
      "id": "synthetic-req-001",
      "type": "safety-requirement",
      "uri": "https://example.com/srac/requirements/req-001",
      "sha256": "2108209f8a367eb370de5082b034ac015d6c9df9606c7a065c974d5c08344eea"
    }
  ],
  "evidence": [
    {
      "id": "synthetic-analysis-001",
      "type": "safety-analysis",
      "uri": "https://example.com/srac/evidence/analysis-001"
    }
  ],
  "assertion": {
    "status": "reviewed",
    "author": {
      "name": "Safety Systems Lead",
      "uri": "https://example.com/people/safety-lead"
    },
    "reviewer": {
      "name": "Independent Assessor",
      "uri": "https://example.com/people/assessor"
    },
    "created": "2026-09-26T00:00:00Z",
    "updated": "2026-09-26T00:00:00Z"
  }
}`
}

func TestParseSRACAssertion(t *testing.T) {
	raw := []byte(sampleValidSRACJSON())
	assertion, digest, err := ParseSRACAssertion(raw)
	if err != nil {
		t.Fatalf("ParseSRACAssertion failed: %v", err)
	}

	if assertion.AssertionID != "srac-synthetic-brake-monitor-001" {
		t.Errorf("expected assertionId %q, got %q", "srac-synthetic-brake-monitor-001", assertion.AssertionID)
	}
	if assertion.SafetyRelevance.Status != "safety-related" {
		t.Errorf("expected status safety-related, got %q", assertion.SafetyRelevance.Status)
	}
	if assertion.SafetyRelevance.Classification != "ASIL-B" {
		t.Errorf("expected classification ASIL-B, got %q", assertion.SafetyRelevance.Classification)
	}
	if len(digest) != 64 {
		t.Errorf("expected 64-character hex digest, got %q", digest)
	}

	errs := ValidateSRACAssertion(assertion)
	if len(errs) != 0 {
		t.Fatalf("expected 0 validation errors, got: %v", errs)
	}
}

func TestParseSRACFileDirectJSON(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.srac.json")
	if err := os.WriteFile(filePath, []byte(sampleValidSRACJSON()), 0600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	wrapped, err := ParseSRACFile(filePath)
	if err != nil {
		t.Fatalf("ParseSRACFile failed: %v", err)
	}

	if len(wrapped) != 1 {
		t.Fatalf("expected 1 assertion, got %d", len(wrapped))
	}
	if wrapped[0].Assertion.AssertionID != "srac-synthetic-brake-monitor-001" {
		t.Errorf("unexpected assertion ID: %s", wrapped[0].Assertion.AssertionID)
	}
	if wrapped[0].SHA256 == "" {
		t.Errorf("expected non-empty SHA256 digest")
	}
}

func TestParseSRACFileArray(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "array.srac.json")

	content := fmt.Sprintf("[%s, %s]", sampleValidSRACJSON(), sampleValidSRACJSON())
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write array file: %v", err)
	}

	wrapped, err := ParseSRACFile(filePath)
	if err != nil {
		t.Fatalf("ParseSRACFile failed on array: %v", err)
	}

	if len(wrapped) != 2 {
		t.Fatalf("expected 2 assertions, got %d", len(wrapped))
	}
	for i, item := range wrapped {
		if item.Assertion.AssertionID != "srac-synthetic-brake-monitor-001" {
			t.Errorf("item %d: unexpected assertion ID %s", i, item.Assertion.AssertionID)
		}
		if item.SHA256 == "" {
			t.Errorf("item %d: expected non-empty SHA256", i)
		}
	}
}

func TestParseSRACFileInTotoStatement(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "statement.json")

	var predicate map[string]interface{}
	if err := json.Unmarshal([]byte(sampleValidSRACJSON()), &predicate); err != nil {
		t.Fatalf("failed to unmarshal sample: %v", err)
	}

	statement := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://witness.dev/attestations/srac/v0.1",
		"subject": []map[string]interface{}{
			{
				"name": "synthetic-brake-monitor",
				"digest": map[string]string{
					"sha256": "2108209f8a367eb370de5082b034ac015d6c9df9606c7a065c974d5c08344eea",
				},
			},
		},
		"predicate": predicate,
	}

	statementBytes, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("failed to marshal in-toto statement: %v", err)
	}
	if err := os.WriteFile(filePath, statementBytes, 0600); err != nil {
		t.Fatalf("failed to write statement file: %v", err)
	}

	wrapped, err := ParseSRACFile(filePath)
	if err != nil {
		t.Fatalf("ParseSRACFile with in-toto statement failed: %v", err)
	}
	if len(wrapped) != 1 {
		t.Fatalf("expected 1 assertion, got %d", len(wrapped))
	}
	if wrapped[0].Assertion.AssertionID != "srac-synthetic-brake-monitor-001" {
		t.Errorf("unexpected assertion ID: %s", wrapped[0].Assertion.AssertionID)
	}
}

func TestExtractSRACFromTypedAttestations(t *testing.T) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(sampleValidSRACJSON()), &data); err != nil {
		t.Fatalf("failed to unmarshal sample: %v", err)
	}

	attestations := []TypedAttestation{
		{
			Type: "material",
			Data: map[string]interface{}{"materials": map[string]interface{}{}},
		},
		{
			Type: "srac",
			Data: data,
		},
	}

	extracted, err := ExtractSRACFromTypedAttestations(attestations)
	if err != nil {
		t.Fatalf("ExtractSRACFromTypedAttestations failed: %v", err)
	}
	if len(extracted) != 1 {
		t.Fatalf("expected 1 extracted assertion, got %d", len(extracted))
	}
	if extracted[0].Assertion.Subject.Name != "synthetic-brake-monitor" {
		t.Errorf("expected subject name synthetic-brake-monitor, got %s", extracted[0].Assertion.Subject.Name)
	}
}

func TestValidateSRACAssertionErrors(t *testing.T) {
	tests := []struct {
		name          string
		modify        func(*SRACAssertion)
		expectedError string
	}{
		{
			name: "missing schemaVersion",
			modify: func(a *SRACAssertion) {
				a.SchemaVersion = ""
			},
			expectedError: "schemaVersion is required",
		},
		{
			name: "missing assertionId",
			modify: func(a *SRACAssertion) {
				a.AssertionID = ""
			},
			expectedError: "assertionId is required",
		},
		{
			name: "missing subject",
			modify: func(a *SRACAssertion) {
				a.Subject = nil
			},
			expectedError: "subject is required",
		},
		{
			name: "invalid purl prefix",
			modify: func(a *SRACAssertion) {
				a.Subject.PURL = "invalid-purl"
			},
			expectedError: "subject.purl must start with 'pkg:'",
		},
		{
			name: "invalid safetyRelevance status",
			modify: func(a *SRACAssertion) {
				a.SafetyRelevance.Status = "security-related"
			},
			expectedError: "invalid safetyRelevance.status",
		},
		{
			name: "invalid safetyRelevance classification",
			modify: func(a *SRACAssertion) {
				a.SafetyRelevance.Classification = "ULTRA-SAFE"
			},
			expectedError: "invalid safetyRelevance.classification",
		},
		{
			name: "missing rationale",
			modify: func(a *SRACAssertion) {
				a.Rationale = ""
			},
			expectedError: "rationale is required",
		},
		{
			name: "empty evidence",
			modify: func(a *SRACAssertion) {
				a.Evidence = nil
			},
			expectedError: "evidence must contain at least one reference",
		},
		{
			name: "invalid evidence sha256",
			modify: func(a *SRACAssertion) {
				a.Evidence[0].SHA256 = "not-a-sha256"
			},
			expectedError: "must be a 64-character hex string",
		},
		{
			name: "invalid assertion status",
			modify: func(a *SRACAssertion) {
				a.Assertion.Status = "active"
			},
			expectedError: "invalid assertion.status",
		},
		{
			name: "missing author",
			modify: func(a *SRACAssertion) {
				a.Assertion.Author = nil
			},
			expectedError: "assertion.author with name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := []byte(sampleValidSRACJSON())
			assertion, _, err := ParseSRACAssertion(raw)
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			tt.modify(assertion)
			errs := ValidateSRACAssertion(assertion)
			found := false
			for _, e := range errs {
				if strings.Contains(e, tt.expectedError) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected error containing %q, got: %v", tt.expectedError, errs)
			}
		})
	}
}
