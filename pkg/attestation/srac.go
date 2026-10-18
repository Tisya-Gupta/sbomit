package attestation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

var sha256Regex = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// SRACAssertion represents an externally authored Safety Relevance Assertion Capability record.
type SRACAssertion struct {
	SchemaVersion   string                 `json:"schemaVersion"`
	AssertionID     string                 `json:"assertionId"`
	Subject         *SRACSubject           `json:"subject"`
	SafetyRelevance *SRACSafetyRelevance   `json:"safetyRelevance"`
	Rationale       string                 `json:"rationale"`
	Requirements    []SRACReference        `json:"requirements,omitempty"`
	Evidence        []SRACReference        `json:"evidence"`
	ImpactAnalysis  []SRACImpactAnalysis   `json:"impactAnalysis,omitempty"`
	SourceOfTruth   *SRACSourceOfTruth     `json:"sourceOfTruth,omitempty"`
	Assertion       *SRACLifecycle         `json:"assertion"`
}

// SRACSubject identifies the software component the safety assertion applies to.
type SRACSubject struct {
	Name          string `json:"name"`
	PURL          string `json:"purl"`
	Version       string `json:"version"`
	Repository    string `json:"repository,omitempty"`
	ComponentPath string `json:"componentPath,omitempty"`
}

// SRACSafetyRelevance captures the functional-safety relevance and integrity classification.
type SRACSafetyRelevance struct {
	Status         string `json:"status"`
	Classification string `json:"classification"`
}

// SRACReference links to requirements, evidence, or external artifacts.
type SRACReference struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	URI    string `json:"uri"`
	SHA256 string `json:"sha256,omitempty"`
}

// SRACImpactAnalysis captures optional change-impact analysis for a safety-relevant component.
type SRACImpactAnalysis struct {
	ID                      string                       `json:"id"`
	Trigger                 SRACAnalysisTrigger          `json:"trigger"`
	ImpactAnalysisStatus    string                       `json:"impactAnalysisStatus"`
	ImpactLevel             string                       `json:"impactLevel,omitempty"`
	SafetyIntegrityLevel    string                       `json:"safetyIntegrityLevel,omitempty"`
	ImpactAnalysisProcess   *SRACURIReference            `json:"impactAnalysisProcess,omitempty"`
	Rationale               string                       `json:"rationale,omitempty"`
	ImpactedElement         []string                     `json:"impactedElement"`
	AddedElement            []string                     `json:"addedElement"`
	ModifiedElement         []string                     `json:"modifiedElement"`
	RemovedElement          []string                     `json:"removedElement"`
	Decisions               []SRACDecision               `json:"decisions"`
	RequirementVerification []SRACRequirementVerification `json:"requirementVerification,omitempty"`
	Bundle                  *SRACBundle                  `json:"bundle,omitempty"`
}

// SRACAnalysisTrigger records the event that triggered safety reassessment.
type SRACAnalysisTrigger struct {
	ID   string `json:"id,omitempty"`
	Type string `json:"type"`
	URI  string `json:"uri"`
}

// SRACURIReference holds a URI reference.
type SRACURIReference struct {
	URI string `json:"uri"`
}

// SRACDecision represents a review or release decision associated with an impact analysis.
type SRACDecision struct {
	ID             string     `json:"id,omitempty"`
	DecisionType   string     `json:"decisionType"`
	DecisionStatus string     `json:"decisionStatus"`
	AppliesTo      []string   `json:"appliesTo"`
	OriginatedBy   *SRACParty `json:"originatedBy,omitempty"`
	Rationale      string     `json:"rationale"`
}

// SRACRequirementVerification connects verification activities with safety requirements.
type SRACRequirementVerification struct {
	ID        string   `json:"id"`
	Verifies  []string `json:"verifies"`
	Evidence  []string `json:"evidence"`
	Rationale string   `json:"rationale,omitempty"`
}

// SRACBundle identifies the published graph roots of an impact analysis.
type SRACBundle struct {
	ID          string   `json:"id"`
	RootElement []string `json:"rootElement"`
}

// SRACSourceOfTruth points to an authoritative lifecycle repository record (e.g. Sphinx-Needs).
type SRACSourceOfTruth struct {
	System            string   `json:"system"`
	DocumentURI       string   `json:"documentUri"`
	Version           string   `json:"version"`
	RootElement       string   `json:"rootElement"`
	RootElementType   string   `json:"rootElementType"`
	RootElementStatus string   `json:"rootElementStatus"`
	IncludedElements  []string `json:"includedElements"`
	SHA256            string   `json:"sha256"`
}

// SRACParty represents an author, reviewer, or organization.
type SRACParty struct {
	Name string `json:"name"`
	URI  string `json:"uri,omitempty"`
}

// SRACLifecycle tracks authoring, review, and publication status.
type SRACLifecycle struct {
	Status   string     `json:"status"`
	Author   *SRACParty `json:"author"`
	Reviewer *SRACParty `json:"reviewer,omitempty"`
	Created  string     `json:"created"`
	Updated  string     `json:"updated,omitempty"`
}

// SRACAssertionWithRaw packages the parsed assertion with its raw byte payload and SHA-256 digest.
type SRACAssertionWithRaw struct {
	Assertion *SRACAssertion
	RawData   []byte
	SHA256    string
	URI       string
}

// SRACReport defines the deterministic enrichment report schema for SRAC correlation.
type SRACReport struct {
	SchemaVersion       string                 `json:"schemaVersion"`
	SourceFormat        string                 `json:"sourceFormat"`
	AssertionID         string                 `json:"assertionId"`
	Subject             *SRACSubject           `json:"subject"`
	SafetyAssessment    *SRACSafetyAssessment  `json:"safetyAssessment"`
	MatchedComponents   []SRACMatchedComponent `json:"matchedComponents"`
	MatchStatus         string                 `json:"matchStatus"`
	Generator           SRACGeneratorInfo      `json:"generator"`
	Integrity           SRACIntegrity          `json:"integrity"`
	ErrorDetails        string                 `json:"errorDetails,omitempty"`
	ImpactAnalysis      []SRACImpactAnalysis   `json:"impactAnalysis,omitempty"`
	SourceOfTruth       *SRACSourceOfTruth     `json:"sourceOfTruth,omitempty"`
	DiscoveredReference map[string]string      `json:"discoveredReference,omitempty"`
}

// SRACSafetyAssessment carries the safety relevance context copied verbatim from the assertion.
type SRACSafetyAssessment struct {
	Source          string     `json:"source"`
	SafetyRelevance string     `json:"safetyRelevance"`
	Classification  string     `json:"classification"`
	AssertionStatus string     `json:"assertionStatus"`
	Reviewer        *SRACParty `json:"reviewer"`
}

// SRACMatchedComponent describes an SBOM component matched to the SRAC subject.
type SRACMatchedComponent struct {
	Format     string `json:"format"`
	Identifier string `json:"identifier"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	PURL       string `json:"purl"`
	Rule       string `json:"rule"`
}

// SRACGeneratorInfo identifies the SBOM generation tool.
type SRACGeneratorInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SRACIntegrity holds verification digests for the assertion and SBOM.
type SRACIntegrity struct {
	Algorithm       string `json:"algorithm"`
	AssertionSHA256 string `json:"assertionSha256"`
	SBOMSHA256      string `json:"sbomSha256,omitempty"`
}

// ComputeSHA256 returns the lowercase hex representation of the SHA-256 hash of data.
func ComputeSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// ParseSRACAssertion decodes JSON bytes into an SRACAssertion and calculates its SHA-256 digest.
func ParseSRACAssertion(data []byte) (*SRACAssertion, string, error) {
	var assertion SRACAssertion
	if err := json.Unmarshal(data, &assertion); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal SRAC assertion: %w", err)
	}
	digest := ComputeSHA256(data)
	return &assertion, digest, nil
}

// ParseSRACFile reads SRAC assertion(s) from a file. It automatically supports standalone
// SRAC JSON, JSON arrays of assertions, in-toto statements, and DSSE envelopes.
func ParseSRACFile(path string) ([]*SRACAssertionWithRaw, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read SRAC file: %w", err)
	}

	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		var list []json.RawMessage
		if err := json.Unmarshal(data, &list); err != nil {
			return nil, fmt.Errorf("failed to parse JSON array from %s: %w", path, err)
		}
		var result []*SRACAssertionWithRaw
		for _, item := range list {
			assertion, digest, err := ParseSRACAssertion(item)
			if err != nil {
				return nil, err
			}
			result = append(result, &SRACAssertionWithRaw{
				Assertion: assertion,
				RawData:   item,
				SHA256:    digest,
				URI:       path,
			})
		}
		return result, nil
	}

	var topLevel map[string]json.RawMessage
	if err := json.Unmarshal(data, &topLevel); err != nil {
		return nil, fmt.Errorf("failed to parse JSON from %s: %w", path, err)
	}

	// 1. Direct SRAC assertion JSON
	if _, hasSchemaVersion := topLevel["schemaVersion"]; hasSchemaVersion {
		if _, hasAssertionID := topLevel["assertionId"]; hasAssertionID {
			assertion, digest, err := ParseSRACAssertion(data)
			if err != nil {
				return nil, err
			}
			return []*SRACAssertionWithRaw{
				{
					Assertion: assertion,
					RawData:   data,
					SHA256:    digest,
					URI:       path,
				},
			}, nil
		}
	}

	// 2. Direct in-toto statement
	if _, hasPredicate := topLevel["predicate"]; hasPredicate {
		var statement InTotoStatement
		if err := json.Unmarshal(data, &statement); err != nil {
			return nil, fmt.Errorf("failed to unmarshal in-toto statement: %w", err)
		}
		return parseSRACFromInTotoStatement(statement, data, path)
	}

	// 3. DSSE envelope
	var rawEnvelope struct {
		PayloadType string          `json:"payloadType"`
		Payload     json.RawMessage `json:"payload"`
		Signatures  []Signature     `json:"signatures"`
	}
	if err := json.Unmarshal(data, &rawEnvelope); err == nil && len(rawEnvelope.Payload) > 0 {
		payload, err := decodeEnvelopePayload(rawEnvelope.Payload)
		if err != nil {
			return nil, fmt.Errorf("failed to decode envelope payload: %w", err)
		}

		trimmedPayload := strings.TrimSpace(string(payload))
		if strings.HasPrefix(trimmedPayload, "[") {
			var list []json.RawMessage
			if err := json.Unmarshal(payload, &list); err == nil {
				var result []*SRACAssertionWithRaw
				for _, item := range list {
					assertion, digest, err := ParseSRACAssertion(item)
					if err != nil {
						return nil, err
					}
					result = append(result, &SRACAssertionWithRaw{
						Assertion: assertion,
						RawData:   item,
						SHA256:    digest,
						URI:       path,
					})
				}
				return result, nil
			}
		}

		var statement InTotoStatement
		if err := json.Unmarshal(payload, &statement); err == nil && statement.Predicate != nil {
			return parseSRACFromInTotoStatement(statement, payload, path)
		}

		assertion, digest, err := ParseSRACAssertion(payload)
		if err != nil {
			return nil, err
		}
		return []*SRACAssertionWithRaw{
			{
				Assertion: assertion,
				RawData:   payload,
				SHA256:    digest,
				URI:       path,
			},
		}, nil
	}

	return nil, fmt.Errorf("file %s is not a recognized SRAC assertion or signed in-toto statement", path)
}

func parseSRACFromInTotoStatement(statement InTotoStatement, rawData []byte, path string) ([]*SRACAssertionWithRaw, error) {
	var result []*SRACAssertionWithRaw
	if attestationsRaw, ok := statement.Predicate["attestations"]; ok {
		if attestationsList, ok := attestationsRaw.([]interface{}); ok {
			for _, att := range attestationsList {
				attMap, ok := att.(map[string]interface{})
				if !ok {
					continue
				}
				rawType, _ := attMap["type"].(string)
				if canonicalAttestationType(rawType) != "srac" {
					continue
				}
				attData, ok := attMap["attestation"].(map[string]interface{})
				if !ok {
					continue
				}
				marshaled, err := json.Marshal(attData)
				if err != nil {
					return nil, fmt.Errorf("failed to serialize SRAC attestation data: %w", err)
				}
				assertion, digest, err := ParseSRACAssertion(marshaled)
				if err != nil {
					return nil, err
				}
				result = append(result, &SRACAssertionWithRaw{
					Assertion: assertion,
					RawData:   marshaled,
					SHA256:    digest,
					URI:       path,
				})
			}
			if len(result) > 0 {
				return result, nil
			}
		}
	}

	// Single statement predicate
	marshaled, err := json.Marshal(statement.Predicate)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize predicate: %w", err)
	}
	assertion, digest, err := ParseSRACAssertion(marshaled)
	if err != nil {
		return nil, err
	}
	return []*SRACAssertionWithRaw{
		{
			Assertion: assertion,
			RawData:   marshaled,
			SHA256:    digest,
			URI:       path,
		},
	}, nil
}

// ExtractSRACFromTypedAttestations searches for all "srac" typed attestations in a parsed slice.
func ExtractSRACFromTypedAttestations(attestations []TypedAttestation) ([]*SRACAssertionWithRaw, error) {
	var result []*SRACAssertionWithRaw
	for _, att := range attestations {
		if att.Type != "srac" {
			continue
		}
		if len(att.Data) == 0 {
			continue
		}
		marshaled, err := json.Marshal(att.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal SRAC attestation data: %w", err)
		}
		assertion, digest, err := ParseSRACAssertion(marshaled)
		if err != nil {
			return nil, err
		}
		uri := ""
		if assertion.Subject != nil && assertion.Subject.Repository != "" {
			uri = assertion.Subject.Repository
		}
		if uri == "" && assertion.AssertionID != "" {
			uri = fmt.Sprintf("urn:srac:%s", assertion.AssertionID)
		}
		result = append(result, &SRACAssertionWithRaw{
			Assertion: assertion,
			RawData:   marshaled,
			SHA256:    digest,
			URI:       uri,
		})
	}
	return result, nil
}

// ValidateSRACAssertion validates an SRAC assertion against the minimum required profile.
func ValidateSRACAssertion(a *SRACAssertion) []string {
	var errors []string
	if a == nil {
		return []string{"assertion is nil"}
	}

	if strings.TrimSpace(a.SchemaVersion) == "" {
		errors = append(errors, "schemaVersion is required")
	}
	if strings.TrimSpace(a.AssertionID) == "" {
		errors = append(errors, "assertionId is required")
	}

	// Subject validation
	if a.Subject == nil {
		errors = append(errors, "subject is required")
	} else {
		if strings.TrimSpace(a.Subject.Name) == "" {
			errors = append(errors, "subject.name is required")
		}
		if strings.TrimSpace(a.Subject.PURL) == "" {
			errors = append(errors, "subject.purl is required")
		} else if !strings.HasPrefix(a.Subject.PURL, "pkg:") {
			errors = append(errors, "subject.purl must start with 'pkg:'")
		}
		if strings.TrimSpace(a.Subject.Version) == "" {
			errors = append(errors, "subject.version is required")
		}
		if a.Subject.Repository != "" {
			if _, err := url.ParseRequestURI(a.Subject.Repository); err != nil {
				errors = append(errors, fmt.Sprintf("subject.repository is not a valid URI: %s", a.Subject.Repository))
			}
		}
	}

	// Safety relevance validation
	if a.SafetyRelevance == nil {
		errors = append(errors, "safetyRelevance is required")
	} else {
		validStatuses := map[string]bool{
			"safety-related":     true,
			"not-safety-related": true,
			"undetermined":       true,
		}
		if !validStatuses[a.SafetyRelevance.Status] {
			errors = append(errors, fmt.Sprintf("invalid safetyRelevance.status %q; must be one of safety-related, not-safety-related, undetermined", a.SafetyRelevance.Status))
		}

		validClassifications := map[string]bool{
			"QM":           true,
			"ASIL-A":       true,
			"ASIL-B":       true,
			"ASIL-C":       true,
			"ASIL-D":       true,
			"SIL-1":        true,
			"SIL-2":        true,
			"SIL-3":        true,
			"SIL-4":        true,
			"DAL-A":        true,
			"DAL-B":        true,
			"DAL-C":        true,
			"DAL-D":        true,
			"DAL-E":        true,
			"Class A":      true,
			"Class B":      true,
			"Class C":      true,
			"not-assigned": true,
		}
		if !validClassifications[a.SafetyRelevance.Classification] {
			errors = append(errors, fmt.Sprintf("invalid safetyRelevance.classification %q", a.SafetyRelevance.Classification))
		}
	}

	if strings.TrimSpace(a.Rationale) == "" {
		errors = append(errors, "rationale is required")
	}

	if len(a.Evidence) == 0 {
		errors = append(errors, "evidence must contain at least one reference")
	}
	for i, ev := range a.Evidence {
		if strings.TrimSpace(ev.ID) == "" {
			errors = append(errors, fmt.Sprintf("evidence[%d].id is required", i))
		}
		if strings.TrimSpace(ev.Type) == "" {
			errors = append(errors, fmt.Sprintf("evidence[%d].type is required", i))
		}
		if strings.TrimSpace(ev.URI) == "" {
			errors = append(errors, fmt.Sprintf("evidence[%d].uri is required", i))
		}
		if ev.SHA256 != "" && !sha256Regex.MatchString(ev.SHA256) {
			errors = append(errors, fmt.Sprintf("evidence[%d].sha256 must be a 64-character hex string", i))
		}
	}

	for i, req := range a.Requirements {
		if strings.TrimSpace(req.ID) == "" {
			errors = append(errors, fmt.Sprintf("requirements[%d].id is required", i))
		}
		if strings.TrimSpace(req.Type) == "" {
			errors = append(errors, fmt.Sprintf("requirements[%d].type is required", i))
		}
		if strings.TrimSpace(req.URI) == "" {
			errors = append(errors, fmt.Sprintf("requirements[%d].uri is required", i))
		}
		if req.SHA256 != "" && !sha256Regex.MatchString(req.SHA256) {
			errors = append(errors, fmt.Sprintf("requirements[%d].sha256 must be a 64-character hex string", i))
		}
	}

	// Lifecycle assertion validation
	if a.Assertion == nil {
		errors = append(errors, "assertion is required")
	} else {
		validAssertionStatuses := map[string]bool{
			"draft":        true,
			"under-review": true,
			"reviewed":     true,
			"approved":     true,
			"superseded":   true,
			"withdrawn":    true,
		}
		if !validAssertionStatuses[a.Assertion.Status] {
			errors = append(errors, fmt.Sprintf("invalid assertion.status %q; must be one of draft, under-review, reviewed, approved, superseded, withdrawn", a.Assertion.Status))
		}
		if a.Assertion.Author == nil || strings.TrimSpace(a.Assertion.Author.Name) == "" {
			errors = append(errors, "assertion.author with name is required")
		}
		if strings.TrimSpace(a.Assertion.Created) == "" {
			errors = append(errors, "assertion.created is required")
		}
	}

	// Impact analysis validation (if present)
	for i, ia := range a.ImpactAnalysis {
		if strings.TrimSpace(ia.ID) == "" {
			errors = append(errors, fmt.Sprintf("impactAnalysis[%d].id is required", i))
		}
		if strings.TrimSpace(ia.Trigger.Type) == "" || strings.TrimSpace(ia.Trigger.URI) == "" {
			errors = append(errors, fmt.Sprintf("impactAnalysis[%d].trigger requires type and uri", i))
		}
		if strings.TrimSpace(ia.ImpactAnalysisStatus) == "" {
			errors = append(errors, fmt.Sprintf("impactAnalysis[%d].impactAnalysisStatus is required", i))
		}
		for j, dec := range ia.Decisions {
			if strings.TrimSpace(dec.DecisionType) == "" || strings.TrimSpace(dec.DecisionStatus) == "" {
				errors = append(errors, fmt.Sprintf("impactAnalysis[%d].decisions[%d] requires decisionType and decisionStatus", i, j))
			}
			if len(dec.AppliesTo) == 0 {
				errors = append(errors, fmt.Sprintf("impactAnalysis[%d].decisions[%d].appliesTo must not be empty", i, j))
			}
		}
	}

	return errors
}
