package generator

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/sbomit/sbomit/pkg/attestation"
)

// SRACSummary tracks statistics for correlated SRAC assertions.
type SRACSummary struct {
	TotalAssertions     int
	MatchedAssertions   int
	UnmatchedAssertions int
	AmbiguousAssertions int
	InvalidAssertions   int
	StaleAssertions     int
}

// CorrelateSRAC correlates a collection of SRAC assertions with package nodes in an SBOM document.
func (g *Generator) CorrelateSRAC(doc *sbom.Document, assertions []*attestation.SRACAssertionWithRaw, failClosed bool) ([]*attestation.SRACReport, SRACSummary, error) {
	summary := SRACSummary{
		TotalAssertions: len(assertions),
	}
	if len(assertions) == 0 || doc == nil || doc.NodeList == nil {
		return nil, summary, nil
	}

	roots := rootElementSet(doc)
	formatStr := "SPDX"
	if strings.HasPrefix(strings.ToLower(g.opts.OutputFormat), "cdx") || strings.Contains(strings.ToLower(g.opts.OutputFormat), "cyclonedx") {
		formatStr = "CycloneDX"
	}

	reports := make([]*attestation.SRACReport, 0, len(assertions))

	for _, item := range assertions {
		assertion := item.Assertion
		rawDigest := item.SHA256
		locator := item.URI
		if locator == "" {
			if assertion.Subject != nil && assertion.Subject.Repository != "" {
				locator = assertion.Subject.Repository
			} else {
				locator = fmt.Sprintf("urn:srac:%s", assertion.AssertionID)
			}
		}

		report := &attestation.SRACReport{
			SchemaVersion: "0.2-draft",
			SourceFormat:  formatStr,
			AssertionID:   assertion.AssertionID,
			Subject:       assertion.Subject,
			Generator: attestation.SRACGeneratorInfo{
				Name:    "sbomit",
				Version: "0.0.1",
			},
			Integrity: attestation.SRACIntegrity{
				Algorithm:       "SHA-256",
				AssertionSHA256: rawDigest,
			},
		}

		if assertion.SafetyRelevance != nil && assertion.Assertion != nil {
			report.SafetyAssessment = &attestation.SRACSafetyAssessment{
				Source:          "assertion",
				SafetyRelevance: assertion.SafetyRelevance.Status,
				Classification:  assertion.SafetyRelevance.Classification,
				AssertionStatus: assertion.Assertion.Status,
				Reviewer:        assertion.Assertion.Reviewer,
			}
		}
		if len(assertion.ImpactAnalysis) > 0 {
			report.ImpactAnalysis = assertion.ImpactAnalysis
		}
		if assertion.SourceOfTruth != nil {
			report.SourceOfTruth = assertion.SourceOfTruth
		}

		// 1. Validation check
		validationErrors := attestation.ValidateSRACAssertion(assertion)
		if len(validationErrors) > 0 {
			report.MatchStatus = "invalid"
			report.ErrorDetails = fmt.Sprintf("SRAC assertion schema validation failed: %s", strings.Join(validationErrors, "; "))
			summary.InvalidAssertions++
			reports = append(reports, report)
			if failClosed {
				return reports, summary, fmt.Errorf("SRAC validation failed for assertion %s: %s", assertion.AssertionID, report.ErrorDetails)
			}
			continue
		}

		// 2. Staleness check
		if assertion.Assertion.Status == "superseded" || assertion.Assertion.Status == "withdrawn" {
			report.MatchStatus = "stale"
			report.ErrorDetails = fmt.Sprintf("SRAC assertion is stale (status: %s)", assertion.Assertion.Status)
			summary.StaleAssertions++
			reports = append(reports, report)
			if failClosed {
				return reports, summary, fmt.Errorf("SRAC assertion %s is stale with status %s", assertion.AssertionID, assertion.Assertion.Status)
			}
			continue
		}

		// 3. Match candidate components in document
		var matches []candidateMatch

		for _, node := range doc.NodeList.Nodes {
			if !isNonRootPackage(node, roots) {
				continue
			}

			rule := matchComponent(assertion.Subject, node)
			if rule != "" {
				matches = append(matches, candidateMatch{node: node, rule: rule})
			}
		}

		// Deduplicate matches pointing to the same logical package
		uniqueMatches := deduplicateMatches(matches)

		if len(uniqueMatches) == 0 {
			report.MatchStatus = "unmatched"
			report.ErrorDetails = fmt.Sprintf("no package in SBOM matched SRAC subject (purl: %s, name: %s, version: %s)",
				assertion.Subject.PURL, assertion.Subject.Name, assertion.Subject.Version)
			summary.UnmatchedAssertions++
			reports = append(reports, report)
			if failClosed {
				return reports, summary, fmt.Errorf("SRAC assertion %s failed to match any package in generated SBOM (subject: %s@%s)",
					assertion.AssertionID, assertion.Subject.Name, assertion.Subject.Version)
			}
			continue
		}

		if len(uniqueMatches) > 1 {
			report.MatchStatus = "ambiguous"
			var targets []string
			for _, m := range uniqueMatches {
				targets = append(targets, fmt.Sprintf("%s (%s)", m.node.Id, m.rule))
			}
			report.ErrorDetails = fmt.Sprintf("assertion matched %d packages ambiguously: %s", len(uniqueMatches), strings.Join(targets, ", "))
			summary.AmbiguousAssertions++
			reports = append(reports, report)
			if failClosed {
				return reports, summary, fmt.Errorf("SRAC assertion %s matched multiple packages ambiguously: %s",
					assertion.AssertionID, strings.Join(targets, ", "))
			}
			continue
		}

		// Exactly one match: apply external reference and register in report
		match := uniqueMatches[0]
		report.MatchStatus = "matched"
		report.MatchedComponents = []attestation.SRACMatchedComponent{
			{
				Format:     formatStr,
				Identifier: match.node.Id,
				Name:       match.node.Name,
				Version:    match.node.Version,
				PURL:       string(match.node.Purl()),
				Rule:       match.rule,
			},
		}
		summary.MatchedAssertions++

		// Attach integrity-protected external reference
		extRef := &sbom.ExternalReference{
			Url:       locator,
			Type:      sbom.ExternalReference_OTHER,
			Authority: "SRAC",
			Comment:   fmt.Sprintf("SRAC sidecar; SHA-256: %s", rawDigest),
			Hashes: map[int32]string{
				int32(sbom.HashAlgorithm_SHA256): rawDigest,
			},
		}
		match.node.ExternalReferences = append(match.node.ExternalReferences, extRef)

		reports = append(reports, report)
	}

	return reports, summary, nil
}

type candidateMatch struct {
	node *sbom.Node
	rule string
}

func deduplicateMatches(matches []candidateMatch) []candidateMatch {
	if len(matches) <= 1 {
		return matches
	}

	seen := make(map[string]bool)
	var result []candidateMatch
	for _, m := range matches {
		key := m.node.Id
		if string(m.node.Purl()) != "" {
			key = normalizedPURLKey(string(m.node.Purl()))
		}
		if !seen[key] {
			seen[key] = true
			result = append(result, m)
		}
	}
	return result
}

func matchComponent(subject *attestation.SRACSubject, node *sbom.Node) string {
	if subject == nil || node == nil {
		return ""
	}

	nodePURL := string(node.Purl())
	subjectPURL := subject.PURL

	// Rule 1: Exact PURL match
	if nodePURL != "" && subjectPURL != "" {
		if strings.EqualFold(nodePURL, subjectPURL) {
			return "purl-exact"
		}

		// Rule 2: Base PURL + Version match (ignoring query qualifiers/subpaths)
		subjBase, subjVer := purlBaseAndVersion(subjectPURL)
		nodeBase, nodeVer := purlBaseAndVersion(nodePURL)
		expectedVer := subjVer
		if expectedVer == "" {
			expectedVer = subject.Version
		}
		actualVer := nodeVer
		if actualVer == "" {
			actualVer = node.Version
		}
		if subjBase != "" && subjBase == nodeBase && expectedVer != "" && versionMatches(expectedVer, actualVer) {
			return "purl-version"
		}
	}

	// Rule 3: Name + Version match
	if subject.Name != "" && subject.Version != "" {
		if strings.EqualFold(subject.Name, node.Name) && versionMatches(subject.Version, node.Version) {
			return "name-version"
		}
	}

	// Rule 4: ID match
	if node.Id != "" {
		if strings.EqualFold(node.Id, subject.PURL) || strings.EqualFold(node.Id, subject.Name) {
			return "id-match"
		}
	}

	return ""
}

func versionMatches(v1, v2 string) bool {
	v1 = strings.TrimSpace(v1)
	v2 = strings.TrimSpace(v2)
	if v1 == v2 {
		return true
	}
	trimmed1 := strings.TrimPrefix(strings.TrimPrefix(v1, "v"), "V")
	trimmed2 := strings.TrimPrefix(strings.TrimPrefix(v2, "v"), "V")
	return trimmed1 != "" && trimmed1 == trimmed2
}

func purlBaseAndVersion(purl string) (string, string) {
	if purl == "" {
		return "", ""
	}
	withoutQuery, _, _ := strings.Cut(purl, "?")
	withoutSubpath, _, _ := strings.Cut(withoutQuery, "#")
	base, version, found := strings.Cut(withoutSubpath, "@")
	if !found {
		return strings.ToLower(withoutSubpath), ""
	}
	return strings.ToLower(base), version
}

// WriteSRACReport writes the deterministic SRAC enrichment report(s) as JSON.
func WriteSRACReport(w io.Writer, reports []*attestation.SRACReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if len(reports) == 1 {
		return enc.Encode(reports[0])
	}
	return enc.Encode(reports)
}

// WriteSRACFileReport writes the SRAC report to a filesystem destination.
func WriteSRACFileReport(path string, reports []*attestation.SRACReport) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create SRAC report file %s: %w", path, err)
	}
	defer f.Close()
	return WriteSRACReport(f, reports)
}

// WriteSRACSummary outputs a formatted summary of SRAC assertion correlations.
func WriteSRACSummary(w io.Writer, summary SRACSummary) {
	if summary.TotalAssertions == 0 {
		return
	}
	fmt.Fprintln(w, "SRAC Safety Relevance Summary")
	fmt.Fprintln(w, "-----------------------------")
	fmt.Fprintf(w, "Total Assertions: %d\n", summary.TotalAssertions)
	fmt.Fprintf(w, "  Matched: %d\n", summary.MatchedAssertions)
	fmt.Fprintf(w, "  Unmatched: %d\n", summary.UnmatchedAssertions)
	fmt.Fprintf(w, "  Ambiguous: %d\n", summary.AmbiguousAssertions)
	fmt.Fprintf(w, "  Invalid: %d\n", summary.InvalidAssertions)
	fmt.Fprintf(w, "  Stale: %d\n", summary.StaleAssertions)
	fmt.Fprintln(w)
}
