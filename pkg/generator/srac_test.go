package generator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
	"github.com/sbomit/sbomit/pkg/attestation"
)

func validTestSRACAssertionJSON() string {
	return `{
  "schemaVersion": "0.2-draft",
  "assertionId": "srac-synthetic-brake-001",
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
  "rationale": "Synthetic component for illustrative safety-relevant brake monitor verification.",
  "requirements": [
    {
      "id": "req-001",
      "type": "safety-requirement",
      "uri": "https://example.com/srac/requirements/req-001"
    }
  ],
  "evidence": [
    {
      "id": "analysis-001",
      "type": "safety-analysis",
      "uri": "https://example.com/srac/evidence/analysis-001"
    }
  ],
  "assertion": {
    "status": "reviewed",
    "author": {
      "name": "Safety Systems Lead",
      "uri": "https://example.com/people/lead"
    },
    "reviewer": {
      "name": "Assessor",
      "uri": "https://example.com/people/assessor"
    },
    "created": "2026-09-26T00:00:00Z"
  }
}`
}

func createTestDocumentWithPackage(purl, name, version string) *sbom.Document {
	doc := sbom.NewDocument()
	doc.Metadata.Id = "urn:uuid:test-doc"
	doc.Metadata.Name = "test-doc"
	doc.Metadata.Version = "0.0.1"

	rootNode := &sbom.Node{
		Id:   "root-app",
		Type: sbom.Node_PACKAGE,
		Name: "root-app",
	}
	doc.NodeList.AddRootNode(rootNode)

	pkgNode := &sbom.Node{
		Id:      purl,
		Type:    sbom.Node_PACKAGE,
		Name:    name,
		Version: version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): purl,
		},
		Hashes: map[int32]string{
			int32(sbom.HashAlgorithm_SHA256): "2108209f8a367eb370de5082b034ac015d6c9df9606c7a065c974d5c08344eea",
		},
	}
	doc.NodeList.AddNode(pkgNode)
	doc.NodeList.RelateNodeAtID(pkgNode, rootNode.Id, sbom.Edge_contains)
	return doc
}

func TestCorrelateSRACPositiveMatch(t *testing.T) {
	doc := createTestDocumentWithPackage("pkg:generic/synthetic-brake-monitor@1.0.0", "synthetic-brake-monitor", "1.0.0")

	assertionJSON := []byte(validTestSRACAssertionJSON())
	assertion, digest, err := attestation.ParseSRACAssertion(assertionJSON)
	if err != nil {
		t.Fatalf("failed to parse assertion: %v", err)
	}

	assertions := []*attestation.SRACAssertionWithRaw{
		{
			Assertion: assertion,
			RawData:   assertionJSON,
			SHA256:    digest,
			URI:       "https://example.com/srac/synthetic-brake-monitor.srac.json",
		},
	}

	gen := New(&Options{
		OutputFormat:   "spdx23",
		FailClosedSRAC: true,
	})

	reports, summary, err := gen.CorrelateSRAC(doc, assertions, true)
	if err != nil {
		t.Fatalf("CorrelateSRAC failed: %v", err)
	}

	if summary.MatchedAssertions != 1 {
		t.Errorf("expected 1 matched assertion, got %d", summary.MatchedAssertions)
	}
	if summary.UnmatchedAssertions != 0 || summary.AmbiguousAssertions != 0 || summary.InvalidAssertions != 0 {
		t.Errorf("expected 0 failures, got %+v", summary)
	}
	if len(reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(reports))
	}

	rep := reports[0]
	if rep.MatchStatus != "matched" {
		t.Errorf("expected matchStatus 'matched', got %q", rep.MatchStatus)
	}
	if rep.AssertionID != "srac-synthetic-brake-001" {
		t.Errorf("expected assertionId 'srac-synthetic-brake-001', got %q", rep.AssertionID)
	}
	if len(rep.MatchedComponents) != 1 {
		t.Fatalf("expected 1 matched component, got %d", len(rep.MatchedComponents))
	}
	if rep.MatchedComponents[0].PURL != "pkg:generic/synthetic-brake-monitor@1.0.0" {
		t.Errorf("unexpected matched PURL: %s", rep.MatchedComponents[0].PURL)
	}
	if rep.SafetyAssessment == nil || rep.SafetyAssessment.Classification != "ASIL-B" {
		t.Errorf("unexpected safety assessment: %+v", rep.SafetyAssessment)
	}

	// Verify external reference attached to node
	matchedNode := doc.NodeList.Nodes[1]
	if len(matchedNode.ExternalReferences) != 1 {
		t.Fatalf("expected 1 external reference on matched package, got %d", len(matchedNode.ExternalReferences))
	}
	extRef := matchedNode.ExternalReferences[0]
	if extRef.Type != sbom.ExternalReference_OTHER {
		t.Errorf("expected ExternalReference_OTHER, got %v", extRef.Type)
	}
	if !strings.Contains(extRef.Comment, "SRAC sidecar; SHA-256: "+digest) {
		t.Errorf("expected comment with SHA-256 digest, got %q", extRef.Comment)
	}
	if extRef.Hashes[int32(sbom.HashAlgorithm_SHA256)] != digest {
		t.Errorf("expected hash in external reference to be %q, got %q", digest, extRef.Hashes[int32(sbom.HashAlgorithm_SHA256)])
	}
}

func TestCorrelateSRACOutputFormats(t *testing.T) {
	doc := createTestDocumentWithPackage("pkg:generic/synthetic-brake-monitor@1.0.0", "synthetic-brake-monitor", "1.0.0")

	assertionJSON := []byte(validTestSRACAssertionJSON())
	assertion, digest, err := attestation.ParseSRACAssertion(assertionJSON)
	if err != nil {
		t.Fatalf("failed to parse assertion: %v", err)
	}

	assertions := []*attestation.SRACAssertionWithRaw{
		{
			Assertion: assertion,
			RawData:   assertionJSON,
			SHA256:    digest,
			URI:       "https://example.com/srac/synthetic-brake-monitor.srac.json",
		},
	}

	gen := New(&Options{
		OutputFormat:   "spdx23",
		FailClosedSRAC: true,
	})
	if _, _, err := gen.CorrelateSRAC(doc, assertions, true); err != nil {
		t.Fatalf("correlate failed: %v", err)
	}

	tmpDir := t.TempDir()
	w := writer.New()

	// Verify SPDX 2.3 export contains external reference with comment
	spdxPath := filepath.Join(tmpDir, "out.spdx.json")
	if err := w.WriteFileWithOptions(doc, spdxPath, &writer.Options{Format: formats.SPDX23JSON}); err != nil {
		t.Fatalf("SPDX write: %v", err)
	}
	spdxData, err := os.ReadFile(spdxPath)
	if err != nil {
		t.Fatalf("read SPDX: %v", err)
	}
	if !strings.Contains(string(spdxData), "SRAC sidecar; SHA-256: "+digest) {
		t.Errorf("SPDX output missing SRAC sidecar comment")
	}

	// Verify CycloneDX 1.5 export contains external reference with hash
	cdxPath := filepath.Join(tmpDir, "out.cdx.json")
	if err := w.WriteFileWithOptions(doc, cdxPath, &writer.Options{Format: formats.CDX15JSON}); err != nil {
		t.Fatalf("CycloneDX write: %v", err)
	}
	cdxData, err := os.ReadFile(cdxPath)
	if err != nil {
		t.Fatalf("read CycloneDX: %v", err)
	}
	if !strings.Contains(string(cdxData), digest) {
		t.Errorf("CycloneDX output missing SRAC SHA-256 hash")
	}
}

func TestCorrelateSRACUnmatched(t *testing.T) {
	doc := createTestDocumentWithPackage("pkg:generic/other-pkg@1.0.0", "other-pkg", "1.0.0")

	assertionJSON := []byte(validTestSRACAssertionJSON())
	assertion, digest, err := attestation.ParseSRACAssertion(assertionJSON)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	assertions := []*attestation.SRACAssertionWithRaw{
		{Assertion: assertion, RawData: assertionJSON, SHA256: digest},
	}

	gen := New(&Options{OutputFormat: "spdx23"})

	// Fail closed enabled
	_, _, err = gen.CorrelateSRAC(doc, assertions, true)
	if err == nil {
		t.Fatalf("expected error when failClosed=true on unmatched assertion, got nil")
	}
	if !strings.Contains(err.Error(), "failed to match any package") {
		t.Errorf("unexpected error message: %v", err)
	}

	// Fail closed disabled
	reports, summary, err := gen.CorrelateSRAC(doc, assertions, false)
	if err != nil {
		t.Fatalf("unexpected error when failClosed=false: %v", err)
	}
	if summary.UnmatchedAssertions != 1 {
		t.Errorf("expected 1 unmatched, got %d", summary.UnmatchedAssertions)
	}
	if reports[0].MatchStatus != "unmatched" {
		t.Errorf("expected matchStatus 'unmatched', got %q", reports[0].MatchStatus)
	}
}

func TestCorrelateSRACAmbiguous(t *testing.T) {
	doc := sbom.NewDocument()
	doc.NodeList.AddRootNode(&sbom.Node{Id: "root"})

	// Two distinct packages with different PURLs that both match name & version
	pkg1 := &sbom.Node{
		Id:      "pkg:generic/synthetic-brake-monitor@1.0.0",
		Type:    sbom.Node_PACKAGE,
		Name:    "synthetic-brake-monitor",
		Version: "1.0.0",
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:generic/synthetic-brake-monitor@1.0.0",
		},
	}
	pkg2 := &sbom.Node{
		Id:      "pkg:deb/debian/synthetic-brake-monitor@1.0.0",
		Type:    sbom.Node_PACKAGE,
		Name:    "synthetic-brake-monitor",
		Version: "1.0.0",
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:deb/debian/synthetic-brake-monitor@1.0.0",
		},
	}
	doc.NodeList.AddNode(pkg1)
	doc.NodeList.AddNode(pkg2)

	assertionJSON := []byte(validTestSRACAssertionJSON())
	assertion, digest, err := attestation.ParseSRACAssertion(assertionJSON)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	assertions := []*attestation.SRACAssertionWithRaw{
		{Assertion: assertion, RawData: assertionJSON, SHA256: digest},
	}

	gen := New(&Options{OutputFormat: "spdx23"})
	_, _, err = gen.CorrelateSRAC(doc, assertions, true)
	if err == nil {
		t.Fatalf("expected error on ambiguous match, got nil")
	}
	if !strings.Contains(err.Error(), "ambiguously") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCorrelateSRACStaleAssertion(t *testing.T) {
	doc := createTestDocumentWithPackage("pkg:generic/synthetic-brake-monitor@1.0.0", "synthetic-brake-monitor", "1.0.0")

	assertionJSON := []byte(validTestSRACAssertionJSON())
	assertion, digest, err := attestation.ParseSRACAssertion(assertionJSON)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	assertion.Assertion.Status = "superseded"

	assertions := []*attestation.SRACAssertionWithRaw{
		{Assertion: assertion, RawData: assertionJSON, SHA256: digest},
	}

	gen := New(&Options{OutputFormat: "spdx23"})
	_, _, err = gen.CorrelateSRAC(doc, assertions, true)
	if err == nil {
		t.Fatalf("expected error on stale assertion, got nil")
	}
	if !strings.Contains(err.Error(), "stale") {
		t.Errorf("unexpected error: %v", err)
	}

	reports, summary, err := gen.CorrelateSRAC(doc, assertions, false)
	if err != nil {
		t.Fatalf("unexpected error when failClosed=false: %v", err)
	}
	if summary.StaleAssertions != 1 {
		t.Errorf("expected 1 stale assertion, got %d", summary.StaleAssertions)
	}
	if reports[0].MatchStatus != "stale" {
		t.Errorf("expected matchStatus 'stale', got %q", reports[0].MatchStatus)
	}
}

func TestCorrelateSRACInvalidAssertion(t *testing.T) {
	doc := createTestDocumentWithPackage("pkg:generic/synthetic-brake-monitor@1.0.0", "synthetic-brake-monitor", "1.0.0")

	assertionJSON := []byte(validTestSRACAssertionJSON())
	assertion, digest, err := attestation.ParseSRACAssertion(assertionJSON)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	assertion.SafetyRelevance.Status = "invalid-status"

	assertions := []*attestation.SRACAssertionWithRaw{
		{Assertion: assertion, RawData: assertionJSON, SHA256: digest},
	}

	gen := New(&Options{OutputFormat: "spdx23"})
	_, _, err = gen.CorrelateSRAC(doc, assertions, true)
	if err == nil {
		t.Fatalf("expected error on invalid assertion, got nil")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGenerateWithSRACFileAndReport(t *testing.T) {
	tmpDir := t.TempDir()
	sracFile := filepath.Join(tmpDir, "brake.srac.json")
	if err := os.WriteFile(sracFile, []byte(validTestSRACAssertionJSON()), 0600); err != nil {
		t.Fatalf("write srac: %v", err)
	}

	catalogFile := filepath.Join(tmpDir, "catalog.spdx.json")
	catalogDoc := createTestDocumentWithPackage("pkg:generic/synthetic-brake-monitor@1.0.0", "synthetic-brake-monitor", "1.0.0")
	if err := writer.New().WriteFileWithOptions(catalogDoc, catalogFile, &writer.Options{Format: formats.SPDX23JSON}); err != nil {
		t.Fatalf("write catalog: %v", err)
	}

	reportFile := filepath.Join(tmpDir, "srac-report.json")
	sbomOut := filepath.Join(tmpDir, "out.spdx.json")

	gen := New(&Options{
		DocumentName:    "test-srac-gen",
		DocumentVersion: "1.0.0",
		OutputFormat:    "spdx23",
		OutputPath:      sbomOut,
		CatalogFile:     catalogFile,
		SRACFile:        sracFile,
		SRACReport:      reportFile,
		FailClosedSRAC:  true,
	})

	doc, err := gen.GenerateFromAttestations(nil)
	if err != nil {
		t.Fatalf("GenerateFromAttestations failed: %v", err)
	}
	if doc == nil {
		t.Fatalf("expected non-nil document")
	}

	// Verify report file
	reportData, err := os.ReadFile(reportFile)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var report attestation.SRACReport
	if err := json.Unmarshal(reportData, &report); err != nil {
		t.Fatalf("unmarshal report JSON: %v", err)
	}
	if report.MatchStatus != "matched" {
		t.Errorf("expected report matchStatus 'matched', got %q", report.MatchStatus)
	}
	if report.AssertionID != "srac-synthetic-brake-001" {
		t.Errorf("expected assertion ID srac-synthetic-brake-001, got %q", report.AssertionID)
	}
	if len(report.MatchedComponents) != 1 {
		t.Fatalf("expected 1 matched component in report, got %d", len(report.MatchedComponents))
	}

	// Verify SBOM output file
	sbomBytes, err := os.ReadFile(sbomOut)
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}
	if !strings.Contains(string(sbomBytes), "SRAC sidecar") {
		t.Errorf("expected output SBOM to contain SRAC sidecar reference")
	}
}
