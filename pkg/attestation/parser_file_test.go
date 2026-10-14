package attestation

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseWitnessFileWithSampleAttestation(t *testing.T) {
	filePath := filepath.Join("..", "..", "test", "sample-attestation.json")

	attestations, err := ParseWitnessFile(filePath, nil)
	if err != nil {
		t.Fatalf("unexpected error parsing witness file: %v", err)
	}

	if len(attestations) == 0 {
		t.Fatal("expected non-empty attestations parsed from sample file")
	}

	typesFound := make(map[string]bool)
	for _, a := range attestations {
		typesFound[a.Type] = true
	}

	if !typesFound["command-run"] || !typesFound["material"] || !typesFound["product"] {
		t.Errorf("expected command-run, material, and product attestations in parsed file")
	}

	filtered, err := ParseWitnessFile(filePath, []string{"product"})
	if err != nil {
		t.Fatalf("unexpected error parsing filtered witness file: %v", err)
	}
	if len(filtered) == 0 {
		t.Fatal("expected at least one product attestation with type filter")
	}
	for _, a := range filtered {
		if a.Type != "product" {
			t.Errorf("expected only product type, got: %q", a.Type)
		}
	}
}

func TestParseWitnessFileMissingFile(t *testing.T) {
	_, err := ParseWitnessFile("/does/not/exist.json", nil)
	if err == nil {
		t.Fatal("expected error reading non-existent file, got nil")
	}
	if !strings.Contains(err.Error(), "failed to read witness file") {
		t.Errorf("expected 'failed to read witness file' in error message, got: %v", err)
	}
}

func TestParseWitnessDataEmbeddedRawJSONPayload(t *testing.T) {
	statementJSON := `{
		"_type": "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://witness.dev/attestations/material/v0.1",
		"predicate": {
			"attestations": [
				{
					"type": "material",
					"attestation": {
						"materials": {
							"main.go": {
								"sha256": "aabbccddeeff"
							}
						}
					}
				}
			]
		}
	}`

	envelope := map[string]interface{}{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     json.RawMessage(statementJSON),
		"signatures":  []map[string]string{},
	}

	envelopeBytes, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	attestations, err := ParseWitnessData(envelopeBytes, nil)
	if err != nil {
		t.Fatalf("unexpected error parsing embedded raw JSON payload: %v", err)
	}

	if len(attestations) != 1 {
		t.Fatalf("expected 1 attestation, got %d", len(attestations))
	}
	if attestations[0].Type != "material" {
		t.Errorf("expected type 'material', got %q", attestations[0].Type)
	}

	materials, ok := attestations[0].Data["materials"].(map[string]interface{})
	if !ok || len(materials) != 1 {
		t.Fatalf("expected materials map with 1 entry, got: %+v", attestations[0].Data)
	}
}

func TestParseWitnessDataUnsupportedPayloadFormat(t *testing.T) {
	envelope := map[string]interface{}{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     12345,
		"signatures":  []map[string]string{},
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	_, err = ParseWitnessData(data, nil)
	if err == nil {
		t.Fatal("expected error for numeric payload, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported payload format") {
		t.Errorf("expected 'unsupported payload format' in error, got: %v", err)
	}
}

func TestExtractFilesFromAttestationsTopLevel(t *testing.T) {
	attestations := []TypedAttestation{
		{
			Type: "material",
			Data: map[string]interface{}{
				"materials": map[string]interface{}{
					"go.mod": map[string]interface{}{
						"sha256": "123456",
					},
				},
			},
		},
	}

	files := ExtractFilesFromAttestations(attestations, []string{"material"})
	if len(files) != 1 {
		t.Fatalf("expected 1 extracted file, got %d", len(files))
	}
	if files[0].Path != "go.mod" || files[0].Hashes["sha256"] != "123456" {
		t.Errorf("unexpected extracted file details: %+v", files[0])
	}
}
