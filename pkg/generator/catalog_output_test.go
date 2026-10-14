package generator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
)

func TestReadCatalogFileErrorHandling(t *testing.T) {
	gen := New(DefaultOptions())

	_, err := gen.readCatalogFile("/non/existent/catalog.spdx.json")
	if err == nil {
		t.Fatal("expected error reading missing catalog file, got nil")
	}
	if !strings.Contains(err.Error(), "failed to read catalog file") {
		t.Errorf("expected 'failed to read catalog file' in error, got: %v", err)
	}

	tmpDir := t.TempDir()
	corruptPath := filepath.Join(tmpDir, "corrupt.json")
	if err := os.WriteFile(corruptPath, []byte("{invalid json"), 0644); err != nil {
		t.Fatalf("failed to write corrupt catalog: %v", err)
	}

	_, err = gen.readCatalogFile(corruptPath)
	if err == nil {
		t.Fatal("expected error parsing corrupt catalog file, got nil")
	}
}

func TestWriteOutputFileFormats(t *testing.T) {
	doc := sbom.NewDocument()
	doc.Metadata.Id = "urn:uuid:test-format-output"
	doc.Metadata.Name = "format-test"
	doc.NodeList.AddRootNode(&sbom.Node{
		Id:   "pkg:generic/root@1.0.0",
		Name: "root",
	})
	doc.NodeList.AddNode(&sbom.Node{
		Id:      "pkg:npm/left-pad@1.3.0",
		Type:    sbom.Node_PACKAGE,
		Name:    "left-pad",
		Version: "1.3.0",
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:npm/left-pad@1.3.0",
		},
	})

	formatsToTest := []struct {
		formatFlag string
		extension  string
	}{
		{"spdx23", "spdx.json"},
		{"cdx14", "cdx14.json"},
		{"cdx15", "cdx15.json"},
	}

	tmpDir := t.TempDir()
	r := reader.New()

	for _, tt := range formatsToTest {
		t.Run(tt.formatFlag, func(t *testing.T) {
			outPath := filepath.Join(tmpDir, "out-"+tt.extension)
			gen := New(&Options{
				OutputFormat: tt.formatFlag,
				OutputPath:   outPath,
			})

			if err := gen.writeOutput(doc); err != nil {
				t.Fatalf("writeOutput failed for format %q: %v", tt.formatFlag, err)
			}

			parsed, err := r.ParseFile(outPath)
			if err != nil {
				t.Fatalf("failed to read back generated SBOM format %q: %v", tt.formatFlag, err)
			}
			if parsed == nil || parsed.NodeList == nil {
				t.Fatalf("expected non-nil parsed document for %q", tt.formatFlag)
			}

			found := false
			for _, node := range parsed.NodeList.Nodes {
				if node != nil && node.Name == "left-pad" {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected package left-pad in round-tripped SBOM for %q", tt.formatFlag)
			}
		})
	}
}

func TestMissingCatalogerExecutableError(t *testing.T) {
	t.Setenv("PATH", "")

	gen := New(DefaultOptions())

	_, errSyft := gen.runSyft("/dummy/project")
	if errSyft == nil || !strings.Contains(errSyft.Error(), "syft not found in PATH") {
		t.Errorf("expected 'syft not found in PATH' error, got: %v", errSyft)
	}

	_, errTrivy := gen.runTrivy("/dummy/project")
	if errTrivy == nil || !strings.Contains(errTrivy.Error(), "trivy not found in PATH") {
		t.Errorf("expected 'trivy not found in PATH' error, got: %v", errTrivy)
	}
}
