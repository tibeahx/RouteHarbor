package maintenance

import (
	"os"
	"path/filepath"
	"testing"
)

// Optional read-only check against actual SDK outputs. Ordinary unit tests do
// not manufacture an SDK success from generated package fixtures.
func TestActualSDKPackageFormatAndGuardBoundary(t *testing.T) {
	dir := os.Getenv("ROUTEHARBOR_SDK_IPK_DIR")
	if dir == "" {
		t.Skip("requires independently built SDK package directory")
	}
	paths, err := filepath.Glob(filepath.Join(dir, "routeharbor*.ipk"))
	if err != nil || len(paths) != 7 {
		t.Fatal("expected seven actual SDK packages", err, len(paths))
	}
	for _, name := range paths {
		t.Run(filepath.Base(name), func(t *testing.T) {
			file, err := os.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			metadata, parseErr := InspectIPK(file)
			closeErr := file.Close()
			if parseErr != nil || closeErr != nil {
				t.Fatal("actual SDK package rejected", parseErr, closeErr)
			}
			t.Logf(
				"%s %s %s: %d expanded bytes, %d payload entries",
				metadata.Name,
				metadata.Version,
				metadata.Architecture,
				metadata.ExpandedBytes,
				len(metadata.Files),
			)
		})
	}
}
