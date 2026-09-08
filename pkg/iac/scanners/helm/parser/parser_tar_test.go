package parser

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"helm.sh/helm/v3/pkg/chart/loader"
)

// buildArchive returns a gzipped tar holding one regular entry per size in sizes.
// Entries are zero bytes, so the archive stays tiny however large they decompress
// to - the shape of a decompression bomb.
func buildArchive(t *testing.T, sizes ...int64) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)

	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "chart/", Typeflag: tar.TypeDir, Mode: 0o755,
	}))

	for i, size := range sizes {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     "chart/file" + string(rune('a'+i)) + ".yaml",
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     size,
		}))
		_, err := tw.Write(bytes.Repeat([]byte{'x'}, int(size)))
		require.NoError(t, err)
	}

	require.NoError(t, tw.Close())
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func parseArchive(t *testing.T, data []byte) error {
	t.Helper()
	p, err := New(".")
	require.NoError(t, err)
	return p.ParseFS(t.Context(), fstest.MapFS{
		"chart.tar.gz": {Data: data},
	}, "chart.tar.gz")
}

// CVE-2026-54448: unpackArchive used to read every entry with an unbounded
// io.ReadAll, so a small archive could decompress to gigabytes and OOM the
// scanner. It now enforces the Helm SDK limits.
func TestUnpackArchiveEnforcesDecompressionLimits(t *testing.T) {
	// Shrink the Helm limits so the test does not have to build a 100 MiB archive.
	origFile, origChart := loader.MaxDecompressedFileSize, loader.MaxDecompressedChartSize
	loader.MaxDecompressedFileSize, loader.MaxDecompressedChartSize = 1024, 2048
	t.Cleanup(func() {
		loader.MaxDecompressedFileSize, loader.MaxDecompressedChartSize = origFile, origChart
	})

	t.Run("single entry over the per-file limit is rejected", func(t *testing.T) {
		err := parseArchive(t, buildArchive(t, loader.MaxDecompressedFileSize+1))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "larger than the maximum file size")
	})

	t.Run("entries summing over the per-archive limit are rejected", func(t *testing.T) {
		// Each entry is within the per-file limit; together they blow the budget.
		err := parseArchive(t, buildArchive(t, 1024, 1024, 1024))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "larger than the maximum size")
	})

	t.Run("archive within the limits still parses", func(t *testing.T) {
		require.NoError(t, parseArchive(t, buildArchive(t, 512, 512)))
	})
}
