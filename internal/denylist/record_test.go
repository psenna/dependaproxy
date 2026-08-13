package denylist

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/middleware/cveosv"
	"github.com/psenna/dependaproxy/internal/middleware/validation/cve"
	"github.com/psenna/dependaproxy/internal/middleware/validation/guarddog"
	"github.com/psenna/dependaproxy/internal/pipeline"
)

// recorderFakeStore records every Record call and its captured Denials. err injects a
// Record failure; Lookup is unused by the recorder but required by Store.
type recorderFakeStore struct {
	recorded []Denial
	err      error
}

var _ Store = (*recorderFakeStore)(nil)

func (f *recorderFakeStore) Record(_ context.Context, d Denial) error {
	f.recorded = append(f.recorded, d)
	return f.err
}

func (f *recorderFakeStore) Lookup(context.Context, string, string, string, string, string) (string, bool, error) {
	return "", false, nil
}

func fixedNow() time.Time {
	return time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
}

// testPipelineCtx builds a minimal PipelineContext with a non-empty tarball and
// a project key, mirroring how adapters set it up before validation.
func testPipelineCtx(t *testing.T) *pipeline.PipelineContext {
	t.Helper()
	ctx := pipeline.NewPipelineContext(context.Background(), slog.New(slog.DiscardHandler), "npm", "lodash", "4.17.20", "")
	ctx.ProjectKey = "proj-1"
	ctx.Tarball = &pipeline.Tarball{Bytes: []byte("some-artifact-bytes")}
	return ctx
}

func wantSha(t *testing.T, b []byte) string {
	t.Helper()
	h, _, err := hash.Sha256Hex(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return h
}

func TestRecorderRecordsAllowlistedMiddleware(t *testing.T) {
	f := &recorderFakeStore{}
	hook := Recorder(f, fixedNow)

	ctx := testPipelineCtx(t)
	ve := &pipeline.ValidationError{
		Middleware: "guarddog-scan",
		Err:        errors.New("guarddog-scan: lodash@4.17.20 flagged: malicious-exec"),
	}
	hook(ctx, ve)

	if len(f.recorded) != 1 {
		t.Fatalf("Record calls = %d want 1", len(f.recorded))
	}
	want := Denial{
		Registry:   ctx.Registry,
		Name:       ctx.PkgName,
		Version:    ctx.Version,
		ArtifactID: ctx.ArtifactID,
		Sha256:     wantSha(t, ctx.Tarball.Bytes),
		ProjectKey: ctx.ProjectKey,
		Reason:     ve.Error(),
		Middleware: "guarddog-scan",
		DeniedAt:   fixedNow(),
	}
	got := f.recorded[0]
	if got != want {
		t.Errorf("Denial = %+v\nwant      %+v", got, want)
	}
}

func TestRecorderUsesMetadataSha256(t *testing.T) {
	f := &recorderFakeStore{}
	hook := Recorder(f, fixedNow)

	ctx := testPipelineCtx(t)
	preset := strings.Repeat("cd", 32) // 64-hex string, != sha256("some-artifact-bytes")
	ctx.Metadata["sha256"] = preset
	hook(ctx, &pipeline.ValidationError{Middleware: "guarddog-scan", Err: errors.New("boom")})

	if len(f.recorded) != 1 {
		t.Fatalf("Record calls = %d want 1", len(f.recorded))
	}
	if got := f.recorded[0].Sha256; got != preset {
		t.Errorf("Sha256 = %q, want preset %q (must read the stash, not recompute)", got, preset)
	}
}

func TestRecorderFallbackHashesWhenMetadataAbsent(t *testing.T) {
	f := &recorderFakeStore{}
	hook := Recorder(f, fixedNow)

	ctx := testPipelineCtx(t) // no "sha256" metadata preset
	hook(ctx, &pipeline.ValidationError{Middleware: "guarddog-scan", Err: errors.New("boom")})

	if len(f.recorded) != 1 {
		t.Fatalf("Record calls = %d want 1", len(f.recorded))
	}
	want := wantSha(t, ctx.Tarball.Bytes)
	if got := f.recorded[0].Sha256; got != want {
		t.Errorf("Sha256 = %q, want %q", got, want)
	}
}

func TestRecorderSkipsNilOrEmptyTarball(t *testing.T) {
	cases := []*pipeline.Tarball{
		nil,
		{Bytes: nil},
		{Bytes: []byte{}},
	}
	for _, tb := range cases {
		f := &recorderFakeStore{}
		ctx := testPipelineCtx(t)
		ctx.Tarball = tb
		hook := Recorder(f, fixedNow)
		hook(ctx, &pipeline.ValidationError{Middleware: "guarddog-scan", Err: errors.New("boom")})
		if len(f.recorded) != 0 {
			t.Fatalf("Record calls = %d want 0 for tarball %+v", len(f.recorded), tb)
		}
	}
}

func TestRecorderSkipsNonValidationError(t *testing.T) {
	f := &recorderFakeStore{}
	ctx := testPipelineCtx(t)
	hook := Recorder(f, fixedNow)
	hook(ctx, errors.New("some unrelated pipeline error"))
	if len(f.recorded) != 0 {
		t.Fatalf("Record calls = %d want 0", len(f.recorded))
	}
}

func TestRecorderSkipsNonAllowlistedMiddleware(t *testing.T) {
	f := &recorderFakeStore{}
	ctx := testPipelineCtx(t)
	hook := Recorder(f, fixedNow)
	hook(ctx, &pipeline.ValidationError{Middleware: "min-publication-age", Err: errors.New("too new")})
	if len(f.recorded) != 0 {
		t.Fatalf("Record calls = %d want 0", len(f.recorded))
	}
}

func TestRecorderCustomAllowlist(t *testing.T) {
	// A custom allowlist {"cve-check"} records a cve-check failure and skips a
	// guarddog-scan failure (not in the allowlist), overriding the default.
	f := &recorderFakeStore{}
	hook := Recorder(f, fixedNow, "cve-check")

	ctx := testPipelineCtx(t)
	hook(ctx, &pipeline.ValidationError{Middleware: "cve-check", Err: errors.New("cve-check: deny")})
	hook(ctx, &pipeline.ValidationError{Middleware: "guarddog-scan", Err: errors.New("guarddog-scan: flagged: malicious-exec")})

	if len(f.recorded) != 1 {
		t.Fatalf("Record calls = %d want 1 (only cve-check allowlisted)", len(f.recorded))
	}
	if got := f.recorded[0].Middleware; got != "cve-check" {
		t.Errorf("Middleware = %q want %q", got, "cve-check")
	}
}

func TestRecorderSkipsTransientScannerFailures(t *testing.T) {
	cases := []struct {
		name       string
		middleware string
		err        error
	}{
		{
			name:       "guarddog scanner unavailable",
			middleware: "guarddog-scan",
			err:        fmt.Errorf("guarddog-scan: %w", errors.Join(guarddog.ErrScannerUnavailable, errors.New("binary crash"))),
		},
		{
			name:       "cve source unavailable",
			middleware: "cve-check",
			err:        fmt.Errorf("cve-check: %w", errors.Join(cve.ErrSourceUnavailable, errors.New("endpoint down"))),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &recorderFakeStore{}
			ctx := testPipelineCtx(t)
			hook := Recorder(f, fixedNow)
			hook(ctx, &pipeline.ValidationError{Middleware: tc.middleware, Err: tc.err})
			if len(f.recorded) != 0 {
				t.Fatalf("Record calls = %d want 0", len(f.recorded))
			}
		})
	}
}

func TestRecorderBestEffortOnRecordError(t *testing.T) {
	f := &recorderFakeStore{err: errors.New("db down")}
	ctx := testPipelineCtx(t)
	hook := Recorder(f, fixedNow)

	// Must not panic, and must not propagate the error to the caller.
	ve := &pipeline.ValidationError{Middleware: "cve-check", Err: errors.New("cve-check: deny")}
	hook(ctx, ve)

	if len(f.recorded) != 1 {
		t.Fatalf("Record calls = %d want 1 (record attempted despite injected failure)", len(f.recorded))
	}
}

func TestRecorderRecordsNonTransientCVEDenyVerdict(t *testing.T) {
	f := &recorderFakeStore{}
	hook := Recorder(f, fixedNow)

	ctx := testPipelineCtx(t)
	vulns := []cveosv.Vuln{{ID: "CVE-2021-1234", Summary: "rce"}}
	ve := &pipeline.ValidationError{
		Middleware: "cve-check",
		Err:        fmt.Errorf("cve-check: %s", cveosv.BuildDenyMessage(ctx.PkgName, ctx.Version, vulns, "")),
	}
	hook(ctx, ve)

	if len(f.recorded) != 1 {
		t.Fatalf("Record calls = %d want 1", len(f.recorded))
	}
	got := f.recorded[0]
	if got.Middleware != "cve-check" {
		t.Errorf("Middleware = %q want %q", got.Middleware, "cve-check")
	}
	if got.Reason != ve.Error() {
		t.Errorf("Reason = %q want %q", got.Reason, ve.Error())
	}
	if !got.DeniedAt.Equal(fixedNow()) {
		t.Errorf("DeniedAt = %v want %v", got.DeniedAt, fixedNow())
	}
	if got.Sha256 != wantSha(t, ctx.Tarball.Bytes) {
		t.Errorf("Sha256 = %q want %q", got.Sha256, wantSha(t, ctx.Tarball.Bytes))
	}
}
