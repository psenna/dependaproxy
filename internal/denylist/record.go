package denylist

import (
	"bytes"
	"errors"
	"time"

	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/middleware/validation/cve"
	"github.com/psenna/dependaproxy/internal/middleware/validation/guarddog"
	"github.com/psenna/dependaproxy/internal/pipeline"
)

// DefaultRecordedMiddlewares are the validation middlewares whose failures are
// a real deny verdict worth persisting. min-publication-age is time-based and
// self-resolves, so it is deliberately excluded; unknown middlewares are
// excluded too.
var DefaultRecordedMiddlewares = []string{"guarddog-scan", "malware-scan", "cve-check"}

// Recorder returns an OnFailure hook that persists a denial. Best-effort:
// it can never change the deny decision.
//
// It records only real verdicts from the allowlist (defaulting to
// DefaultRecordedMiddlewares when no allowlist is given), skipping time-based
// rejections (min-publication-age) and transient fail_closed scanner/source
// failures (guarddog.ErrScannerUnavailable, cve.ErrSourceUnavailable). A
// record failure is warn-logged and swallowed.
func Recorder(s Store, now func() time.Time, allowlist ...string) func(*pipeline.PipelineContext, error) {
	recorded := allowlist
	if len(recorded) == 0 {
		recorded = DefaultRecordedMiddlewares
	}
	return func(ctx *pipeline.PipelineContext, err error) {
		if ctx == nil {
			return
		}
		// No artifact to hash: nothing to deny by.
		if ctx.Tarball == nil || len(ctx.Tarball.Bytes) == 0 {
			return
		}
		var ve *pipeline.ValidationError
		if !errors.As(err, &ve) {
			return
		}
		if !allowlisted(recorded, ve.Middleware) {
			return
		}
		// A fail_closed scanner crash is infrastructure, not a verdict: skip.
		if errors.Is(err, guarddog.ErrScannerUnavailable) || errors.Is(err, cve.ErrSourceUnavailable) {
			return
		}
		h, ok := ctx.Sha256FromMetadata()
		if !ok {
			// Defensive fallback: serveUntrusted stashes the hash before running
			// the validation chain, so this is only reachable for direct callers
			// (tests) or future non-serveUntrusted uses. Recompute to keep
			// behavior identical.
			var herr error
			h, _, herr = hash.Sha256Hex(bytes.NewReader(ctx.Tarball.Bytes))
			if herr != nil {
				return
			}
		}
		d := Denial{
			Registry:   ctx.Registry,
			Name:       ctx.PkgName,
			Version:    ctx.Version,
			ArtifactID: ctx.ArtifactID,
			Sha256:     h,
			ProjectKey: ctx.ProjectKey,
			Reason:     err.Error(),
			Middleware: ve.Middleware,
			DeniedAt:   now(),
		}
		if rerr := s.Record(ctx.Ctx, d); rerr != nil {
			// Best-effort: never propagate, never change the deny decision.
			if ctx.Log != nil {
				ctx.Log.Warn("denylist: failed to record denial (deny decision unchanged)",
					"package", ctx.PkgName, "version", ctx.Version, "err", rerr)
			}
		}
	}
}

// allowlisted reports whether mw is a member of the recorded allowlist.
func allowlisted(recorded []string, mw string) bool {
	for _, r := range recorded {
		if r == mw {
			return true
		}
	}
	return false
}
