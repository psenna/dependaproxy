// Package guarddog implements a validation middleware that scans a fetched
// package artifact with the GuardDog CLI (https://github.com/DataDog/guarddog).
// It is the repo's first subprocess middleware: instead of doing the analysis
// in-process, it shells out to the guarddog binary via exec.CommandContext,
// writing the tarball the pipeline already fetched to a temp file and running
// `guarddog <eco> scan <file> --output-format=json` against it.
//
// GuardDog covers the npm and PyPI ecosystems only; other registries (e.g.
// maven, goproxy) are skipped. On findings the middleware rejects the package
// (mode: deny, the default) or allows it with a log + Metadata annotation
// (mode: warn). A GuardDog invocation failure follows on_error: fail_open (the
// default) serves the package, fail_closed rejects it.
//
// There is no in-memory cache in v1: the trust store dedups repeated scans of
// the same artifact, so caching here would be redundant.
package guarddog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// Defaults used when the corresponding param is omitted.
const (
	name           = "guarddog-scan"
	DefaultMode    = "deny"
	DefaultOnError = "fail_open"
	DefaultTimeout = 60 * time.Second
	maxStdout      = 32 << 20
)

// Modes and error policies.
const (
	modeDeny        = "deny"
	modeWarn        = "warn"
	onErrFailOpen   = "fail_open"
	onErrFailClosed = "fail_closed"
)

// Finding is one GuardDog rule hit in the JSON scan report. GuardDog emits
// findings under results[<rule>] with location/code/match/message; RuleName is
// not in the JSON — it is the results map key, populated by parse.
type Finding struct {
	RuleName string `json:"-"`
	Location string `json:"location"`
	Code     string `json:"code"`
	Match    string `json:"match"`
	Message  string `json:"message"`
}

// Runner scans one artifact. It is an interface so tests can inject a fake and
// the real implementation (execRunner) can be exercised end-to-end.
type Runner interface {
	Scan(ctx context.Context, eco, artifactName string, artifact []byte) ([]Finding, error)
}

// Params is the yaml-decoded configuration for the guarddog-scan middleware.
type Params struct {
	Mode    string        `yaml:"mode"`
	OnError string        `yaml:"on_error"`
	Timeout time.Duration `yaml:"timeout"`
	// Sandbox is a *bool so an unset param (nil) can be distinguished from an
	// explicit false: nil defaults to true (GuardDog's sandbox on).
	Sandbox *bool  `yaml:"sandbox"`
	Binary  string `yaml:"binary"`
}

// Middleware is the GuardDog-backed validation middleware.
type Middleware struct {
	runner  Runner
	mode    string // deny (default) | warn
	onError string // fail_open (default) | fail_closed
}

// Name returns the config type string.
func (*Middleware) Name() string { return name }

// New constructs a guarddog-scan middleware. Empty mode/on_error/binary and
// non-positive timeout fall back to the defaults; a nil sandbox defaults to
// true. A nil runner builds the real execRunner from the params.
func New(pr Params, runner Runner) *Middleware {
	mode := pr.Mode
	if mode == "" {
		mode = DefaultMode
	}
	onError := pr.OnError
	if onError == "" {
		onError = DefaultOnError
	}
	timeout := pr.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	binary := pr.Binary
	if binary == "" {
		binary = "guarddog"
	}
	sandbox := true
	if pr.Sandbox != nil {
		sandbox = *pr.Sandbox
	}
	if runner == nil {
		runner = &execRunner{binary: binary, timeout: timeout, sandbox: sandbox}
	}
	return &Middleware{runner: runner, mode: mode, onError: onError}
}

// Validate scans ctx.Tarball.Bytes (already fetched by the pipeline) with
// GuardDog and applies the configured mode/on_error to the result.
func (m *Middleware) Validate(ctx *pipeline.PipelineContext) error {
	eco, ok := ecoFor(ctx.Registry)
	if !ok {
		// Not a registry GuardDog covers (e.g. maven, goproxy); nothing to check.
		return nil
	}
	if ctx.Tarball == nil || len(ctx.Tarball.Bytes) == 0 {
		if ctx.Log != nil {
			ctx.Log.Warn("guarddog-scan: no artifact bytes to scan", "package", ctx.PkgName, "version", ctx.Version)
		}
		return nil
	}
	findings, err := m.runner.Scan(ctx.Ctx, eco, ctx.ArtifactID, ctx.Tarball.Bytes)
	if err != nil {
		return m.applyError(ctx, err)
	}
	return m.apply(ctx, findings)
}

// ecoFor maps a pipeline registry name to a GuardDog ecosystem. GuardDog covers
// npm and PyPI only; anything else returns ok=false so callers skip the scan.
// This deliberately does NOT reuse cveosv.Ecosystem, which maps goproxy to "Go"
// — GuardDog has no Go support.
func ecoFor(registry string) (string, bool) {
	switch registry {
	case "npm", "pypi":
		return registry, true
	default:
		return "", false
	}
}

// apply enforces the configured mode on the scan findings.
func (m *Middleware) apply(ctx *pipeline.PipelineContext, findings []Finding) error {
	if len(findings) == 0 {
		return nil
	}
	summary := summarize(findings)
	switch m.mode {
	case modeWarn:
		if ctx.Log != nil {
			ctx.Log.Warn("guarddog-scan: package flagged (served in warn mode)",
				"package", ctx.PkgName, "version", ctx.Version, "rules", summary)
		}
		ctx.Metadata["guarddog"] = findings
		return nil
	default: // deny
		return fmt.Errorf("guarddog-scan: %s@%s flagged: %s", ctx.PkgName, ctx.Version, summary)
	}
}

// summarize joins the finding rule names for the deny/warn message.
func summarize(findings []Finding) string {
	names := make([]string, 0, len(findings))
	for _, f := range findings {
		names = append(names, f.RuleName)
	}
	return strings.Join(names, ", ")
}

// applyError handles a GuardDog invocation failure per on_error.
func (m *Middleware) applyError(ctx *pipeline.PipelineContext, err error) error {
	switch m.onError {
	case onErrFailClosed:
		if ctx.Log != nil {
			ctx.Log.Error("guarddog-scan: scanner unavailable; rejecting (fail_closed)", "err", err)
		}
		return fmt.Errorf("guarddog-scan: %w", err)
	default: // fail_open
		if ctx.Log != nil {
			ctx.Log.Warn("guarddog-scan: scanner unavailable; serving (fail_open)", "err", err)
		}
		return nil
	}
}

// Factory builds the middleware from its raw params node, registered by each
// adapter under "guarddog-scan".
func Factory(r Runner) pipeline.ValidationFactory {
	return func(p yaml.Node) (pipeline.ValidationMiddleware, error) {
		var pr Params
		if !p.IsZero() {
			if err := p.Decode(&pr); err != nil {
				return nil, fmt.Errorf("%s: decode params: %w", name, err)
			}
		}
		return New(pr, r), nil
	}
}

// execRunner is the real Runner: it writes the artifact to a temp file and runs
// the GuardDog CLI against it.
type execRunner struct {
	binary  string
	timeout time.Duration
	sandbox bool
}

// Scan writes artifact to a temp file and runs
// `guarddog --log-level=error <eco> scan <file> --output-format=json`. The
// JSON report is parsed into findings. --log-level is a GuardDog GLOBAL option
// and must precede the ecosystem subcommand; --output-format and --no-sandbox
// are per-scan options and stay after it.
func (r *execRunner) Scan(ctx context.Context, eco, artifactName string, artifact []byte) ([]Finding, error) {
	dir, absPath, err := writeTemp(eco, artifactName, artifact)
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	scanCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	args := []string{"--log-level=error", eco, "scan", absPath, "--output-format=json"}
	if !r.sandbox {
		args = append(args, "--no-sandbox")
	}
	//nolint:gosec // binary path is config-controlled, not user input
	cmd := exec.CommandContext(scanCtx, r.binary, args...)
	var stdout limitWriter
	var stderr limitWriter
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	return r.parse(stdout.buf.Bytes(), runErr, stderr.buf.String())
}

// limitWriter caps the captured stdout/stderr at maxStdout bytes: anything
// beyond is dropped (the child keeps draining, so it never blocks on a full
// pipe) and the full length is reported so the child's writes always succeed.
// Bounding both streams prevents a verbose/misconfigured binary from exhausting
// proxy memory.
type limitWriter struct {
	buf bytes.Buffer
}

var _ io.Writer = (*limitWriter)(nil)

func (w *limitWriter) Write(p []byte) (int, error) {
	n := len(p)
	room := maxStdout - w.buf.Len()
	if room > 0 {
		if len(p) > room {
			p = p[:room]
		}
		_, _ = w.buf.Write(p)
	}
	return n, nil
}

// writeTemp writes the artifact to a temp file and returns the temp dir and the
// absolute file path. The absolute path is REQUIRED: GuardDog treats a bare
// argument as a registry package name (GuardDog issue #175), so a relative path
// would be scanned as a package rather than a file.
func writeTemp(eco, artifactName string, artifact []byte) (dir, absPath string, err error) {
	dir, err = os.MkdirTemp("", "guarddog-scan-*")
	if err != nil {
		return "", "", err
	}
	absPath = filepath.Join(dir, "artifact"+extFor(eco, artifactName))
	if err = os.WriteFile(absPath, artifact, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", "", err
	}
	return dir, absPath, nil
}

// extFor picks the artifact extension GuardDog expects for the ecosystem.
func extFor(eco, artifactName string) string {
	switch eco {
	case "npm":
		return ".tgz"
	case "pypi":
		if artifactName != "" {
			return filepath.Base(artifactName)
		}
		return ".tar.gz"
	default:
		return ".bin"
	}
}

// report is the GuardDog JSON scan output (guarddog 3.x, --output-format=json):
//
//	{
//	  "package": "<path>",
//	  "results": { "<rule>": [ {location, code, match, message}, ... ] | {} },
//	  "errors":  { "<step>": "<message>" },
//	  "issues":  <int count>,
//	  "risk_score": {...}, "risks": [...]
//	}
//
// results is a map of rule name to findings (a rule with no hits is an empty
// object, so each value is kept as raw JSON and decoded per-rule); errors is
// non-empty when the scan itself failed (e.g. a download error); issues is a
// count, not an array.
type report struct {
	Results map[string]json.RawMessage `json:"results"`
	Errors  map[string]string          `json:"errors"`
	Issues  int                        `json:"issues"`
}

// parse decodes the GuardDog JSON report. Findings are collected from every
// results[<rule>] entry (RuleName set from the map key); a rule with no hits
// (an empty object, which cannot unmarshal into a slice) is skipped. A
// non-empty errors map means the scan failed and is surfaced as an error so
// on_error governs. On a parse failure the scan is treated as an error only
// when the process itself failed (runErr) or wrote to stderr; a clean exit
// with unparsable stdout yields no findings.
func (r *execRunner) parse(stdout []byte, runErr error, stderr string) ([]Finding, error) {
	var rep report
	if err := json.Unmarshal(stdout, &rep); err != nil {
		if runErr != nil || stderr != "" {
			return nil, fmt.Errorf("guarddog-scan: parse output (stderr: %s): %w", strings.TrimSpace(stderr), err)
		}
		return nil, nil
	}
	if len(rep.Errors) > 0 {
		return nil, fmt.Errorf("guarddog-scan: scan reported errors: %s", summarizeErrors(rep.Errors))
	}
	var findings []Finding
	for rule, raw := range rep.Results {
		var hits []Finding
		if err := json.Unmarshal(raw, &hits); err != nil {
			continue // e.g. {} — a rule with no hits
		}
		for _, f := range hits {
			f.RuleName = rule
			findings = append(findings, f)
		}
	}
	return findings, nil
}

// summarizeErrors joins the GuardDog errors map for the error message.
func summarizeErrors(errs map[string]string) string {
	parts := make([]string, 0, len(errs))
	for step, msg := range errs {
		parts = append(parts, step+": "+msg)
	}
	return strings.Join(parts, "; ")
}
