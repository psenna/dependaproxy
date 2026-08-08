package guarddog

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

func testCtx(registry, pkg, version, artifactID string, tarball []byte) *pipeline.PipelineContext {
	ctx := pipeline.NewPipelineContext(context.Background(), slog.New(slog.DiscardHandler), registry, pkg, version, artifactID)
	if tarball != nil {
		ctx.Tarball = &pipeline.Tarball{Bytes: tarball}
	}
	return ctx
}

// fakeRunner records the Scan invocation and returns canned findings/err.
type fakeRunner struct {
	findings []Finding
	err      error
	gotEco   string
	gotName  string
	called   bool
}

func (f *fakeRunner) Scan(_ context.Context, eco, artifactName string, _ []byte) ([]Finding, error) {
	f.called = true
	f.gotEco = eco
	f.gotName = artifactName
	return f.findings, f.err
}

func boolPtr(b bool) *bool { return &b }

// stubBinary writes a #!/bin/sh script to a temp dir that cats the given
// stdout/stderr (from pre-written files, so empty content emits nothing) and
// exits with the given code. When GD_ARGS_FILE is set in the environment it
// also writes its args one-per-line to that file (exec.Cmd inherits the parent
// env when cmd.Env is nil).
func stubBinary(t *testing.T, stdout, stderr string, exit int) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "guarddog-stub-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	script := filepath.Join(dir, "guarddog-stub")
	outFile := filepath.Join(dir, "stdout")
	errFile := filepath.Join(dir, "stderr")
	if err := os.WriteFile(outFile, []byte(stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(errFile, []byte(stderr), 0o600); err != nil {
		t.Fatal(err)
	}
	body := "#!/bin/sh\n" +
		"if [ -n \"$GD_ARGS_FILE\" ]; then\n" +
		"  : > \"$GD_ARGS_FILE\"\n" +
		"  for a in \"$@\"; do\n" +
		"    printf '%s\\n' \"$a\" >> \"$GD_ARGS_FILE\"\n" +
		"  done\n" +
		"fi\n" +
		"cat \"" + outFile + "\"\n" +
		"cat \"" + errFile + "\" >&2\n" +
		"exit " + strconv.Itoa(exit) + "\n"
	//nolint:gosec // the stub script must be executable
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script
}

// makeTarGz builds a minimal gzipped tar archive in-memory (used only by the
// real-guarddog test; #85 is the real e2e).
func makeTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

func TestCleanPasses(t *testing.T) {
	m := New(Params{}, &fakeRunner{})
	if err := m.Validate(testCtx("npm", "testpkg", "1.0.0", "", []byte("tarball"))); err != nil {
		t.Fatalf("a clean scan should pass, got %v", err)
	}
}

func TestFindingsDenyRejects(t *testing.T) {
	m := New(Params{}, &fakeRunner{findings: []Finding{
		{RuleName: "R1"}, {RuleName: "R2"},
	}})
	ctx := testCtx("npm", "testpkg", "1.0.0", "", []byte("tarball"))
	err := m.Validate(ctx)
	if err == nil {
		t.Fatal("deny mode should reject on findings")
	}
	if !strings.Contains(err.Error(), "testpkg@1.0.0") {
		t.Fatalf("error should name package@version, got: %v", err)
	}
	if !strings.Contains(err.Error(), "R1") || !strings.Contains(err.Error(), "R2") {
		t.Fatalf("error should list both rule names, got: %v", err)
	}
	if _, ok := ctx.Metadata["guarddog"]; ok {
		t.Fatal("deny mode should not annotate metadata")
	}
}

func TestFindingsWarnAnnotates(t *testing.T) {
	m := New(Params{Mode: "warn"}, &fakeRunner{findings: []Finding{
		{RuleName: "R1"}, {RuleName: "R2"},
	}})
	ctx := testCtx("npm", "testpkg", "1.0.0", "", []byte("tarball"))
	if err := m.Validate(ctx); err != nil {
		t.Fatalf("warn mode should accept, got %v", err)
	}
	findings, ok := ctx.Metadata["guarddog"].([]Finding)
	if !ok || len(findings) != 2 {
		t.Fatalf("warn mode should record findings in metadata, got %#v", ctx.Metadata["guarddog"])
	}
}

func TestFailOpenOnScanError(t *testing.T) {
	m := New(Params{}, &fakeRunner{err: errors.New("boom")})
	if err := m.Validate(testCtx("npm", "testpkg", "1.0.0", "", []byte("tarball"))); err != nil {
		t.Fatalf("fail_open should accept on scan error, got %v", err)
	}
}

func TestFailClosedOnScanError(t *testing.T) {
	m := New(Params{OnError: "fail_closed"}, &fakeRunner{err: errors.New("boom")})
	err := m.Validate(testCtx("npm", "testpkg", "1.0.0", "", []byte("tarball")))
	if err == nil {
		t.Fatal("fail_closed should reject on scan error")
	}
	if !strings.Contains(err.Error(), "guarddog-scan:") {
		t.Fatalf("error should be prefixed with guarddog-scan:, got: %v", err)
	}
}

func TestEmptyTarballPasses(t *testing.T) {
	fr := &fakeRunner{}
	m := New(Params{}, fr)
	if err := m.Validate(testCtx("npm", "testpkg", "1.0.0", "", nil)); err != nil {
		t.Fatalf("a nil tarball should pass, got %v", err)
	}
	if fr.called {
		t.Fatal("scanner should not be invoked for a nil tarball")
	}
}

func TestUnknownRegistrySkipped(t *testing.T) {
	fr := &fakeRunner{}
	m := New(Params{}, fr)
	if err := m.Validate(testCtx("maven", "g:a", "1.0", "", []byte("tarball"))); err != nil {
		t.Fatalf("an unscanned registry should pass, got %v", err)
	}
	if fr.called {
		t.Fatal("scanner should not be invoked for an unknown registry")
	}
}

func TestEcoMapping(t *testing.T) {
	for _, reg := range []string{"npm", "pypi"} {
		fr := &fakeRunner{}
		m := New(Params{}, fr)
		ctx := testCtx(reg, "testpkg", "1.0.0", "testpkg-1.0.0.tar.gz", []byte("tarball"))
		if err := m.Validate(ctx); err != nil {
			t.Fatalf("%s should pass, got %v", reg, err)
		}
		if !fr.called {
			t.Fatalf("%s should invoke the scanner", reg)
		}
		if fr.gotEco != reg {
			t.Fatalf("%s: expected eco %q, got %q", reg, reg, fr.gotEco)
		}
		if fr.gotName != ctx.ArtifactID {
			t.Fatalf("%s: expected artifact name %q, got %q", reg, ctx.ArtifactID, fr.gotName)
		}
	}
}

func TestFactoryDecodesParams(t *testing.T) {
	var n yaml.Node
	// yaml.v3 decodes time.Duration from a string only (an int is rejected), so
	// the timeout is expressed as "30s" rather than a raw nanosecond count.
	if err := n.Encode(map[string]any{
		"mode": "warn", "on_error": "fail_closed", "timeout": "30s", "binary": "/usr/bin/guarddog",
	}); err != nil {
		t.Fatal(err)
	}
	mw, err := Factory(nil)(n)
	if err != nil {
		t.Fatalf("factory should decode valid params: %v", err)
	}
	m := mw.(*Middleware)
	if m.mode != "warn" || m.onError != "fail_closed" {
		t.Fatalf("unexpected decoded params: mode=%q on_error=%q", m.mode, m.onError)
	}
	er, ok := m.runner.(*execRunner)
	if !ok {
		t.Fatalf("runner should be *execRunner, got %T", m.runner)
	}
	if er.binary != "/usr/bin/guarddog" || er.timeout != 30*time.Second || !er.sandbox {
		t.Fatalf("unexpected execRunner: binary=%q timeout=%v sandbox=%v", er.binary, er.timeout, er.sandbox)
	}
}

func TestFactoryDefaults(t *testing.T) {
	var n yaml.Node // zero value: IsZero() true
	mw, err := Factory(nil)(n)
	if err != nil {
		t.Fatalf("factory should default empty params: %v", err)
	}
	m := mw.(*Middleware)
	if m.mode != "deny" || m.onError != "fail_open" {
		t.Fatalf("unexpected defaults: mode=%q on_error=%q", m.mode, m.onError)
	}
	er, ok := m.runner.(*execRunner)
	if !ok {
		t.Fatalf("runner should be *execRunner, got %T", m.runner)
	}
	if er.binary != "guarddog" || er.timeout != 60*time.Second || !er.sandbox {
		t.Fatalf("unexpected execRunner defaults: binary=%q timeout=%v sandbox=%v", er.binary, er.timeout, er.sandbox)
	}
}

func TestFactorySandboxFalse(t *testing.T) {
	var n yaml.Node
	if err := n.Encode(map[string]any{"sandbox": false}); err != nil {
		t.Fatal(err)
	}
	mw, err := Factory(nil)(n)
	if err != nil {
		t.Fatalf("factory should decode sandbox: %v", err)
	}
	er := mw.(*Middleware).runner.(*execRunner)
	if er.sandbox {
		t.Fatal("sandbox:false should disable the sandbox")
	}
}

func TestExecRunnerArgConstruction(t *testing.T) {
	bin := stubBinary(t, "", "", 0)
	argsFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("GD_ARGS_FILE", argsFile)
	r := New(Params{Binary: bin}, nil).runner.(*execRunner)
	if _, err := r.Scan(context.Background(), "npm", "", []byte("tarball-bytes")); err != nil {
		t.Fatalf("scan should succeed: %v", err)
	}
	//nolint:gosec // argsFile is a test-controlled temp path
	//nolint:gosec // argsFile is a test-controlled temp path
	got, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(string(got)), "\n")
	if len(args) != 5 {
		t.Fatalf("expected 5 args, got %v", args)
	}
	// --log-level is a GuardDog global option and must precede the subcommand.
	if args[0] != "--log-level=error" || args[1] != "npm" || args[2] != "scan" || args[4] != "--output-format=json" {
		t.Fatalf("unexpected args: %v", args)
	}
	if !filepath.IsAbs(args[3]) {
		t.Fatalf("artifact path should be absolute, got %q", args[3])
	}
	if !strings.HasSuffix(args[3], ".tgz") {
		t.Fatalf("npm artifact should end in .tgz, got %q", args[3])
	}
}

func TestExecRunnerNoSandboxFlag(t *testing.T) {
	bin := stubBinary(t, "", "", 0)
	argsFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("GD_ARGS_FILE", argsFile)
	r := New(Params{Binary: bin, Sandbox: boolPtr(false)}, nil).runner.(*execRunner)
	if _, err := r.Scan(context.Background(), "npm", "", []byte("x")); err != nil {
		t.Fatalf("scan should succeed: %v", err)
	}
	//nolint:gosec // argsFile is a test-controlled temp path
	got, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "--no-sandbox") {
		t.Fatalf("expected --no-sandbox in args, got %q", got)
	}
}

func TestExecRunnerSandboxOnOmitsFlag(t *testing.T) {
	bin := stubBinary(t, "", "", 0)
	argsFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("GD_ARGS_FILE", argsFile)
	r := New(Params{Binary: bin, Sandbox: boolPtr(true)}, nil).runner.(*execRunner)
	if _, err := r.Scan(context.Background(), "npm", "", []byte("x")); err != nil {
		t.Fatalf("scan should succeed: %v", err)
	}
	//nolint:gosec // argsFile is a test-controlled temp path
	got, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "--no-sandbox") {
		t.Fatalf("sandbox on should omit --no-sandbox, got %q", got)
	}
}

func TestExecRunnerJsonParseResultsMap(t *testing.T) {
	bin := stubBinary(t, `{"results":{"R1":[{"location":"pkg/package.json:1","code":"c","match":"m","message":"has_npm_hook rule matched"}]},"errors":{},"issues":1}`, "", 0)
	r := New(Params{Binary: bin}, nil).runner.(*execRunner)
	findings, err := r.Scan(context.Background(), "npm", "", []byte("x"))
	if err != nil {
		t.Fatalf("scan should succeed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %#v", findings)
	}
	if findings[0].RuleName != "R1" || findings[0].Location != "pkg/package.json:1" || findings[0].Message != "has_npm_hook rule matched" {
		t.Fatalf("finding should carry the rule name (from the map key) and real fields, got %#v", findings[0])
	}
}

func TestExecRunnerJsonParseEmptyRuleSkipped(t *testing.T) {
	// A rule with no hits is an empty object {} and must contribute nothing.
	bin := stubBinary(t, `{"results":{"R1":{},"R2":[{"location":"x","code":"c","match":"m","message":"msg"}]},"errors":{},"issues":1}`, "", 0)
	r := New(Params{Binary: bin}, nil).runner.(*execRunner)
	findings, err := r.Scan(context.Background(), "npm", "", []byte("x"))
	if err != nil {
		t.Fatalf("scan should succeed: %v", err)
	}
	if len(findings) != 1 || findings[0].RuleName != "R2" {
		t.Fatalf("expected only the R2 finding, got %#v", findings)
	}
}

func TestExecRunnerJsonParseMultipleRulesCollected(t *testing.T) {
	bin := stubBinary(t, `{"results":{"R1":[{"location":"a","code":"c","match":"m","message":"m1"}],"R2":[{"location":"b","code":"c","match":"m","message":"m2"}]},"errors":{},"issues":2}`, "", 0)
	r := New(Params{Binary: bin}, nil).runner.(*execRunner)
	findings, err := r.Scan(context.Background(), "npm", "", []byte("x"))
	if err != nil {
		t.Fatalf("scan should succeed: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %#v", findings)
	}
	names := map[string]bool{}
	for _, f := range findings {
		names[f.RuleName] = true
	}
	if !names["R1"] || !names["R2"] {
		t.Fatalf("expected findings from both rules, got %#v", findings)
	}
}

func TestExecRunnerJsonParseErrorsSurfaced(t *testing.T) {
	// A non-empty errors map means the scan failed (e.g. a download error); it
	// must surface as an error so on_error governs (fail_open serves, fail_closed
	// rejects).
	bin := stubBinary(t, `{"results":{},"errors":{"download-package":"Received status code: 404 from npm"},"issues":0}`, "", 0)
	r := New(Params{Binary: bin}, nil).runner.(*execRunner)
	_, err := r.Scan(context.Background(), "npm", "", []byte("x"))
	if err == nil {
		t.Fatal("expected an error when the scan reports errors")
	}
	if !strings.Contains(err.Error(), "download-package") || !strings.Contains(err.Error(), "404") {
		t.Fatalf("error should include the guarddog errors, got: %v", err)
	}
}

func TestExecRunnerNonzeroStderrError(t *testing.T) {
	bin := stubBinary(t, "not json", "oops", 1)
	r := New(Params{Binary: bin}, nil).runner.(*execRunner)
	_, err := r.Scan(context.Background(), "npm", "", []byte("x"))
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "guarddog-scan:") || !strings.Contains(err.Error(), "oops") {
		t.Fatalf("error should mention guarddog-scan and stderr, got: %v", err)
	}
}

func TestExecRunnerParseFailCleanReturnsNil(t *testing.T) {
	bin := stubBinary(t, "not json", "", 0)
	r := New(Params{Binary: bin}, nil).runner.(*execRunner)
	findings, err := r.Scan(context.Background(), "npm", "", []byte("x"))
	if err != nil {
		t.Fatalf("clean exit with unparsable stdout should not error, got %v", err)
	}
	if findings != nil {
		t.Fatalf("expected nil findings, got %#v", findings)
	}
}

func TestExecRunnerTimeoutKill(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "hang-stub")
	// A busy loop in the shell itself (not `sleep 30`, whose orphaned child
	// would hold the stdout/stderr pipes open and stall cmd.Run until it exits).
	//nolint:gosec // the stub script must be executable
	if err := os.WriteFile(script, []byte("#!/bin/sh\nwhile true; do :; done\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := New(Params{Binary: script, Timeout: 100 * time.Millisecond}, nil).runner.(*execRunner)
	if _, err := r.Scan(context.Background(), "npm", "", []byte("x")); err == nil {
		t.Fatal("expected a timeout error")
	}
}

func TestExecRunner_RealGuarddog(t *testing.T) {
	// #85 is the real e2e; this test only runs when a guarddog binary is
	// actually on PATH (it is not in the CI golang image, so it skips there).
	path, err := exec.LookPath("guarddog")
	if err != nil {
		t.Skip("guarddog not installed; skipping real-binary scan")
	}
	tar := makeTarGz(t, map[string]string{
		"package/package.json": `{"name":"benign","version":"1.0.0","scripts":{"test":"echo ok"}}`,
	})
	r := New(Params{Binary: path}, nil).runner.(*execRunner)
	findings, err := r.Scan(context.Background(), "npm", "", tar)
	if err != nil {
		t.Fatalf("scan of a benign tarball should succeed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("benign tarball should have no findings, got %#v", findings)
	}
}
