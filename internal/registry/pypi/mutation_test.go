package pypi

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
)

type pRecorder struct {
	mu     sync.Mutex
	events []string
	pre    int
	post   int
}

func (r *pRecorder) record(e string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

type pRecMutation struct{ r *pRecorder }

func (pRecMutation) Name() string { return "recording" }
func (m pRecMutation) PreFetch(*pipeline.PipelineContext) error {
	m.r.pre++
	m.r.record("prefetch")
	return nil
}
func (m pRecMutation) PostFetch(*pipeline.PipelineContext) error {
	m.r.post++
	m.r.record("postfetch")
	return nil
}

type pRecClient struct {
	r       *pRecorder
	project *Project
	raw     []byte
	file    []byte
}

func (c *pRecClient) FetchIndex(context.Context, string) (*Project, error) { return c.project, nil }
func (c *pRecClient) FetchIndexRaw(context.Context, string, string) ([]byte, string, error) {
	return c.raw, acceptJSON, nil
}
func (c *pRecClient) FetchFile(context.Context, string) (io.ReadCloser, int64, error) {
	c.r.record("fetch")
	return io.NopCloser(bytes.NewReader(c.file)), int64(len(c.file)), nil
}

func TestPypiMutationHookOrderAndCount(t *testing.T) {
	dir := t.TempDir()
	rec := &pRecorder{}
	proj, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("W"))
	client := &pRecClient{r: rec, project: proj, raw: raw, file: []byte("W")}
	global := &project.Resolved{Mutation: pipeline.MutationPipeline{Chain: []pipeline.MutationMiddleware{pRecMutation{r: rec}}}}
	a := newTestAdapterWithGlobal(t, "/pypi", dir, 0, client, newMemStore(), global)
	srv := newTestServer(t, a)

	code, _ := fetchViaProxy(t, srv.URL+"/pypi", "testpkg")
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	rec.mu.Lock()
	got := append([]string(nil), rec.events...)
	pre, post := rec.pre, rec.post
	rec.mu.Unlock()

	if pre != 1 || post != 1 {
		t.Errorf("hook counts: pre=%d post=%d, want 1/1", pre, post)
	}
	want := []string{"prefetch", "fetch", "postfetch"}
	if len(got) != len(want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events = %v, want %v", got, want)
		}
	}
}
