package npm

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

type recorder struct {
	mu     sync.Mutex
	events []string
	pre    int
	post   int
}

func (r *recorder) record(e string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

type recMutation struct{ r *recorder }

func (recMutation) Name() string { return "recording" }
func (m recMutation) PreFetch(*pipeline.PipelineContext) error {
	m.r.pre++
	m.r.record("prefetch")
	return nil
}
func (m recMutation) PostFetch(*pipeline.PipelineContext) error {
	m.r.post++
	m.r.record("postfetch")
	return nil
}

type recClient struct {
	r       *recorder
	pack    *Packument
	raw     []byte
	tarball []byte
}

func (c *recClient) FetchPackument(context.Context, string) (*Packument, error) { return c.pack, nil }
func (c *recClient) FetchPackumentRaw(context.Context, string) ([]byte, error)  { return c.raw, nil }
func (c *recClient) FetchBytes(context.Context, string) ([]byte, error)         { return nil, ErrNotFound }
func (c *recClient) FetchTarball(context.Context, string) (io.ReadCloser, int64, error) {
	c.r.record("fetch")
	return io.NopCloser(bytes.NewReader(c.tarball)), int64(len(c.tarball)), nil
}

func TestNpmMutationHookOrderAndCount(t *testing.T) {
	dir := t.TempDir()
	rec := &recorder{}
	pack, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("T"))
	client := &recClient{r: rec, pack: pack, raw: raw, tarball: []byte("T")}
	global := &project.Resolved{Mutation: pipeline.MutationPipeline{Chain: []pipeline.MutationMiddleware{recMutation{r: rec}}}}
	a := newTestAdapterWithGlobal(t, "/npm", dir, 0, client, newMemStore(), global)
	srv := newTestServer(t, a)

	code, _ := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0")
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
