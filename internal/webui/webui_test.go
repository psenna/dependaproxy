package webui

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// testFS returns a MapFS shaped like a built Vite app: an index.html plus
// hashed assets under assets/.
func testFS() fs.FS {
	return fstest.MapFS{
		"index.html":           &fstest.MapFile{Data: []byte("<!doctype html><html><body>test index</body></html>")},
		"assets/index-abc.js":  &fstest.MapFile{Data: []byte("console.log('hi')")},
		"assets/index-abc.css": &fstest.MapFile{Data: []byte("body { color: red }")},
	}
}

func get(h http.Handler, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestHandlerServesIndexAtRoot(t *testing.T) {
	h := handler(testFS())
	rr := get(h, "/")
	if rr.Code != 200 {
		t.Fatalf("GET /: code=%d want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "<html") {
		t.Errorf("GET /: body missing <html: %q", rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("GET /: Content-Type=%q want text/html", ct)
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("GET /: Cache-Control=%q want no-cache", cc)
	}
}

func TestHandlerServesIndexHTML(t *testing.T) {
	h := handler(testFS())
	rr := get(h, "/index.html")
	if rr.Code != 200 {
		t.Fatalf("GET /index.html: code=%d want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("GET /index.html: Content-Type=%q want text/html", ct)
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("GET /index.html: Cache-Control=%q want no-cache", cc)
	}
}

func TestHandlerSPAFallback(t *testing.T) {
	root := testFS()
	h := handler(root)
	rr := get(h, "/projects/acme/edit")
	if rr.Code != 200 {
		t.Fatalf("GET /projects/acme/edit: code=%d want 200", rr.Code)
	}
	indexBytes, err := fs.ReadFile(root, "index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	if rr.Body.String() != string(indexBytes) {
		t.Errorf("GET /projects/acme/edit: body=%q want index.html bytes %q", rr.Body.String(), string(indexBytes))
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("GET /projects/acme/edit: Content-Type=%q want text/html", ct)
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("GET /projects/acme/edit: Cache-Control=%q want no-cache", cc)
	}
}

func TestHandlerServesAssets(t *testing.T) {
	h := handler(testFS())
	rr := get(h, "/assets/index-abc.js")
	if rr.Code != 200 {
		t.Fatalf("GET /assets/index-abc.js: code=%d want 200", rr.Code)
	}
	if rr.Body.String() != "console.log('hi')" {
		t.Errorf("GET /assets/index-abc.js: body=%q want asset bytes", rr.Body.String())
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Errorf("GET /assets/index-abc.js: Cache-Control=%q want immutable", cc)
	}
}

func TestHandlerContentTypes(t *testing.T) {
	h := handler(testFS())
	rr := get(h, "/assets/index-abc.js")
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/javascript") && !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("GET .js: Content-Type=%q want application/javascript or text/javascript", ct)
	}
	rr = get(h, "/assets/index-abc.css")
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Errorf("GET .css: Content-Type=%q want text/css", ct)
	}
}

func TestHandlerRealEmbed(t *testing.T) {
	h := Handler()
	if h == nil {
		t.Fatal("Handler() returned nil")
	}
	rr := get(h, "/")
	if rr.Code != 200 {
		t.Fatalf("GET / (embedded): code=%d want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "<html") {
		t.Errorf("GET / (embedded): body missing <html: %q", rr.Body.String())
	}
}
