package oci

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, 404, CodeNameUnknown, "repository name not known to registry")

	if rec.Code != 404 {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not valid JSON: %v (body: %s)", err, rec.Body.String())
	}
	if len(body.Errors) != 1 {
		t.Fatalf("len(errors) = %d, want 1", len(body.Errors))
	}
	if body.Errors[0].Code != "NAME_UNKNOWN" {
		t.Errorf("code = %q, want NAME_UNKNOWN", body.Errors[0].Code)
	}
	if body.Errors[0].Message != "repository name not known to registry" {
		t.Errorf("message = %q, want the given message", body.Errors[0].Message)
	}
}

func TestErrorCodeConstants(t *testing.T) {
	// Pin the exact wire values -- these are read by the Docker/OCI client,
	// not just internal identifiers, so a typo here is a real protocol bug.
	cases := map[string]string{
		CodeNameUnknown:     "NAME_UNKNOWN",
		CodeManifestUnknown: "MANIFEST_UNKNOWN",
		CodeBlobUnknown:     "BLOB_UNKNOWN",
		CodeDenied:          "DENIED",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("constant = %q, want %q", got, want)
		}
	}
}
