package oci

import (
	"encoding/json"
	"net/http"
)

// Registry-v2 / OCI Distribution spec error codes this adapter returns. The
// exact strings are part of the wire protocol the Docker/OCI client parses.
const (
	CodeNameUnknown     = "NAME_UNKNOWN"
	CodeManifestUnknown = "MANIFEST_UNKNOWN"
	CodeBlobUnknown     = "BLOB_UNKNOWN"
	CodeDenied          = "DENIED"
)

type errorEnvelope struct {
	Errors []errorEntry `json:"errors"`
}

type errorEntry struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// writeError writes the registry-v2 error envelope
// {"errors":[{"code":...,"message":...}]} with the given HTTP status, so a
// Docker/OCI client can render a real error instead of "unknown error".
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorEnvelope{Errors: []errorEntry{{Code: code, Message: message}}})
}
