// Package s3cache implements the localcache.CacheBackend interface against any
// S3-compatible object store (AWS S3, MinIO, GCS XML API, ...) using
// minio-go. It plugs into the shared cache middleware
// (localcache.NewNamedBackend("s3-cache", ...)), so retrieval, write-through,
// keying, and eviction behave exactly like the disk backend — only the storage
// medium differs.
package s3cache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// Options configures the S3 backend.
type Options struct {
	Endpoint  string // host[:port], no scheme (minio-go requirement)
	Bucket    string
	Region    string
	AccessKey string
	SecretKey string
	UseSSL    bool
	BasePath  string // optional object-key prefix ("" for the bucket root)
}

// Backend is an S3-compatible localcache.CacheBackend.
type Backend struct {
	client   *minio.Client
	bucket   string
	basePath string
}

// New builds a Backend from Options. It constructs the minio-go client but does
// not contact the server (the endpoint/bucket are validated on first access).
func New(o Options) (*Backend, error) {
	if o.Endpoint == "" || o.Bucket == "" {
		return nil, fmt.Errorf("s3-cache: endpoint and bucket are required")
	}
	client, err := minio.New(o.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(o.AccessKey, o.SecretKey, ""),
		Secure: o.UseSSL,
		Region: o.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("s3-cache: build client for %s: %w", o.Endpoint, err)
	}
	return NewWithClient(client, o.Bucket, o.BasePath), nil
}

// NewWithClient builds a Backend over an existing client (used by tests against
// a real MinIO/S3 instance).
func NewWithClient(client *minio.Client, bucket, basePath string) *Backend {
	return &Backend{client: client, bucket: bucket, basePath: strings.Trim(basePath, "/")}
}

// objectKey maps a cache key (a relative path like "npm/express/4.18.0.bin") to
// the object key in the bucket, honouring BasePath.
func (b *Backend) objectKey(key string) string {
	if b.basePath == "" {
		return key
	}
	return b.basePath + "/" + key
}

// Get fetches the object bytes; a missing object is reported as os.ErrNotExist.
func (b *Backend) Get(key string) ([]byte, error) {
	obj, err := b.client.GetObject(context.Background(), b.bucket, b.objectKey(key), minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = obj.Close() }()
	data, err := io.ReadAll(obj)
	if err != nil {
		var er minio.ErrorResponse
		if errors.As(err, &er) && er.Code == "NoSuchKey" {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	return data, nil
}

// Put stores the object bytes.
func (b *Backend) Put(key string, data []byte) error {
	_, err := b.client.PutObject(context.Background(), b.bucket, b.objectKey(key),
		bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: "application/octet-stream"})
	return err
}

// Delete removes the object; a missing object is not an error.
func (b *Backend) Delete(key string) error {
	err := b.client.RemoveObject(context.Background(), b.bucket, b.objectKey(key), minio.RemoveObjectOptions{})
	if err != nil {
		var er minio.ErrorResponse
		if errors.As(err, &er) && er.Code == "NoSuchKey" {
			return nil
		}
		return err
	}
	return nil
}

// EnsureBackend is the localcache.CacheBackend compile-time assertion.
var _ localcache.CacheBackend = (*Backend)(nil)

type params struct {
	Endpoint  string `yaml:"endpoint"`
	Bucket    string `yaml:"bucket"`
	Region    string `yaml:"region"`
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	UseSSL    bool   `yaml:"use_ssl"`
	BasePath  string `yaml:"base_path"`
}

// Factory builds the middleware from its raw params node, registered by each
// adapter under "s3-cache".
var Factory pipeline.RetrievalFactory = func(p yaml.Node, next pipeline.RetrievalMiddleware) (pipeline.RetrievalMiddleware, error) {
	var pr params
	if !p.IsZero() {
		if err := p.Decode(&pr); err != nil {
			return nil, fmt.Errorf("s3-cache: decode params: %w", err)
		}
	}
	backend, err := New(Options(pr))
	if err != nil {
		return nil, err
	}
	return localcache.NewNamedBackend("s3-cache", backend, next), nil
}
