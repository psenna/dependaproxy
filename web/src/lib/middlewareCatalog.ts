export type MiddlewareChain = 'validation' | 'retrieval' | 'mutation'

export type ParamType = 'string' | 'number' | 'boolean' | 'duration'

export interface ParamField {
  key: string
  label: string
  type: ParamType
  required?: boolean
  description?: string
}

export interface CatalogEntry {
  type: string
  label: string
  description: string
  params: ParamField[]
}

export const MIDDLEWARE_CATALOG: Record<MiddlewareChain, CatalogEntry[]> = {
  validation: [
    {
      type: 'deny-list-check',
      label: 'Deny-list check',
      description: 'Rejects packages that were previously denied.',
      params: [],
    },
    {
      type: 'min-publication-age',
      label: 'Min publication age',
      description: 'Rejects packages published too recently.',
      params: [
        {
          key: 'min_days',
          label: 'Min days',
          type: 'number',
          required: true,
          description: 'Minimum age in days before a package is accepted.',
        },
      ],
    },
    {
      type: 'cve-check',
      label: 'CVE check',
      description: 'Queries the OSV database for known vulnerabilities.',
      params: [
        { key: 'mode', label: 'Mode', type: 'string', description: 'deny (default) or warn.' },
        { key: 'on_error', label: 'On error', type: 'string', description: 'fail_open (default) or fail_closed.' },
        { key: 'timeout', label: 'Timeout', type: 'duration', description: 'Per-query timeout.' },
        { key: 'cache_ttl', label: 'Cache TTL', type: 'duration', description: 'How long to cache OSV responses.' },
      ],
    },
    {
      type: 'malware-scan',
      label: 'Malware scan',
      description: 'Scans artifacts for known malware signatures.',
      params: [{ key: 'mode', label: 'Mode', type: 'string', description: 'deny (default) or warn.' }],
    },
    {
      type: 'guarddog-scan',
      label: 'Guarddog scan',
      description: 'Scans artifacts with GuardDog heuristics.',
      params: [
        { key: 'mode', label: 'Mode', type: 'string', description: 'deny (default) or warn.' },
        { key: 'on_error', label: 'On error', type: 'string', description: 'fail_open (default) or fail_closed.' },
        { key: 'timeout', label: 'Timeout', type: 'duration', description: 'Per-scan timeout.' },
        { key: 'sandbox', label: 'Sandbox', type: 'boolean', description: 'Run GuardDog in a sandbox.' },
        { key: 'binary', label: 'Binary', type: 'string', description: 'Path to the GuardDog binary.' },
      ],
    },
    {
      type: 'provenance-verify',
      label: 'Provenance verify',
      description: 'Verifies signed provenance attestations.',
      params: [
        { key: 'mode', label: 'Mode', type: 'string', description: 'deny (default) or warn.' },
        {
          key: 'require_provenance',
          label: 'Require provenance',
          type: 'boolean',
          description: 'Deny/warn when no attestation is published.',
        },
        { key: 'on_error', label: 'On error', type: 'string', description: 'fail_open (default) or fail_closed.' },
        { key: 'identity', label: 'Identity', type: 'string', description: 'Regex matched against the signing cert SAN.' },
        { key: 'timeout', label: 'Timeout', type: 'duration', description: 'Per-verify sigstore timeout.' },
      ],
    },
  ],
  retrieval: [
    {
      type: 'cve-check-retrieval',
      label: 'CVE check (retrieval)',
      description: 'Enforces CVE policy on retrieved artifacts.',
      params: [
        { key: 'mode', label: 'Mode', type: 'string', description: 'deny (default) or warn.' },
        { key: 'on_error', label: 'On error', type: 'string', description: 'fail_open (default) or fail_closed.' },
        { key: 'cache_ttl', label: 'Cache TTL', type: 'duration', description: 'How long to cache OSV responses.' },
      ],
    },
    {
      type: 'local-disk-cache',
      label: 'Local disk cache',
      description: 'Caches artifacts on the local filesystem.',
      params: [
        {
          key: 'path',
          label: 'Path',
          type: 'string',
          required: true,
          description: 'Directory used for the cache.',
        },
      ],
    },
    {
      type: 's3-cache',
      label: 'S3 cache',
      description: 'Caches artifacts in an S3-compatible bucket.',
      params: [
        { key: 'endpoint', label: 'Endpoint', type: 'string', required: true, description: 'S3 endpoint URL.' },
        { key: 'bucket', label: 'Bucket', type: 'string', required: true, description: 'Bucket name.' },
        { key: 'region', label: 'Region', type: 'string', description: 'AWS region.' },
        { key: 'access_key', label: 'Access key', type: 'string', description: 'S3 access key.' },
        { key: 'secret_key', label: 'Secret key', type: 'string', description: 'S3 secret key.' },
        { key: 'use_ssl', label: 'Use SSL', type: 'boolean', description: 'Connect over HTTPS.' },
        { key: 'base_path', label: 'Base path', type: 'string', description: 'Prefix for keys inside the bucket.' },
      ],
    },
    {
      type: 'upstream-registry',
      label: 'Upstream registry',
      description: 'Fetches artifacts from the upstream registry.',
      params: [],
    },
  ],
  mutation: [
    {
      type: 'strip-install-scripts',
      label: 'Strip install scripts',
      description: 'Removes install scripts from published artifacts.',
      params: [],
    },
  ],
}

export function catalogForChain(chain: MiddlewareChain): CatalogEntry[] {
  return MIDDLEWARE_CATALOG[chain]
}

export function isKnownType(type: string): boolean {
  return Object.values(MIDDLEWARE_CATALOG).some((entries) => entries.some((entry) => entry.type === type))
}

export function findEntry(type: string): CatalogEntry | undefined {
  for (const entries of Object.values(MIDDLEWARE_CATALOG)) {
    const found = entries.find((entry) => entry.type === type)
    if (found) return found
  }
  return undefined
}
