{{/*
Chart name, overridable.
*/}}
{{- define "dependaproxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "dependaproxy.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "dependaproxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
component: proxy keeps the Deployment's pod selector from ever matching the
bundled PostgreSQL pods, which otherwise share the same name+instance labels.
*/}}
{{- define "dependaproxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dependaproxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: proxy
{{- end }}

{{- define "dependaproxy.labels" -}}
helm.sh/chart: {{ include "dependaproxy.chart" . }}
{{ include "dependaproxy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "dependaproxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "dependaproxy.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "dependaproxy.postgresql.fullname" -}}
{{- printf "%s-postgresql" (include "dependaproxy.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "dependaproxy.postgresql.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dependaproxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: postgresql
{{- end }}

{{- define "dependaproxy.postgresql.labels" -}}
helm.sh/chart: {{ include "dependaproxy.chart" . }}
{{ include "dependaproxy.postgresql.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Resolves the image reference. Falls back to Chart.AppVersion when image.tag is
empty (there is no :latest tag on ghcr.io/psenna/dependaproxy — every image is
tagged with a verbatim release tag). image.digest, if set, wins over tag.
*/}}
{{- define "dependaproxy.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- if not $tag -}}
{{- fail "image.tag is empty and Chart.yaml declares no appVersion. Set image.tag to a published dependaproxy release tag (e.g. \"v0.0.5\"); there is no :latest tag on ghcr.io/psenna/dependaproxy." -}}
{{- end -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end }}

{{/*
Derives the container port from config.server.addr (e.g. ":8080" -> 8080).
The app's own config schema has no separate "port" field, so this is the
single source of truth other templates (Service, probes) must use.
*/}}
{{- define "dependaproxy.containerPort" -}}
{{- $addr := .Values.config.server.addr | toString -}}
{{- $port := last (splitList ":" $addr) -}}
{{- if ne $port (regexFind "^[0-9]+$" $port) -}}
{{- fail (printf "config.server.addr=%q: the chart derives the container port from the text after the last ':' and could not parse a numeric port there. Use a form like \":8080\" or \"0.0.0.0:8080\" (a named port such as \":http\" is not supported)." $addr) -}}
{{- end -}}
{{- $n := atoi $port -}}
{{- if or (lt $n 1) (gt $n 65535) -}}
{{- fail (printf "config.server.addr=%q: derived port %d is outside the valid range 1-65535." $addr $n) -}}
{{- end -}}
{{- $n -}}
{{- end }}

{{/*
auth.existingSecret is unconditionally required: internal/config's Validate()
rejects an empty auth.admin_token whenever storage is configured, and
storage.type must always be "postgres" (storage is therefore ALWAYS
configured) -- so admin_token can never legally be omitted.
*/}}
{{- define "dependaproxy.auth.secretName" -}}
{{- if not .Values.auth.existingSecret -}}
{{- fail "auth.existingSecret is required. dependaproxy hard-requires auth.admin_token: internal/config's Validate() rejects an empty admin_token whenever storage is configured, and storage.type must always be \"postgres\" -- so there is no configuration in which admin_token may be omitted. Create a Secret holding a verbatim `auth:` YAML block (auth.token + auth.admin_token, which MUST differ) and set auth.existingSecret to its name. See examples/auth-secret.yaml." -}}
{{- end -}}
{{- .Values.auth.existingSecret -}}
{{- end }}

{{- define "dependaproxy.auth.secretKey" -}}
{{- required "auth.key must not be empty; it is the key inside auth.existingSecret holding the `auth:` YAML block (default: auth.yaml)." .Values.auth.key -}}
{{- end }}

{{/*
Resolves which Secret holds the `storage:` YAML fragment. When
postgresql.enabled=true, the chart's own generated Secret is used (see
templates/postgresql/secret.yaml) -- this makes the bundled and external
paths byte-identical everywhere except this one resolved name.
*/}}
{{- define "dependaproxy.storage.secretName" -}}
{{- if and .Values.postgresql.enabled .Values.storage.existingSecret -}}
{{- fail "Ambiguous storage configuration: postgresql.enabled=true (the chart generates its own storage Secret from the bundled PostgreSQL's credentials) AND storage.existingSecret is set. Pick exactly one -- bundled DEV-ONLY PostgreSQL: postgresql.enabled=true and storage.existingSecret=\"\"; or external/managed PostgreSQL: postgresql.enabled=false and storage.existingSecret=<your-secret>." -}}
{{- end -}}
{{- if .Values.postgresql.enabled -}}
{{- include "dependaproxy.postgresql.fullname" . -}}
{{- else if .Values.storage.existingSecret -}}
{{- .Values.storage.existingSecret -}}
{{- else -}}
{{- fail "storage.existingSecret is required when postgresql.enabled=false. dependaproxy refuses to start unless storage.type is \"postgres\" (internal/config Validate()), and the chart never renders a DSN into the ConfigMap. Create a Secret holding a verbatim `storage:` YAML block with the full DSN (see examples/storage-secret.yaml), or set postgresql.enabled=true to use the bundled single-instance DEV/DEMO-ONLY PostgreSQL." -}}
{{- end -}}
{{- end }}

{{- define "dependaproxy.storage.secretKey" -}}
{{- if .Values.postgresql.enabled -}}
{{- "storage.yaml" -}}
{{- else -}}
{{- required "storage.key must not be empty; it is the key inside storage.existingSecret holding the `storage:` YAML block (default: storage.yaml)." .Values.storage.key -}}
{{- end -}}
{{- end }}

{{/*
registries: is a top-level key the ConfigMap renders directly from values UNLESS
config.registriesExistingSecret is set, in which case the whole block comes
from a Secret instead (needed so s3-cache access_key/secret_key, which live
inside registries[].retrieval[].params, never have to appear in values.yaml).
The two are mutually exclusive: two `registries:` keys in one assembled YAML
file is a duplicate-mapping-key parse error.
*/}}
{{- define "dependaproxy.validateRegistries" -}}
{{- if and .Values.config.registriesExistingSecret (gt (len .Values.config.registries) 0) -}}
{{- fail "config.registriesExistingSecret and config.registries are mutually exclusive: two top-level `registries:` keys in one YAML document is a duplicate-mapping-key parse error and dependaproxy would refuse to start. Set config.registries: [] when sourcing the whole registries block from a Secret (this is the supported way to keep s3-cache access_key/secret_key out of values.yaml), or unset config.registriesExistingSecret to template the block from values." -}}
{{- end -}}
{{- if and (not .Values.config.registriesExistingSecret) (eq (len .Values.config.registries) 0) -}}
{{- fail "config.registries is empty and config.registriesExistingSecret is unset: dependaproxy requires at least one registry (internal/config Validate(): \"at least one registry is required\"). Define config.registries in values, or set config.registriesExistingSecret to a Secret holding a verbatim `registries:` block." -}}
{{- end -}}
{{- end }}

{{/*
Every local-disk-cache middleware's params.path must live under the chart's
one writable cache mount (cache.mountPath) -- the container runs with
readOnlyRootFilesystem: true, so a path outside the mount fails with
permission-denied deep inside a package-fetch request, not at startup.
Skipped when registries come from a Secret (the chart can't inspect Secret
contents at render time).
*/}}
{{- define "dependaproxy.validateCachePaths" -}}
{{- if and .Values.cache.enforcePathPrefix (not .Values.config.registriesExistingSecret) -}}
{{- $mount := .Values.cache.mountPath | trimSuffix "/" -}}
{{- range $i, $r := .Values.config.registries -}}
{{- range $j, $m := (default (list) $r.retrieval) -}}
{{- if eq (default "" $m.type) "local-disk-cache" -}}
{{- $p := "" -}}
{{- if $m.params -}}{{- $p = default "" $m.params.path -}}{{- end -}}
{{- if not $p -}}
{{- fail (printf "config.registries[%d].retrieval[%d] is a local-disk-cache with no params.path. Set it to a directory under %s -- the only writable cache mount this chart provides. (Set cache.enforcePathPrefix=false to disable this check.)" $i $j $mount) -}}
{{- end -}}
{{- if not (or (eq $p $mount) (hasPrefix (printf "%s/" $mount) $p)) -}}
{{- fail (printf "config.registries[%d].retrieval[%d] local-disk-cache params.path=%q must live under %s (the chart's writable cache mount, cache.mountPath). Fix the path, change cache.mountPath, or set cache.enforcePathPrefix=false to disable this check." $i $j $p $mount) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/*
A ReadWriteOnce cache PVC can only be attached on one node; with
replicaCount>1, pods scheduled elsewhere hang Pending on FailedAttachVolume --
a silent, hard-to-diagnose rollout stall. Guarded off by default (the cache
PVC itself is opt-in) and escapable via ignoreAccessModeCheck for deployments
that pin every replica to one node.
*/}}
{{- define "dependaproxy.validateCacheReplicas" -}}
{{- $p := .Values.persistence.cache -}}
{{- if and $p.enabled (not $p.existingClaim) (not $p.ignoreAccessModeCheck) -}}
{{- if and (gt (int $.Values.replicaCount) 1) (not (has "ReadWriteMany" $p.accessModes)) -}}
{{- fail (printf "persistence.cache.enabled=true with persistence.cache.accessModes=%v and replicaCount=%d. A ReadWriteOnce artifact-cache PVC can only be attached on one node, so replicas scheduled elsewhere hang Pending on FailedAttachVolume. Fix by one of: (1) replicaCount=1; (2) persistence.cache.accessModes=[ReadWriteMany] on an RWX StorageClass; (3) persistence.cache.existingClaim=<an existing RWX claim>; (4) persistence.cache.enabled=false and use the shared s3-cache retrieval middleware instead; (5) persistence.cache.ignoreAccessModeCheck=true if every replica is pinned to one node." $p.accessModes (int $.Values.replicaCount)) -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/*
Single entry point that fires every render-time guard. Included from BOTH
configmap.yaml and deployment.yaml so `helm template -s <either file>` still
exercises every check. Renders nothing (the two "$_ :=" assignments discard
the resolved secret name -- they exist only to trigger the fail calls).
*/}}
{{- define "dependaproxy.validate" -}}
{{- include "dependaproxy.validateRegistries" . -}}
{{- include "dependaproxy.validateCachePaths" . -}}
{{- include "dependaproxy.validateCacheReplicas" . -}}
{{- $_ := include "dependaproxy.auth.secretName" . -}}
{{- $_ := include "dependaproxy.storage.secretName" . -}}
{{- $_ := include "dependaproxy.containerPort" . -}}
{{- end }}

{{- define "dependaproxy.cacheClaimName" -}}
{{- default (printf "%s-cache" (include "dependaproxy.fullname" .)) .Values.persistence.cache.existingClaim -}}
{{- end }}
