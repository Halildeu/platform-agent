# Faz 22.5 M1 — endpoint-agent artifact host image.
#
# Serves the packaged one-command bootstrap artifacts as STATIC files at
#   /artifacts/endpoint-agent/<VERSION>/
#     ├─ bootstrap-package.ps1     (the one-command bootstrap client)
#     ├─ EndpointAgent.zip         (signed exe + install/uninstall + SHA256SUMS)
#     ├─ EndpointAgent.zip.sha256  (value for -ExpectedZipSha256)
#     ├─ SHA256SUMS                (hashes of the SERVED files: zip+ps1+manifest)
#     └─ release-manifest.json     (machine-readable release contract)
#
# Built + pushed by .github/workflows/release.yml (publish job) to
#   ghcr.io/<owner>/platform-agent-artifacts:<tag>   (+ immutable sha-<short>).
# Pulled DIGEST-PINNED (D30) by platform-k8s-gitops kustomize/base/apps/artifact-host.
#
# Retention contract: ONE version folder per image. The cluster serves the
# currently-pinned release; older /artifacts/<old-tag>/ host URLs 404 after the
# image rolls — the durable archive is the GitHub release assets.
FROM nginx:1.27-alpine

ARG VERSION
ARG REVISION="unknown"
ARG RELEASE_TAG="unknown"
ARG ZIP_SHA256="unknown"
ARG SOURCE_RUN_ID="unknown"

LABEL org.opencontainers.image.title="platform-agent-artifacts" \
      org.opencontainers.image.description="Static host for the Windows endpoint-agent one-command bootstrap artifacts (Faz 22.5 M1)" \
      org.opencontainers.image.source="https://github.com/Halildeu/platform-agent" \
      org.opencontainers.image.revision="${REVISION}" \
      com.acik.platform-agent.release-tag="${RELEASE_TAG}" \
      com.acik.platform-agent.endpoint-agent-zip-sha256="${ZIP_SHA256}" \
      com.acik.platform-agent.source-run-id="${SOURCE_RUN_ID}"

# Canonical static-serving config (no SPA fallback, correct content types,
# hard 404 on missing artifact so a wrong URL never returns executable HTML).
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Packaged release assets staged by CI into build-assets/ — one version folder.
COPY build-assets/ /usr/share/nginx/html/artifacts/endpoint-agent/${VERSION}/

# Stable MUTABLE alias serving the SAME bytes at a version-independent URL.
# Lets the endpoint-admin UI render a copy-paste one-command install AND
# discover the current package hash (/current/EndpointAgent.zip.sha256) without
# a per-release frontend edit. Re-points to THIS image's version on every
# release. nginx serves /current/ with no-store (see nginx.conf) precisely
# because — unlike the versioned path above — it is NOT immutable; pinning the
# 1y immutable cache here would hand clients a stale bootstrap after a bump.
COPY build-assets/ /usr/share/nginx/html/artifacts/endpoint-agent/current/
