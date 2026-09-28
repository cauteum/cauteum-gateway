# SPDX-FileCopyrightText: Copyright (c) 2026 the whaleshell authors
# SPDX-License-Identifier: MIT
#
# Build from a workspace that has sibling checkouts (CI does this):
#   docker build -f whaleshell-gateway/Dockerfile -t whaleshell-gateway:local .

FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY whaleshell-core ./whaleshell-core
COPY whaleshell-providers ./whaleshell-providers
COPY whaleshell-runtime ./whaleshell-runtime
COPY whaleshell-proxy ./whaleshell-proxy
COPY whaleshell-driver ./whaleshell-driver
COPY whaleshell-sdk ./whaleshell-sdk
COPY slogx ./slogx
COPY whaleshell-gateway ./whaleshell-gateway
RUN cat > go.work <<'WORK'
go 1.27.0
use (
	./whaleshell-gateway
	./whaleshell-core
	./whaleshell-providers
	./whaleshell-runtime
	./whaleshell-proxy
	./whaleshell-driver
	./whaleshell-sdk
	./slogx
)
replace (
	github.com/whaleshell/whaleshell-gateway v0.1.0-alpha.1 => ./whaleshell-gateway
	github.com/whaleshell/whaleshell-gateway v0.1.0-alpha.2 => ./whaleshell-gateway
	github.com/whaleshell/whaleshell-core v0.1.0-alpha.1 => ./whaleshell-core
	github.com/whaleshell/whaleshell-core v0.1.0-alpha.2 => ./whaleshell-core
	github.com/whaleshell/whaleshell-providers v0.1.0-alpha.1 => ./whaleshell-providers
	github.com/whaleshell/whaleshell-providers v0.1.0-alpha.2 => ./whaleshell-providers
	github.com/whaleshell/whaleshell-runtime v0.1.0-alpha.1 => ./whaleshell-runtime
	github.com/whaleshell/whaleshell-runtime v0.1.0-alpha.2 => ./whaleshell-runtime
	github.com/whaleshell/whaleshell-proxy v0.1.0-alpha.1 => ./whaleshell-proxy
	github.com/whaleshell/whaleshell-proxy v0.1.0-alpha.2 => ./whaleshell-proxy
	github.com/whaleshell/whaleshell-driver v0.1.0-alpha.1 => ./whaleshell-driver
	github.com/whaleshell/whaleshell-driver v0.1.0-alpha.2 => ./whaleshell-driver
	github.com/whaleshell/whaleshell-sdk v0.1.0-alpha.1 => ./whaleshell-sdk
	github.com/whaleshell/whaleshell-sdk v0.1.0-alpha.2 => ./whaleshell-sdk
	github.com/whaleshell/slogx v0.1.0-alpha.1 => ./slogx
	github.com/whaleshell/slogx v0.1.0-alpha.2 => ./slogx
)
WORK
ENV GOWORK=/src/go.work
WORKDIR /src/whaleshell-gateway
RUN CGO_ENABLED=0 go build -o /out/whaleshell-gateway ./cmd/whaleshell-gateway

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/whaleshell-gateway /usr/local/bin/whaleshell-gateway
LABEL org.opencontainers.image.title="whaleshell-gateway" \
      org.opencontainers.image.description="whaleshell control-plane gateway" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/whaleshell/osg-gateway"
ENV WHALESHELL_GATEWAY_DATA=/var/lib/whaleshell-gateway
VOLUME ["/var/lib/whaleshell-gateway"]
EXPOSE 7443
HEALTHCHECK --interval=15s --timeout=3s --start-period=3s --retries=5 \
  CMD curl -fsS http://127.0.0.1:7443/healthz >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/whaleshell-gateway"]
CMD ["--listen", "0.0.0.0:7443", "--data-dir", "/var/lib/whaleshell-gateway"]
