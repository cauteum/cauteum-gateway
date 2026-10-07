# SPDX-FileCopyrightText: Copyright (c) 2026 the whaleshell authors
# SPDX-License-Identifier: Apache-2.0
#
# Build from a workspace that has sibling checkouts (CI does this):
#   docker build -f whaleshell-gateway/Dockerfile -t whaleshell-gateway:local .

FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.work go.work.sum ./
COPY whaleshell-core ./whaleshell-core
COPY whaleshell-display ./whaleshell-display
COPY whaleshell-providers ./whaleshell-providers
COPY whaleshell-runtime ./whaleshell-runtime
COPY whaleshell-cli ./whaleshell-cli
COPY whaleshell-proxy ./whaleshell-proxy
COPY whaleshell-driver ./whaleshell-driver
COPY whaleshell-sdk ./whaleshell-sdk
COPY whaleshell-slogx ./whaleshell-slogx
COPY whaleshell-gateway ./whaleshell-gateway
WORKDIR /src/whaleshell-gateway
ARG TARGETARCH
RUN set -eu; arch="${TARGETARCH:-$(go env GOARCH)}"; mkdir -p /out/helpers/linux-$arch; \
	CGO_ENABLED=0 go build -o /out/whaleshell-gateway ./cmd/whaleshell-gateway; \
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -C /src/whaleshell-cli -o /out/helpers/linux-$arch/whaleshell ./cmd/whaleshell; \
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -C /src/whaleshell-runtime -o /out/helpers/linux-$arch/whaleshell-init ./cmd/whaleshell-init; \
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -C /src/whaleshell-runtime -o /out/helpers/linux-$arch/whaleshell-sshd ./cmd/whaleshell-sshd; \
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -C /src/whaleshell-runtime -o /out/helpers/linux-$arch/whaleshell-supervisor ./cmd/whaleshell-supervisor

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/whaleshell-gateway /usr/local/bin/whaleshell-gateway
COPY --from=build /out/helpers/ /usr/local/lib/whaleshell/
COPY --from=build /src/whaleshell-cli/providers/ /usr/local/providers/
COPY --from=build /src/whaleshell-gateway/LICENSE /src/whaleshell-gateway/NOTICE /usr/share/licenses/whaleshell-gateway/
COPY --from=build /src/whaleshell-cli/LICENSE /src/whaleshell-cli/NOTICE /usr/share/licenses/whaleshell-cli/
COPY --from=build /src/whaleshell-runtime/LICENSE /src/whaleshell-runtime/NOTICE /usr/share/licenses/whaleshell-runtime/
LABEL org.opencontainers.image.title="whaleshell-gateway" \
      org.opencontainers.image.description="whaleshell control-plane gateway" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/whaleshell/whaleshell-gateway"
ENV WHALESHELL_GATEWAY_DATA=/var/lib/whaleshell-gateway
VOLUME ["/var/lib/whaleshell-gateway"]
EXPOSE 7443
HEALTHCHECK --interval=15s --timeout=3s --start-period=3s --retries=5 \
  CMD curl -fsS http://127.0.0.1:7443/healthz >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/whaleshell-gateway"]
CMD ["--listen", "0.0.0.0:7443", "--data-dir", "/var/lib/whaleshell-gateway"]
