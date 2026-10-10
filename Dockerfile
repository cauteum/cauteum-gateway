# SPDX-FileCopyrightText: Copyright (c) 2026 the cauteum authors
# SPDX-License-Identifier: Apache-2.0
#
# Build from a workspace that has sibling checkouts (CI does this):
#   docker build -f cauteum-gateway/Dockerfile -t cauteum-gateway:local .

FROM golang:1.27-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS build
WORKDIR /src
COPY go.work go.work.sum ./
COPY cauteum-core ./cauteum-core
COPY cauteum-display ./cauteum-display
COPY cauteum-providers ./cauteum-providers
COPY cauteum-runtime ./cauteum-runtime
COPY cauteum-cli ./cauteum-cli
COPY cauteum-proxy ./cauteum-proxy
COPY cauteum-driver ./cauteum-driver
COPY cauteum-sdk ./cauteum-sdk
COPY cauteum-slogx ./cauteum-slogx
COPY cauteum-gateway ./cauteum-gateway
WORKDIR /src/cauteum-gateway
ARG TARGETARCH
RUN set -eu; arch="${TARGETARCH:-$(go env GOARCH)}"; mkdir -p /out/helpers/linux-$arch; \
	CGO_ENABLED=0 go build -o /out/cauteum-gateway ./cmd/cauteum-gateway; \
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -C /src/cauteum-cli -o /out/helpers/linux-$arch/cauteum ./cmd/cauteum; \
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -C /src/cauteum-runtime -o /out/helpers/linux-$arch/cauteum-init ./cmd/cauteum-init; \
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -C /src/cauteum-runtime -o /out/helpers/linux-$arch/cauteum-sshd ./cmd/cauteum-sshd; \
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -C /src/cauteum-runtime -o /out/helpers/linux-$arch/cauteum-supervisor ./cmd/cauteum-supervisor

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/cauteum-gateway /usr/local/bin/cauteum-gateway
COPY --from=build /out/helpers/ /usr/local/lib/cauteum/
COPY --from=build /src/cauteum-cli/providers/ /usr/local/providers/
COPY --from=build /src/cauteum-gateway/LICENSE /src/cauteum-gateway/NOTICE /usr/share/licenses/cauteum-gateway/
COPY --from=build /src/cauteum-cli/LICENSE /src/cauteum-cli/NOTICE /usr/share/licenses/cauteum-cli/
COPY --from=build /src/cauteum-runtime/LICENSE /src/cauteum-runtime/NOTICE /usr/share/licenses/cauteum-runtime/
LABEL org.opencontainers.image.title="cauteum-gateway" \
      org.opencontainers.image.description="cauteum control-plane gateway" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/cauteum/cauteum-gateway"
ENV CAUTEUM_GATEWAY_DATA=/var/lib/cauteum-gateway
VOLUME ["/var/lib/cauteum-gateway"]
EXPOSE 7443
HEALTHCHECK --interval=15s --timeout=3s --start-period=3s --retries=5 \
  CMD curl -fsS http://127.0.0.1:7443/healthz >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/cauteum-gateway"]
CMD ["--listen", "0.0.0.0:7443", "--data-dir", "/var/lib/cauteum-gateway"]
