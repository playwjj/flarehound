FROM golang:1.26-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=${VERSION}" -o /out/flarehound ./cmd/flarehound

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /out/flarehound /usr/local/bin/flarehound
VOLUME ["/app/data"]
USER 65534
# Dead-man switch: the watch loop writes data/heartbeat every round; a stale
# heartbeat marks the container unhealthy. (The admin/enforce container
# overrides this to check data/heartbeat-enforce.)
HEALTHCHECK --interval=5m --timeout=30s --start-period=15m --retries=2 \
  CMD ["flarehound", "-config", "/app/config.json", "health"]
ENTRYPOINT ["flarehound"]
CMD ["-config", "/app/config.json"]
