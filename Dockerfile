FROM golang:1.24-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=${VERSION}" -o /out/flarehound ./cmd/flarehound

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /out/flarehound /usr/local/bin/flarehound
VOLUME ["/app/data"]
USER 65534
ENTRYPOINT ["flarehound"]
CMD ["-config", "/app/config.json"]
