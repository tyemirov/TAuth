FROM --platform=$BUILDPLATFORM golang:1.25 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN targetOs="${TARGETOS:-$(go env GOOS)}" && \
    targetArch="${TARGETARCH:-$(go env GOARCH)}" && \
    CGO_ENABLED=0 GOOS="${targetOs}" GOARCH="${targetArch}" go build -ldflags="-s -w" -o /app/tauth ./cmd/server

FROM alpine:3.20

RUN apk add --no-cache ca-certificates && \
    mkdir -p /data /web

COPY --from=builder /app/tauth /usr/local/bin/tauth
COPY --from=builder /app/web /web

VOLUME ["/data", "/web"]

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/tauth"]
