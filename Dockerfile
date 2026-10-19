FROM --platform=$BUILDPLATFORM golang:1.26.5 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN targetOs="${TARGETOS:-$(go env GOOS)}" && \
    targetArch="${TARGETARCH:-$(go env GOARCH)}" && \
    CGO_ENABLED=0 GOOS="${targetOs}" GOARCH="${targetArch}" go build -ldflags="-s -w" -o /app/tauth ./cmd/server && \
    CGO_ENABLED=0 GOOS="${targetOs}" GOARCH="${targetArch}" go build -ldflags="-s -w" -o /app/tauth-migrate ./deployment/tenantownership

FROM alpine:3.20

RUN apk add --no-cache ca-certificates && \
    mkdir -p /data

COPY --from=builder /app/tauth /usr/local/bin/tauth
COPY --from=builder /app/tauth-migrate /usr/local/bin/tauth-migrate

COPY deployment/migrations/20260930-tenant-console.json deployment/migrations/20261005-console-google-client.json deployment/migrations/20261006-application-subjects.json /usr/local/share/tauth/deployment/migrations/
COPY deployment/rollout/inputs.yml deployment/rollout/cutover.yml deployment/rollout/console-google-client.yml deployment/rollout/application-subjects.yml /usr/local/share/tauth/deployment/rollout/

VOLUME ["/data"]

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/tauth"]
