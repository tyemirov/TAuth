FROM golang:1.25 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /app/tauth ./cmd/server

FROM alpine:3.20

RUN apk add --no-cache ca-certificates && \
    mkdir -p /data

COPY --from=builder /app/tauth /usr/local/bin/tauth

VOLUME ["/data"]

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/tauth"]
