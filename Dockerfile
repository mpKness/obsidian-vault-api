# syntax=docker/dockerfile:1

FROM golang:1.23-alpine AS build
WORKDIR /src

# If you use go modules
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/vault-api ./

LABEL org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY}"

FROM alpine:3.20
RUN adduser -D -H -u 10001 app \
  && apk add --no-cache ca-certificates tzdata ripgrep

WORKDIR /app
COPY --from=build /out/vault-api /app/vault-api

USER 10001:10001

# Default port
EXPOSE 8787

# These are configured via env
ENV ADDR=":8787"

ENTRYPOINT ["/app/vault-api"]
