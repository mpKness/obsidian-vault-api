# syntax=docker/dockerfile:1

FROM golang:1.23-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/vault-api ./


LABEL org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY}"

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata ripgrep

WORKDIR /app
COPY --from=build /out/vault-api /app/vault-api

EXPOSE 8787
ENTRYPOINT ["/app/vault-api"]

