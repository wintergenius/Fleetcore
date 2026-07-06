# syntax=docker/dockerfile:1
# Multi-stage: build a static binary, ship it on distroless/static (~10 MB, no
# shell, minimal CVE surface). DESIGN.md §10.

FROM golang:1.26-alpine AS build
WORKDIR /src

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

# Build.
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w" -o /out/fleetcore ./cmd/fleetcore

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/fleetcore /usr/local/bin/fleetcore
EXPOSE 8443
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/fleetcore"]
CMD ["serve", "-c", "/etc/fleetcore/fleet.yaml"]
