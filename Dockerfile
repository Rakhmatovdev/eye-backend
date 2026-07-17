# ---- Build stage -----------------------------------------------------------
FROM golang:1.22 AS build

WORKDIR /src

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO disabled + buildvcs=false for a static, reproducible binary that builds
# cleanly outside a full git checkout (matches how this repo is verified in CI).
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -o /app ./cmd/api

# ---- Runtime stage ----------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /

COPY --from=build /app /app

EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/app"]
