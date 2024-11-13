FROM --platform=$BUILDPLATFORM golang:alpine AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app
COPY main.go .
COPY internal internal
# COPY go.mod .

# Initialize go.mod and add dependencies
RUN go mod init httpheaders && \
    go mod tidy && \
    go get github.com/prometheus/client_golang/prometheus && \
    go get github.com/prometheus/client_golang/prometheus/promauto && \
    go get github.com/prometheus/client_golang/prometheus/promhttp

# Build with all size and memory optimizations
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    CGO_ENABLED=0 \
    GO_EXTLINK_ENABLED=0 \
    CGO_LDFLAGS="-s -w" \
    go build \
    -ldflags="-s -w -extldflags '-static'" \
    -trimpath \
    -tags netgo \
    -a -installsuffix cgo \
    -o httpheaders .

FROM scratch

# Set memory limits and garbage collection optimizations
ENV GOGC=off \
    GOMEMLIMIT=64MiB \
    GODEBUG=madvdontneed=1

COPY --from=builder /app/httpheaders /httpheaders

LABEL \
    org.opencontainers.image.title="httpheaders" \
    org.opencontainers.image.description="Docker image that echoes request data as JSON; listens on HTTP, useful for debugging." \
    org.opencontainers.image.url="https://hub.docker.com/r/danielewood/httpheaders" \
    org.opencontainers.image.documentation="https://github.com/danielewood/httpheaders/blob/master/README.md" \
    org.opencontainers.image.source="https://github.com/danielewood/httpheaders" \
    org.opencontainers.image.licenses="MIT"

# No need to run as root, unless you want to bind to ports < 1024
USER 1000

# Set default environment variables
# if not provided, these are set within the app automatically
ENV CORS_ALLOW_CREDENTIALS="" \
	JSON_LOGGING=true \
	LOG_RESPONSE=true \
    CORS_ALLOW_HEADERS="" \
    CORS_ALLOW_METHODS="" \
    CORS_ALLOW_ORIGIN="" \
    DISABLE_COLOR_OUTPUT=false \
    DISABLE_REQUEST_LOGS=false \
    ECHO_BACK_TO_CLIENT=true \
    ECHO_INCLUDE_ENV_VARS=false \
    LOG_IGNORE_PATH="" \
    LOG_WITHOUT_NEWLINE=false \
    OVERRIDE_RESPONSE_BODY_FILE_PATH="" \
    PRESERVE_HEADER_CASE=false \
    PROMETHEUS_ENABLED=true

ENV HEALTH_PORT=8081 \
    METRICS_PORT=9090 \
    SERVICE_PORT=8080
EXPOSE $HEALTH_PORT $METRICS_PORT $SERVICE_PORT

ENTRYPOINT ["/httpheaders"]