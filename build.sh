#!/usr/bin/env bash
CONTAINER_REPO="danielewood"
CONTAINER_NAME="httpheaders"
CONTAINER_VERSION="latest"

# Create the builder:
docker buildx rm -f multiarch
docker buildx create --name multiarch --driver docker-container --bootstrap --use

# Build with multi-arch support
#   --platform linux/arm64 \
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7,linux/arm/v6,linux/386 \
  --tag "${CONTAINER_REPO}/${CONTAINER_NAME}":"${CONTAINER_VERSION}" \
  --push .

# Pull the image
docker pull "${CONTAINER_REPO}/${CONTAINER_NAME}":"${CONTAINER_VERSION}"

# Stop and remove the existing container
docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true

# Run with Prometheus enabled
# docker run -it --rm \
docker run --rm \
  -p 8080:8080 \
  -p 8081:8081 \
  -p 9090:9090 \
  -e PROMETHEUS_ENABLED=false \
  --name "${CONTAINER_NAME}" \
  "${CONTAINER_REPO}/${CONTAINER_NAME}":"${CONTAINER_VERSION}"