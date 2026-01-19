#!/bin/bash
set -e

# Configuration
REGISTRY="registry.smtx.io/xingyu.ren"
IMAGE_NAME="claudereview"
BUN_IMAGE="registry.smtx.io/xingyu.ren/oven/bun:canary-debian"
PLATFORMS="linux/amd64,linux/arm64"

# Get version from package.json
VERSION=$(grep '"version"' package.json | head -1 | sed 's/.*: "\(.*\)".*/\1/')
GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Full image tags
IMAGE_TAG="${REGISTRY}/${IMAGE_NAME}:${VERSION}"
IMAGE_TAG_LATEST="${REGISTRY}/${IMAGE_NAME}:latest"
IMAGE_TAG_SHA="${REGISTRY}/${IMAGE_NAME}:${GIT_SHA}"

echo "Building ${IMAGE_NAME} (multi-arch)..."
echo "  Version: ${VERSION}"
echo "  Git SHA: ${GIT_SHA}"
echo "  Base image: ${BUN_IMAGE}"
echo "  Platforms: ${PLATFORMS}"
echo ""

# Ensure buildx builder exists
if ! docker buildx inspect multiarch-builder &>/dev/null; then
  echo "Creating buildx builder..."
  docker buildx create --name multiarch-builder --use
fi
docker buildx use multiarch-builder

# Build and push multi-arch image
docker buildx build \
  --platform "${PLATFORMS}" \
  --build-arg BUN_IMAGE="${BUN_IMAGE}" \
  -t "${IMAGE_TAG}" \
  -t "${IMAGE_TAG_LATEST}" \
  -t "${IMAGE_TAG_SHA}" \
  --push \
  .

echo ""
echo "Pushed multi-arch images:"
echo "  ${IMAGE_TAG}"
echo "  ${IMAGE_TAG_LATEST}"
echo "  ${IMAGE_TAG_SHA}"
