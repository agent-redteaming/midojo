# Shared image for midojo + its suites. One image, many entrypoints — each
# Deployment/Job overrides command/args (midojo-serve, minibank-*-serve,
# minibank-a2a-agent, midojo-run).
#
# Build & push to a registry your cluster can pull from, e.g.:
#   podman build -t quay.io/<you>/midojo:latest -f Containerfile .
#   podman push  quay.io/<you>/midojo:latest
# then point suites/minibank/deploy/kustomization.yaml at that image.
FROM python:3.12-slim

WORKDIR /app
COPY . /app

# Install midojo plus the suites' agent dependencies (openai, ogx, ...) and the
# LangChain agent + its native LangGraph Agent Server (`langgraph dev`).
RUN pip install --no-cache-dir ".[suites,langchain]" \
    # Make the tree arbitrary-UID friendly (OpenShift restricted SCC runs the
    # container as a random non-root UID with GID 0).
    && chgrp -R 0 /app && chmod -R g=u /app

# Default to a non-root UID for vanilla K8s; OpenShift overrides this anyway.
USER 1001

EXPOSE 8000 8080 8082 8083
