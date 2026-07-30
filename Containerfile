# Shared image for midojo + its suites. One image, many entrypoints — each
# Deployment/Job overrides command/args (midojo-serve, minibank-*-serve,
# minibank-a2a-agent, midojo-run).
#
# Built in-cluster on OpenShift via a binary Docker-strategy BuildConfig, or
# locally with podman. Uses a Red Hat UBI Python base so the in-cluster build
# pulls from registry.access.redhat.com (no Docker Hub pull-rate limits):
#   oc new-build --name=midojo --binary --strategy=docker
#   oc patch bc/midojo --type=merge \
#     -p '{"spec":{"strategy":{"dockerStrategy":{"dockerfilePath":"Containerfile"}}}}'
#   oc start-build midojo --from-dir=. --follow
# or locally:
#   podman build -t quay.io/<you>/midojo:latest -f Containerfile .
FROM registry.access.redhat.com/ubi9/python-312:latest

# UBI's default user is 1001; run the build steps as root, then drop back to an
# unprivileged UID at the end.
USER 0

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
