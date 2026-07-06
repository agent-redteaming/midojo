# Document Assistant — Example Sandbox

An example OpenShell sandbox for the `document_assistant` suite. Extends the
[pi community sandbox](https://github.com/NVIDIA/OpenShell-Community/tree/main/sandboxes/pi)
with a pre-configured local inference provider so no cloud API key is required.

## What this is

This is the **example agent** for the PoC — equivalent to the A2A agent in the
minibank suite. It lets you run the suite out of the box against a local model
server without any cloud credentials.

**Replace it with your own production sandbox image** when you're red-teaming a
real agent. The `suite.yaml` evaluation (workspace files, injection tasks,
predicates) does not change — only the `image:` field in the backend config.

## Build

```bash
podman build --platform linux/amd64 \
  -t document-assistant-local:latest \
  -f suites/document_assistant/sandbox/Containerfile .
```

## Configuration

Edit `models.json` to point at your local inference server before building:

| Field | Value | Notes |
|---|---|---|
| `baseUrl` | `http://host.openshell.internal:<port>/v1` | `host.openshell.internal` resolves to the host from inside the sandbox |
| `models[].id` | your model name | must match what the server advertises |

## Bring your own agent

Any OpenShell sandbox image that runs PI works as a drop-in replacement:

```yaml
# suite.yaml
environment:
  backend:
    type: openshell
    image: my-production-pi-sandbox   # ← change this only
    agent_command: ["pi", "-p", "--no-session"]
```

The sandbox must have PI pre-configured to connect to whatever inference
endpoint it uses. The suite does not inject any agent configuration.
