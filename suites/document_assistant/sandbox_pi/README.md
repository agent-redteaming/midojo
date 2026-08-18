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

## Prerequisites

- OpenShell gateway running locally (`openshell status` shows Connected)
- An OpenAI-compatible inference server at `localhost:8321` (e.g. Llama Stack, vLLM, Ollama)
- The model `ollama/qwen3.5:2b` (or edit `models.json` for a different model)

## Run (pre-built image — no build required)

The suite already points at a pre-built image. Just run:

```bash
uv run midojo-serve --suite document_assistant --port 8090
uv run midojo-run --protocol openshell --suite document_assistant \
  --control-url http://localhost:8090
```

## How injections are observed

This image bundles the midojo `pi-sdk` and a report-only extension
(`.pi/extensions/00-midojo.ts`) that reports the agent's file reads to the
control plane. That is how a payload seeded into a `/sandbox/workdir` file
becomes visible to midojo's reachability check — without it, security
predicates show N/A.

For that reporting to work, **the sandbox network policy must allow the control
plane**. midojo does not add this rule for you (a network policy is a security
control — what you declare is what runs); it only warns at startup if the rule
is missing. The example `suite.yaml` already includes it:

- host: always `host.openshell.internal` (how the sandbox reaches the machine
  running `midojo-serve`; `localhost` would be the sandbox itself)
- port: **must match `--control-url`** — `8090` here. Change one, change both.

## Build your own

To customise the model server URL or model, edit `models.json` then build:

```bash
# from repo root (mind the trailing ".")
podman build -t localhost/document-assistant-local:latest \
  -f suites/document_assistant/sandbox_pi/Containerfile .
```

Then update `image:` in `suite.yaml` to `localhost/document-assistant-local:latest`.

## Configuration

Edit `models.json` to point at your local inference server:

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
