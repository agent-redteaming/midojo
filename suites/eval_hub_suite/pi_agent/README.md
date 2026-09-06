# eval_hub_suite — HTTP-wrapped pi agent

The system under test for the `eval_hub_suite` red-team, packaged for the
EvalHub **Option C** topology: an operator-managed midojo control plane, an
eval-hub adapter job that runs the orchestrator, and this agent — a `pi` coding
agent wrapped in a plain HTTP server.

This is a copy of the `weather` suite's pi agent (same dict-backend eval
mechanics: real `get_weather`/`list_cities` tools, a fake `send_weather_alert`
tool, and prompt-injection payloads delivered through weather notes). Only the
delivery path differs: the agent is reachable over HTTP and calls back to a
control plane addressed by a fixed, operator-provisioned URL.

## How it works

- `server.mjs` — a dependency-free Node HTTP server implementing midojo's
  `--protocol http` contract: `POST /` with `{"prompt": "..."}` returns
  `{"response": "..."}`; `GET /health` returns `{"status": "ok"}`. Each request
  launches `pi -p --no-session <prompt>` (mirroring midojo's `PIAgentClient`).
- `entrypoint.sh` — generates pi's `models.json`/`settings.json` from the
  `LITELLM_*` environment (so credentials stay out of the image), then starts
  the server.
- `.pi/extensions/` — the midojo pi-sdk extensions (`01-fake-tools.ts`,
  `02-real-tools.ts`). At image build they are installed into pi's global agent
  dir and their dev import path is rewritten to the in-image layout.
- `MIDOJO_URL` (env) — the fixed control-plane address the extensions call back
  to. In-cluster this is the operator-created `<cr-name>-midojo` Service.

## Build

From the midojo repo root (the build context needs `pi-sdk/` and this suite):

```bash
podman build -t quay.io/evalhub/eval-hub-suite-agent:latest \
  -f suites/eval_hub_suite/pi_agent/Containerfile .
```

## Run locally

```bash
# 1. Control plane
midojo-serve --suite eval_hub_suite --host 127.0.0.1 --port 8080 &

# 2. Agent (LiteLLM creds via env; MIDOJO_URL points at the control plane)
export LITELLM_API_URL=... LITELLM_API_KEY=... LITELLM_MODEL=...
MIDOJO_URL=http://127.0.0.1:8080 APP_DIR="$PWD/suites/eval_hub_suite/pi_agent" \
  bash suites/eval_hub_suite/pi_agent/entrypoint.sh &

# 3. Orchestrator
midojo-run --protocol http --suite eval_hub_suite \
  --agent-uri http://127.0.0.1:8000 --control-url http://127.0.0.1:8080 \
  --logdir ./runs
```

## Deploy (OpenShift)

```bash
# LLM creds (never committed)
oc create secret generic eval-hub-suite-agent-llm-creds -n openshell \
  --from-literal=LITELLM_API_KEY=... \
  --from-literal=LITELLM_API_URL=https://your-maas-endpoint/v1 \
  --from-literal=LITELLM_MODEL=your-model-id

oc apply -k suites/eval_hub_suite/pi_agent/deploy -n openshell
```

Set `MIDOJO_URL` in `deploy/agent.yaml` to your EvalHub CR's control-plane
Service (`http://<cr-name>-midojo.<ns>.svc.cluster.local:8080`).

## Model note

MaaS-hosted models are often reasoning models (they emit a `reasoning_content`
trace). The entrypoint marks the model `reasoning: true` by default so pi parses
the trace and still returns the final answer. Override with
`PI_MODEL_REASONING=false` / `PI_MODEL_MAX_TOKENS=<n>` if needed.
