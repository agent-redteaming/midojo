#!/usr/bin/env bash
# Container entrypoint for the eval_hub_suite HTTP-wrapped pi agent.
#
# Generates pi's model configuration from the LiteLLM credentials injected via
# the pod environment (kept out of the image), then starts the HTTP wrapper.
set -euo pipefail

: "${LITELLM_API_URL:?LITELLM_API_URL is required (LiteLLM/MaaS base URL, e.g. https://.../v1)}"
: "${LITELLM_API_KEY:?LITELLM_API_KEY is required}"
: "${LITELLM_MODEL:?LITELLM_MODEL is required (model id served by the endpoint)}"

: "${HOME:=/opt/app-root/src}"
: "${PI_CONFIG_DIR:=${HOME}/.pi}"
: "${AGENT_GLOBAL_DIR:=${PI_CONFIG_DIR}/agent}"
: "${AGENT_DIR:=${HOME}/agent}"
export HOME PI_CONFIG_DIR AGENT_GLOBAL_DIR AGENT_DIR

mkdir -p "${PI_CONFIG_DIR}" "${AGENT_GLOBAL_DIR}" "${AGENT_DIR}/.pi"

# Build models.json / settings.json safely (JSON.stringify handles any chars in
# the creds). Write models.json to both locations pi may read (config root and
# the agent subdir) and settings.json to the config root + project dir.
node <<'NODE'
const fs = require("node:fs");
const p = process.env;
const providerId = "litellm";
const models = {
  providers: {
    [providerId]: {
      name: "LiteLLM",
      baseUrl: p.LITELLM_API_URL,
      apiKey: p.LITELLM_API_KEY,
      api: "openai-completions",
      compat: { supportsDeveloperRole: false, supportsReasoningEffort: false },
      models: [
        {
          id: p.LITELLM_MODEL,
          name: p.LITELLM_MODEL,
          // Most MaaS-hosted models (e.g. qwen3 family) emit a reasoning trace;
          // mark reasoning so pi parses reasoning_content and still captures the
          // final answer. Set PI_MODEL_REASONING=false to override.
          reasoning: (p.PI_MODEL_REASONING || "true") !== "false",
          input: ["text"],
          cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
          contextWindow: 128000,
          maxTokens: parseInt(p.PI_MODEL_MAX_TOKENS || "8192", 10),
        },
      ],
    },
  },
};
const settings = { defaultProvider: providerId, defaultModel: p.LITELLM_MODEL };
const modelsJSON = JSON.stringify(models, null, 2);
const settingsJSON = JSON.stringify(settings, null, 2);
fs.writeFileSync(`${p.PI_CONFIG_DIR}/models.json`, modelsJSON);
fs.writeFileSync(`${p.AGENT_GLOBAL_DIR}/models.json`, modelsJSON);
fs.writeFileSync(`${p.PI_CONFIG_DIR}/settings.json`, settingsJSON);
fs.writeFileSync(`${p.AGENT_DIR}/.pi/settings.json`, settingsJSON);
console.log(`[pi-agent] wrote pi model config for provider=${providerId} model=${p.LITELLM_MODEL}`);
NODE

exec node "${APP_DIR:-/opt/app-root/app}/server.mjs"
