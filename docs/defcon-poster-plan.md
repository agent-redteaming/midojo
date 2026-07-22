# DEF CON 34 AI Village Poster: MiDojo

## Context

MiDojo poster accepted to DEF CON 34 AI Village (Aug 7-10, 2026). Digital screen poster. Need to design concrete content, run benchmark experiments, and build the poster. Ollama + OpenAI API available for benchmarks. 3-5 days of compute for experiments.

## Narrative Arc

**One sentence:** MiDojo red-teams AI agents through their actual tools — intercepting, injecting, and grading attacks across 6 surfaces that mirror how real prompt injections land.

**The story in 3 beats:**

1. **The problem:** Tool-using AI agents are vulnerable to prompt injection through many surfaces — not just the user prompt. Current testing tools only check one surface at a time, in simulated environments.

2. **The approach:** MiDojo is a man-in-the-middle framework. It sits between the agent and its tools, injecting attacks through the same channels a real attacker would use — poisoned data fields, hijacked tool responses, modified tool descriptions — while the agent does real work.

3. **The results:** We tested N models across 6 attack surfaces with 18 delivery techniques and 4 adaptive strategies. Here's what breaks, what holds, and what surprised us.

---

## Poster Layout (6 panels for digital screen)

```
┌──────────────────────────────────────────────────────────────┐
│  TITLE BAR: MiDojo: Red-Team Any Agent in Any Environment    │
│  Authors | Red Hat | QR code to repo                         │
├────────────────────────────┬─────────────────────────────────┤
│                            │                                 │
│  PANEL 1: The Problem      │  PANEL 2: The MITM Architecture│
│  Why agent red-teaming     │  The killer diagram showing     │
│  is broken today           │  fake MCP interposition         │
│                            │                                 │
├────────────────────────────┼─────────────────────────────────┤
│                            │                                 │
│  PANEL 3: 6 Attack         │  PANEL 4: Composable Attack    │
│  Surfaces                  │  Library                        │
│  The unique contribution   │  Wrappers × Channels ×          │
│                            │  Strategies × Goals             │
│                            │                                 │
├────────────────────────────┴─────────────────────────────────┤
│                                                              │
│  PANEL 5: Results                                            │
│  Heatmaps / tables showing what breaks                       │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│  PANEL 6: Try It Yourself — 3 commands to red-team your agent│
└──────────────────────────────────────────────────────────────┘
```

---

## Panel 1: The Problem (left side, compact)

**Headline:** "Your agent's tools are its attack surface"

**Key points (3 bullets):**
- AI agents with tools are vulnerable to prompt injection through MANY surfaces — not just the user prompt
- The agent's tools, their data, and the tool descriptions are all attacker-controlled in realistic threat models
- Current red-teaming tools test one surface at a time in simulated environments — missing how real attacks land

**Visual:** Simple diagram showing 6 arrows pointing at an agent from different directions (user prompt, tool data, tool description, tool response, memory, inter-agent), each labeled with a real CVE or incident:
- User prompt: Classic jailbreaks
- Tool data: Indirect prompt injection (Greshake et al.)
- Tool description: MCP tool poisoning (Invariant Labs, CVE-2025-54136)
- Tool response: ATPA (CyberArk 2025)
- Memory: MINJA (NeurIPS 2025)
- Inter-agent: A2A data poisoning

---

## Panel 2: The MITM Architecture

**Headline:** "Man-in-the-middle, not simulation"

**Visual:** The architecture diagram (refined version of the AGENTS.md mermaid diagram):

```
                     ┌─────────────┐
                     │ Orchestrator│
                     │ midojo-run  │
                     └──┬──────┬───┘
                        │      │
              prompt    │      │ create eval
              + inject  │      │ + grade
                        │      │
                        ▼      ▼
  ┌─────────┐    ┌──────────────────┐
  │  Agent   │◄──►│  Control Plane  │
  │ (target) │    │  (state + grade)│
  └────┬─────┘    └───────▲─────────┘
       │                  │
       │ tool calls       │ env state
       │ + responses      │ + recording
       │                  │
  ┌────▼──────────────────┴──┐
  │     Fake MCP Server      │
  │  ┌─────┐ ┌─────┐ ┌────┐ │
  │  │Tool1│ │Tool2│ │ToolN│ │◄──► Real MCP
  │  │ FWD │ │INJECT│ │BOTH│ │     (optional)
  │  └─────┘ └─────┘ └────┘ │
  └──────────────────────────┘
```

**Key callouts:**
- "No agent modification — works with any MCP-compatible agent"
- "Swiss-cheese: each tool independently forwards, intercepts, or both"
- "Payloads land in tool responses, exactly how real attacks arrive"

---

## Panel 3: 6 Attack Surfaces

**Headline:** "Every channel a real attacker would use"

**Visual:** A table or visual showing 6 channels mapped to attacker access levels:

| Attack Surface | Channel | How Payload Arrives | Attacker Access | Real-World Reference |
|---|---|---|---|---|
| **User Prompt** | `user_prompt` | Injected directly into the user's message | Black-box (user input) | Classic jailbreaks, DAN |
| **Environment Data** | `environment_state` | Hidden in data fields the agent reads (customer notes, transaction descriptions) | Gray-box (data source) | Indirect PI (Greshake 2023) |
| **Tool Descriptions** | `tool_description` | Hidden directive in MCP tool description | Gray-box (tool registry) | TPA (Invariant Labs 2025), MCPTox |
| **Tool Responses** | `tool_output` | Injected into tool return values at runtime | White-box (compromised tool) | ATPA (CyberArk 2025) |
| **Memory/RAG** | `memory` | Poisoned entries in agent's memory store | Gray-box (knowledge base) | MINJA (NeurIPS 2025), PoisonedRAG |
| **Inter-Agent** | `inter_agent` | Forged messages between agents | White-box (compromised agent) | A2A data poisoning |

**Callout:** "MiDojo is the first framework to test all 6 surfaces in a unified evaluation — utility AND security scored together."

---

## Panel 4: Composable Attack Library

**Headline:** "Attack = Wrappers × Channel × Strategy × Goal"

**Visual:** Show the composition model with concrete examples:

**18 Delivery Techniques** (payload wrappers):
- Direct: important_instructions, persona_hijack (DAN), authority_spoofing, dev_mode, context_switch, ...
- Encoding: base64, unicode_homoglyph, zero_width_smuggle, typoglycemia, payload_split
- Framing: delayed_trigger, authority_impersonation, progressive_escalation

**5 Search Strategies:**
- Static (one-shot)
- PAIR (iterative adversarial refinement, Chao et al. NeurIPS 2023)
- TAP (tree search with pruning, Mehrotra et al. NeurIPS 2024)
- Best-of-N (brute-force variation)
- Crescendo (progressive multi-turn, Russinovich USENIX 2025)

**Composability example:**
```yaml
attack:
  wrappers: [refusal_suppression, persona_hijack, base64_encode]
  channel: tool_output
  strategy:
    type: pair
    streams: 3
    max_iterations: 5
  goal: data_exfiltration
```
"This attack: suppresses refusal → hijacks persona → base64 encodes → injects into tool response → iterates with PAIR until it finds a payload that works."

**Math:** 18 wrappers × 6 channels × 5 strategies = 540 distinct attack configurations from composable pieces.

---

## Panel 5: Results

**Headline:** "What breaks, what holds, and what surprised us"

This panel needs benchmark data. Experiments to run:

### Experiment 1: Wrapper Effectiveness Across Models
- Suite: minibank (banking agent with 12 tools)
- Channel: environment_state (indirect injection via transaction notes)
- Strategy: static (one-shot)
- Models: qwen3.5:2b (local), llama3.2:3b (local), GPT-4o-mini (OpenAI)
- Wrappers: all 18, one run per wrapper per model
- Total runs: 18 × 3 = 54
- Present as: heatmap (wrapper × model → attack success rate)

### Experiment 2: Channel Effectiveness
- Suite: minibank
- Wrapper: important_instructions (fixed)
- Strategy: static
- Models: same 3
- Channels: environment_state, user_prompt, tool_description, tool_output
- Total runs: 4 × 3 = 12
- Present as: bar chart (channel → ASR per model)

### Experiment 3: Static vs Adaptive
- Suite: minibank
- Wrapper: important_instructions
- Channel: environment_state
- Models: same 3
- Strategies: static, pair, best_of_n (n=5)
- Total runs: 3 × 3 = 9 (but PAIR/BoN do multiple evals internally)
- Present as: bar chart (strategy → ASR, with total evals shown)

### Experiment 4: The Money Shot — Full Matrix
- Combine the most interesting findings from 1-3 into one summary table:

| | qwen3.5:2b | llama3.2:3b | GPT-4o-mini |
|---|---|---|---|
| Best static wrapper (which?) | X% | X% | X% |
| Best channel (which?) | X% | X% | X% |
| Static vs PAIR improvement | +X pp | +X pp | +X pp |
| Overall attack surface coverage | X/6 channels | X/6 channels | X/6 channels |

**Total benchmark runs needed:** ~75 runs. At ~2 min per static run, ~10 min per PAIR run = ~3-4 hours of compute.

### Presentation format:
- Heatmap for Experiment 1 (color-coded: red=attack succeeded, green=agent resisted)
- Bar charts for Experiments 2-3
- Summary table for Experiment 4

---

## Panel 6: Try It Yourself

**Headline:** "Red-team your agent in 3 commands"

```bash
# 1. Start MiDojo (control plane + fake MCP)
midojo-serve --suite minibank --port 8080
minibank-fake-mcp-serve --port 8082

# 2. Run the benchmark
midojo-run --agent-url http://your-agent:8080 \
    --protocol openai --suite minibank

# 3. Run with adaptive attacks
midojo-run ... --attacker-model gpt-4o \
    --attacker-api-key $OPENAI_API_KEY
```

**QR code** → GitHub repo

**Callout:** "Works with any MCP-compatible agent. No agent modification. Supports OpenAI, OGX, A2A, HTTP protocols."

**Small footer:** "Part of a larger pipeline: policy-mapper → scenario-forge → MiDojo. Automate red-teaming from compliance requirements to attack execution."

---

## Pre-Poster Work Needed

1. **Run benchmark experiments** (3-4 hours of compute)
   - Set up GPT-4o-mini via OpenAI protocol
   - Pull llama3.2:3b via Ollama
   - Run all 75 experiments, collect results
   - Generate heatmaps and charts

2. **Build the poster** (digital screen format)
   - HTML/CSS or PowerPoint
   - Clean diagrams (redraw the architecture in a design tool)
   - Include heatmaps from experiment data

3. **Prepare talking points** (for when people ask at the poster)
   - "What's the most effective attack?" → Experiment 1 results
   - "Does this work against GPT-4?" → Experiment 4 results
   - "How is this different from garak/PyRIT?" → MITM design, 6 channels, utility+security
   - "Can I use this on my agent?" → Panel 6, 3 commands

---

## Timeline

| When | What |
|---|---|
| Week 1 (Jul 22-28) | Run benchmark experiments, collect data |
| Week 2 (Jul 29-Aug 4) | Build poster visuals, generate charts from data |
| Aug 5-6 | Final review + polish |
| Aug 7-10 | DEF CON 34 |
