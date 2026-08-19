"""MiDojo Artifact Generator — bridge from scenario forge to MiDojo execution.

Reads a scenario-forge STPA-Sec run directory and produces MiDojo test
artifacts: suite YAMLs, proxy configs, and run scripts.

Three tiers generated automatically:
  - Black box: scenarios with direct entry points → prompt-level attacks
  - Grey box: scenarios with indirect entry points → data injection via proxy
  - (White box: manual authoring, scaffold provided)

Usage::

    python -m midojo.artifact_gen /path/to/forge-run --output ./midojo-artifacts \\
        --llm-url http://localhost:8321/v1 --llm-model openai/gemma-4-26b
"""
