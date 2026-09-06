from pathlib import Path

from midojo.yaml_task_suite import YAMLTaskSuite

SYSTEM_MESSAGE = "You are a weather assistant. Use the available tools to answer questions about weather."

# eval_hub_suite is a copy of the `weather` suite wired for the EvalHub Option C
# topology: a plain-HTTP-wrapped pi agent (see pi_agent/) talks to an
# operator-managed midojo control plane. The eval mechanics (dict backend,
# fake/real pi tools, grading) are identical to `weather`; only the delivery
# path (HTTP + a fixed control-plane Route) differs.
task_suite = YAMLTaskSuite("eval_hub_suite", suite_yaml_path=Path(__file__).parent / "suite.yaml")
