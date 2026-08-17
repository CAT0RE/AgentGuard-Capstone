"""Optional integrations with third-party agent frameworks and benchmarks."""

from .agentdojo import (
    agentdojo_log_to_case,
    convert_agentdojo_logs,
    evaluate_agentdojo_logs,
    infer_agentdojo_tool_spec,
    make_agentdojo_executor,
)
from .injecagent import (
    convert_injecagent_dataset,
    evaluate_injecagent_dataset,
    injecagent_record_to_case,
    injecagent_safe_control_to_case,
)

__all__ = [
    "agentdojo_log_to_case",
    "convert_agentdojo_logs",
    "evaluate_agentdojo_logs",
    "infer_agentdojo_tool_spec",
    "make_agentdojo_executor",
    "convert_injecagent_dataset",
    "evaluate_injecagent_dataset",
    "injecagent_record_to_case",
    "injecagent_safe_control_to_case",
]
