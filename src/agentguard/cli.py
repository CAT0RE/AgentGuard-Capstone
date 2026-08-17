from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .agent_scenarios import AGENT_SCENARIOS, build_offline_scenario
from .dataset_tools import annotation_agreement, freeze_dataset, validate_dataset
from .demo import SCENARIOS, run_scenario
from .evaluation import evaluate_file
from .integrations.agentdojo import convert_agentdojo_logs, evaluate_agentdojo_logs
from .integrations.injecagent import convert_injecagent_dataset, evaluate_injecagent_dataset
from .monitor import SecurityMonitor
from .paths import default_benchmark_path
from .policy import profile_policy
from .providers import OpenAIResponsesProvider
from .runner import MonitoredAgentRunner
from .server import serve


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentguard", description="Security monitor for tool-using LLM agents")
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo = subparsers.add_parser("demo", help="Run a built-in security scenario")
    demo.add_argument("--scenario", choices=sorted(SCENARIOS), default="indirect_prompt_injection")
    demo.add_argument("--policy", choices=("strict", "balanced", "permissive"), default="balanced")
    demo.add_argument("--json", action="store_true", help="Print the complete JSON trace")

    agent_demo = subparsers.add_parser("agent-demo", help="Run a monitored model-to-tool agent loop")
    agent_demo.add_argument("--scenario", choices=sorted(AGENT_SCENARIOS), default="injected_email")
    agent_demo.add_argument("--provider", choices=("offline", "openai"), default="offline")
    agent_demo.add_argument("--model", default="gpt-5.4-nano", help="Model used only with provider=openai")
    agent_demo.add_argument("--policy", choices=("strict", "balanced", "permissive"), default="balanced")
    agent_demo.add_argument("--json", action="store_true", help="Print the complete JSON trace")

    evaluate = subparsers.add_parser("evaluate", help="Evaluate baseline and full monitors")
    evaluate.add_argument("--dataset", type=Path, default=default_benchmark_path())
    evaluate.add_argument("--output", type=Path)
    evaluate.add_argument("--bootstrap-samples", type=int, default=1000)
    evaluate.add_argument(
        "--profiles",
        nargs="+",
        choices=("none", "keyword", "tool_policy", "full_v1", "full", "full_v3", "full_v4", "full_v5"),
        default=["none", "keyword", "tool_policy", "full_v1", "full", "full_v3", "full_v5"],
    )

    server = subparsers.add_parser("serve", help="Start the local dashboard")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8080)
    server.add_argument("--dataset", type=Path, default=default_benchmark_path())

    validate = subparsers.add_parser("validate-dataset", help="Validate benchmark JSONL and annotations")
    validate.add_argument("--dataset", type=Path, default=default_benchmark_path())
    validate.add_argument("--require-annotations", action="store_true")

    freeze = subparsers.add_parser("freeze-dataset", help="Validate and hash a frozen experiment dataset")
    freeze.add_argument("--dataset", type=Path, required=True)
    freeze.add_argument("--manifest", type=Path, required=True)
    freeze.add_argument("--development", action="store_true", help="Allow missing final-study annotation fields")

    agreement = subparsers.add_parser("agreement", help="Calculate inter-annotator Cohen kappa")
    agreement.add_argument("--annotator-a", type=Path, required=True)
    agreement.add_argument("--annotator-b", type=Path, required=True)

    dojo_convert = subparsers.add_parser(
        "agentdojo-convert", help="Convert AgentDojo TraceLogger JSON files to AgentGuard JSONL"
    )
    dojo_convert.add_argument("--input", type=Path, required=True, help="AgentDojo JSON file or run directory")
    dojo_convert.add_argument("--output", type=Path, required=True)

    dojo_evaluate = subparsers.add_parser(
        "agentdojo-evaluate", help="Evaluate monitor profiles against AgentDojo security labels"
    )
    dojo_evaluate.add_argument("--input", type=Path, required=True, help="AgentDojo JSON file or run directory")
    dojo_evaluate.add_argument("--output", type=Path)
    dojo_evaluate.add_argument("--bootstrap-samples", type=int, default=1000)
    dojo_evaluate.add_argument(
        "--profiles",
        nargs="+",
        choices=("none", "keyword", "tool_policy", "full_v1", "full", "full_v3", "full_v4", "full_v5"),
        default=["none", "keyword", "tool_policy", "full_v1", "full", "full_v3", "full_v5"],
    )

    injec_convert = subparsers.add_parser(
        "injecagent-convert", help="Convert official InjecAgent base cases to AgentGuard JSONL"
    )
    injec_convert.add_argument("--input", type=Path, required=True, help="Root of the InjecAgent repository")
    injec_convert.add_argument("--output", type=Path, required=True)
    injec_convert.add_argument("--no-safe-controls", action="store_true")

    injec_evaluate = subparsers.add_parser(
        "injecagent-evaluate", help="Evaluate monitor profiles on official InjecAgent base cases"
    )
    injec_evaluate.add_argument("--input", type=Path, required=True, help="Root of the InjecAgent repository")
    injec_evaluate.add_argument("--output", type=Path)
    injec_evaluate.add_argument("--bootstrap-samples", type=int, default=1000)
    injec_evaluate.add_argument("--no-safe-controls", action="store_true")
    injec_evaluate.add_argument(
        "--profiles",
        nargs="+",
        choices=("none", "keyword", "tool_policy", "full_v1", "full", "full_v3", "full_v4", "full_v5"),
        default=["none", "keyword", "tool_policy", "full_v1", "full", "full_v3", "full_v5"],
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "demo":
        monitor = SecurityMonitor(policy=profile_policy(args.policy))
        result = run_scenario(monitor, args.scenario)
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            _print_demo(result)
    elif args.command == "agent-demo":
        scenario, replay_provider, sandbox = build_offline_scenario(args.scenario)
        provider = (
            replay_provider
            if args.provider == "offline"
            else OpenAIResponsesProvider(model=args.model, api_key=os.environ.get("OPENAI_API_KEY"))
        )
        runner = MonitoredAgentRunner(
            provider,
            monitor=SecurityMonitor(policy=profile_policy(args.policy)),
            sandbox=sandbox,
        )
        preauthorized = set(scenario.preauthorized_tools)
        result = runner.run(
            scenario.user_intent,
            allowed_tools=scenario.allowed_tools,
            authorized_destinations=scenario.authorized_destinations,
            authorization_resolver=lambda _call, monitor_name: monitor_name in preauthorized,
        ).to_dict()
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            _print_agent_run(result, scenario.expected_status)
    elif args.command == "evaluate":
        result = evaluate_file(args.dataset, args.profiles, bootstrap_samples=args.bootstrap_samples)
        rendered = json.dumps(result, indent=2, ensure_ascii=False)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n", encoding="utf-8")
            print(f"Wrote evaluation results to {args.output}")
        print(_metrics_table(result))
    elif args.command == "serve":
        serve(args.host, args.port, args.dataset)
    elif args.command == "validate-dataset":
        report = validate_dataset(args.dataset, require_annotations=args.require_annotations)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        if not report["valid"]:
            raise SystemExit(1)
    elif args.command == "freeze-dataset":
        manifest = freeze_dataset(args.dataset, args.manifest, require_annotations=not args.development)
        print(json.dumps(manifest, indent=2, ensure_ascii=False))
    elif args.command == "agreement":
        report = annotation_agreement(args.annotator_a, args.annotator_b)
        print(json.dumps(report, indent=2, ensure_ascii=False))
    elif args.command == "agentdojo-convert":
        cases = convert_agentdojo_logs(args.input)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        rendered = "\n".join(json.dumps(case, ensure_ascii=False) for case in cases) + "\n"
        args.output.write_text(rendered, encoding="utf-8")
        print(f"Converted {len(cases)} AgentDojo trace(s) to {args.output}")
    elif args.command == "agentdojo-evaluate":
        result = evaluate_agentdojo_logs(
            args.input, profiles=args.profiles, bootstrap_samples=args.bootstrap_samples
        )
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"Wrote AgentDojo evaluation results to {args.output}")
        print(_metrics_table(result))
    elif args.command == "injecagent-convert":
        cases = convert_injecagent_dataset(args.input, include_safe_controls=not args.no_safe_controls)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        rendered = "\n".join(json.dumps(case, ensure_ascii=False) for case in cases) + "\n"
        args.output.write_text(rendered, encoding="utf-8")
        print(f"Converted {len(cases)} InjecAgent case(s) to {args.output}")
    elif args.command == "injecagent-evaluate":
        result = evaluate_injecagent_dataset(
            args.input,
            profiles=args.profiles,
            bootstrap_samples=args.bootstrap_samples,
            include_safe_controls=not args.no_safe_controls,
        )
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"Wrote InjecAgent evaluation results to {args.output}")
        print(_metrics_table(result))


def _print_demo(result: dict) -> None:
    print(f"Scenario : {result['scenario']['title']}")
    print(f"Trace ID : {result['trace_id']}")
    print(f"Max risk : {result['max_risk_score']:.2f}/100")
    print(f"Halted   : {'yes' if result['halted'] else 'no'}")
    for index, item in enumerate(result["timeline"], 1):
        assessment = item["assessment"]
        print(
            f"  {index:02d}. {item['step']['type']:<12} "
            f"risk={assessment['score']:>6.2f} decision={assessment['decision']:<7} "
            f"findings={len(assessment['findings'])}"
        )
        for finding in assessment["findings"]:
            print(f"      - {finding['title']}: {finding['evidence']}")


def _print_agent_run(result: dict, expected_status: str) -> None:
    print(f"Provider : {result['provider']}")
    print(f"Trace ID : {result['trace_id']}")
    print(f"Status   : {result['status']} (expected {expected_status})")
    print(f"Turns    : {result['turns']}")
    print(f"Executed : {len(result['executed_tools'])} sandbox tool(s)")
    print(f"Output   : {result['final_text']}")
    for item in result["interventions"]:
        print(f"  intervention={item['decision']} risk={item['score']:.2f} kind={item['kind']}")
        print(f"    {item['explanation']}")


def _metrics_table(result: dict) -> str:
    lines = [
        "profile       precision  recall     f1   accuracy  p95 ms",
        "------------  ---------  ------  -----  --------  ------",
    ]
    for profile, value in result["profiles"].items():
        metrics = value["metrics"]
        lines.append(
            f"{profile:<12}  {metrics['precision']:>9.3f}  {metrics['recall']:>6.3f}  "
            f"{metrics['f1']:>5.3f}  {metrics['accuracy']:>8.3f}  {value['latency_ms']['p95']:>6.3f}"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    main()
