from __future__ import annotations

import json
import mimetypes
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import unquote, urlparse

from .agent_scenarios import AGENT_SCENARIOS, build_offline_scenario
from .demo import SCENARIOS, run_scenario
from .evaluation import evaluate_file
from .monitor import SecurityMonitor
from .paths import default_benchmark_path
from .policy import profile_policy
from .runner import MonitoredAgentRunner


class Application:
    def __init__(self, benchmark_path: Path) -> None:
        self.benchmark_path = benchmark_path
        self.runs: Dict[str, Dict[str, Any]] = {}

    def scenarios(self) -> Dict[str, Any]:
        return {"scenarios": [scenario.summary() for scenario in SCENARIOS.values()]}

    def agent_scenarios(self) -> Dict[str, Any]:
        return {
            "scenarios": [
                {
                    "id": item.scenario_id,
                    "title": item.title,
                    "user_intent": item.user_intent,
                    "expected_status": item.expected_status,
                }
                for item in AGENT_SCENARIOS.values()
            ]
        }

    def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        scenario_id = str(payload.get("scenario_id", "benign_email_summary"))
        policy = profile_policy(str(payload.get("policy", "balanced")))
        monitor = SecurityMonitor(policy=policy)
        result = run_scenario(monitor, scenario_id)
        self.runs[result["trace_id"]] = result
        return result

    def evaluate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        profiles = payload.get("profiles") or ["none", "keyword", "tool_policy", "full_v1", "full"]
        return evaluate_file(self.benchmark_path, profiles)

    def run_agent(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        scenario_id = str(payload.get("scenario_id", "injected_email"))
        policy = profile_policy(str(payload.get("policy", "balanced")))
        scenario, provider, sandbox = build_offline_scenario(scenario_id)
        runner = MonitoredAgentRunner(provider, monitor=SecurityMonitor(policy=policy), sandbox=sandbox)
        preauthorized = set(scenario.preauthorized_tools)
        result = runner.run(
            scenario.user_intent,
            allowed_tools=scenario.allowed_tools,
            authorized_destinations=scenario.authorized_destinations,
            authorization_resolver=lambda _call, monitor_name: monitor_name in preauthorized,
        ).to_dict()
        result["scenario"] = {
            "id": scenario.scenario_id,
            "title": scenario.title,
            "expected_status": scenario.expected_status,
        }
        self.runs[result["trace_id"]] = result
        return result


def make_handler(app: Application):
    class Handler(BaseHTTPRequestHandler):
        server_version = "AgentGuard/0.2"

        def do_GET(self) -> None:  # noqa: N802
            path = unquote(urlparse(self.path).path)
            if path == "/api/health":
                self._json({"status": "ok", "service": "AgentGuard"})
            elif path == "/api/scenarios":
                self._json(app.scenarios())
            elif path == "/api/agent-scenarios":
                self._json(app.agent_scenarios())
            elif path.startswith("/api/traces/"):
                trace_id = path.rsplit("/", 1)[-1]
                result = app.runs.get(trace_id)
                if result is None:
                    self._json({"error": "trace not found"}, HTTPStatus.NOT_FOUND)
                else:
                    self._json(result)
            elif path == "/api/traces":
                self._json({"traces": list(app.runs.values())[-20:]})
            else:
                self._static(path)

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            try:
                payload = self._body()
                if path == "/api/run":
                    self._json(app.run(payload))
                elif path == "/api/agent-run":
                    self._json(app.run_agent(payload))
                elif path == "/api/evaluate":
                    self._json(app.evaluate(payload))
                else:
                    self._json({"error": "route not found"}, HTTPStatus.NOT_FOUND)
            except (ValueError, KeyError) as exc:
                self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:  # pragma: no cover - defensive server boundary
                self._json({"error": f"internal error: {exc}"}, HTTPStatus.INTERNAL_SERVER_ERROR)

        def log_message(self, fmt: str, *args) -> None:
            print(f"[AgentGuard] {self.address_string()} - {fmt % args}")

        def _body(self) -> Dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 1_000_000:
                raise ValueError("request body too large")
            raw = self.rfile.read(length) if length else b"{}"
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError("JSON body must be an object")
            return value

        def _json(self, value: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
            body = json.dumps(value, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(status.value)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _static(self, path: str) -> None:
            relative = "index.html" if path in {"", "/"} else path.lstrip("/")
            if ".." in Path(relative).parts:
                self._json({"error": "invalid path"}, HTTPStatus.BAD_REQUEST)
                return
            try:
                static_root = resources.files("agentguard").joinpath("static")
                target = static_root.joinpath(relative)
                data = target.read_bytes()
            except (FileNotFoundError, IsADirectoryError):
                if "." not in Path(relative).name:
                    try:
                        data = resources.files("agentguard").joinpath("static/index.html").read_bytes()
                        relative = "index.html"
                    except FileNotFoundError:
                        self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                        return
                else:
                    self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                    return
            mime = mimetypes.guess_type(relative)[0] or "application/octet-stream"
            self.send_response(HTTPStatus.OK.value)
            self.send_header("Content-Type", f"{mime}; charset=utf-8" if mime.startswith("text/") else mime)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8080, benchmark_path: Optional[Path] = None) -> None:
    benchmark_path = benchmark_path or default_benchmark_path()
    app = Application(benchmark_path=benchmark_path)
    server = ThreadingHTTPServer((host, port), make_handler(app))
    print(f"AgentGuard dashboard: http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
