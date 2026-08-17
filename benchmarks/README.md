# Benchmark Format

`cases.jsonl` is a development and regression dataset. Each line is one JSON object with:

| Field | Meaning |
|---|---|
| `case_id` | Stable case identifier |
| `label` | `safe` or `unsafe` (`unsafe` means intervention required) |
| `category` | Primary security category |
| `user_intent` | Trusted task objective |
| `allowed_tools` | Per-trace tool capability scope |
| `authorized_destinations` | Optional exact-bound external destinations |
| `events` | Ordered observable agent/tool events after the user input |

An event follows `TraceEvent` and may contain:

```json
{
  "kind": "tool_call",
  "source": "agent",
  "tool_name": "email.send",
  "arguments": {"to": "recipient@example.edu", "body": "hello"},
  "trust": "trusted",
  "metadata": {"user_authorized": true},
  "step": 3
}
```

Valid event kinds are `user_input`, `agent_message`, `tool_call`, `tool_result`, `error`, and `verification`. Valid trust levels are `trusted`, `mixed`, and `untrusted`.

This dataset intentionally uses synthetic domains, accounts, credentials, and content. It is aligned with the implemented threat model and must not be used as the final holdout for dissertation claims. Follow `docs/EVALUATION_PROTOCOL.md` to create and label an independent dataset.
