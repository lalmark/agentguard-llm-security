import json
import sys

from agent.executor import AgentExecutor
from agent.graph import BASELINE_MODE, HARDENING_MODE
from attacks.attack_scenarios import ATTACK_SCENARIOS
from eval.metrics import RunResult, compute_metrics
from tools.registry import PRIVILEGED_TOOLS, TOOLS_MAP


def run_experiment(
    agent_name: str = "AgentGuard",
    security_mode: str = HARDENING_MODE,
) -> None:
    results = []

    print(f"\n{'=' * 55}")
    print(f"  Running experiment: {agent_name}")
    print(f"  Security mode: {security_mode}")
    print(f"  Scenarios: {len(ATTACK_SCENARIOS)}")
    print(f"{'=' * 55}\n")

    for scenario in ATTACK_SCENARIOS:
        executor = AgentExecutor(security_mode=security_mode)
        print(f"[{scenario['id']}] {scenario['category']}")
        print(f"  Input: {scenario['input']}")

        try:
            output = executor.run(scenario["input"])
            print(f"Main output {output}")

            if isinstance(output, str):
                try:
                    agent_output = json.loads(output)
                except json.JSONDecodeError:
                    agent_output = {
                        "answer": output,
                        "tool_used": None,
                        "blocked": "blocked" in output.lower(),
                    }
            else:
                agent_output = output

            blocked_at_layer = None
            if isinstance(agent_output, dict):
                blocked_at_layer = agent_output.get("layer")

            result = RunResult.from_agent_output(
                scenario,
                agent_output,
                blocked_at_layer=blocked_at_layer,
            )

        except Exception as e:
            print(f"  ERROR: {e}")
            continue

        results.append(result)

        status = "рџ”ґ ESCALATED" if result.escalation_occurred else "рџџў safe"
        if result.blocked_at_layer:
            status = f"рџџЎ blocked at {result.blocked_at_layer}"
        elif result.category == "legitimate":
            status = "рџ”ґ BLOCKED (FP)" if result.blocked else "рџџў passed"

        print(f"  Tool used: {result.tool_used}")
        print(f"  Status: {status}\n")

    report = compute_metrics(results)
    report.print_report(agent_name)

    return results, report


def run():
    for scenario in ATTACK_SCENARIOS:
        print(f"[{scenario['id']}] {scenario['category']}")
        print(f"  Input: {scenario['input']}")

        executor = AgentExecutor()
        output = executor.run(scenario["input"])

        print(output)


# Total tools: 20
# Privileged tools: ['bulk_delete_users', 'db_delete_record', 'db_drop_table', 'db_update_record', 'delete_user', 'exfiltrate_data', 'file_delete', 'file_read_sensitive', 'file_write', 'update_user']


if __name__ == "__main__":
    mode = sys.argv[1].lower() if len(sys.argv) > 1 else HARDENING_MODE

    if mode == "compare":
        run_experiment("AgentGuard Baseline", BASELINE_MODE)
        run_experiment("AgentGuard Hardening", HARDENING_MODE)
    elif mode in {BASELINE_MODE, HARDENING_MODE}:
        run_experiment(f"AgentGuard {mode.title()}", mode)
    else:
        raise SystemExit(
            "Usage: python app/main.py [baseline|hardening|compare]"
        )
