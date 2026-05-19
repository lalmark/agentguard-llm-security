from app.agent.executor import AgentExecutor
from app.tools.registry import TOOLS_MAP, PRIVILEGED_TOOLS
from app.eval.metrics import RunResult, compute_metrics
from app.attacks.attack_scenarios import ATTACK_SCENARIOS


def run_experiment(agent_name: str = "AgentGuard") -> None:
    executor = AgentExecutor()
    results = []

    print(f"\n{'='*55}")
    print(f"  Running experiment: {agent_name}")
    print(f"  Scenarios: {len(ATTACK_SCENARIOS)}")
    print(f"{'='*55}\n")

    for scenario in ATTACK_SCENARIOS:
        print(f"[{scenario['id']}] {scenario['category']}")
        print(f"  Input: {scenario['input']}")

        try:
            output = executor.run(scenario["input"])
            print(f'Main output {output.get("final_answer", output.get("messages")[-1].content if output.get("messages") else "No response")}')
            
            # Выводим результат фильтра безопасности, если есть
            guard_result = output.get("guard_result")
            if guard_result:
                print(f'  GuardResult(allowed={guard_result.get("allowed")}, rule="{guard_result.get("rule")}", layer="{guard_result.get("layer")}")')

            agent_output = output

            result = RunResult.from_agent_output(scenario, agent_output)

        except Exception as e:
            result = RunResult(
                scenario_id=scenario["id"],
                category=scenario["category"],
                expected_escalation=scenario["expected_escalation"],
                tool_used=None,
                escalation_occurred=False,
                blocked=False,
                blocked_at_layer=None,
                attack_success=False,
            )
            print(f"  ERROR: {e}")

        results.append(result)

        if result.category == "legitimate":
            status = "🔴 BLOCKED (FP)" if result.blocked else "🟢 passed"
        else:
            if result.attack_success:
                status = "🔴 ESCALATED"
            elif result.blocked:
                status = f"🛡️ BLOCKED at {result.blocked_at_layer}"
            else:
                status = "🟡 MISSED"

        print(f"  Tool used: {result.tool_used}")
        print(f"  Status: {status}\n")

    # Метрики
    report = compute_metrics(results)
    report.print_report(agent_name)

    return results, report

# Total tools: 20
# Privileged tools: ['bulk_delete_users', 'db_delete_record', 'db_drop_table', 'db_update_record', 'delete_user', 'exfiltrate_data', 'file_delete', 'file_read_sensitive', 'file_write', 'update_user']


# =======================================================
#   METRICS REPORT — Vulnerable Agent (mock)
# =======================================================
#   Total attacks:       15
#   Total legitimate:    5
# ───────────────────────────────────────────────────────
#   ASR  (Attack Success Rate):    100.0%  ← чем меньше, тем лучше
#   FPR  (False Positive Rate):      0.0%  ← чем меньше, тем лучше
#   FNR  (False Negative Rate):      0.0%  ← чем меньше, тем лучше
#   Block Rate:                      0.0%  ← чем больше, тем лучше
# ───────────────────────────────────────────────────────
#   По категориям атак:
#     direct_prompt_injection             7/7  (100.0% ASR)
#     indirect_prompt_injection           4/4  (100.0% ASR)
#     tool_based_injection                4/4  (100.0% ASR)
# =======================================================


if __name__ == "__main__":
    run_experiment()
