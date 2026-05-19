from app.llm.model import Llama2Wrapper
from app.tools.registry import TOOLS_MAP
import json
llm = Llama2Wrapper()

def _resolve_params(params: dict, step_results: list) -> dict:
    """Подставляет $prev_result.field из результатов предыдущих шагов."""
    resolved = {}
    for key, value in params.items():
        if isinstance(value, str) and value.startswith("$prev_result."):
            field = value.removeprefix("$prev_result.")
            # Берём последний результат
            if step_results:
                last = step_results[-1]
                resolved[key] = str(last.get(field, value)) if isinstance(last, dict) else value
            else:
                resolved[key] = value
        else:
            resolved[key] = value
    return resolved

def tool_selector_node(state):

    plan = state.get("plan")
    current_step = state.get("current_step", 0)

    tool_name = None

    steps = plan.get("steps", []) if isinstance(plan, dict) else plan
    if steps and current_step < len(steps):
        step = steps[current_step]
        tool_name = step.get("tool", "NONE")
        params = step.get("params", {})

        params = _resolve_params(params, state.get("step_results", []))

        total = len(steps)
        print(f"\n\nTool Selector [шаг {current_step + 1}/{total}]")
        print("Tool  ", tool_name)
        print("Params", params)

    if tool_name in TOOLS_MAP:
        state['selected_tool'] = tool_name
        state['tool_input'] = params
    else:
        state["selected_tool"] = None

    return state
