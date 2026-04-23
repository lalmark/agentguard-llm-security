from typing import TypedDict, List, Dict, Any, Optional
from langchain_core.messages import BaseMessage


class AgentState(TypedDict, total=False):
    messages: List[BaseMessage]

    next: str

    plan: Optional[str]

    selected_tool: Optional[str]
    tool_input: Optional[Dict[str, Any]]
    tool_result: Optional[Any]

    is_safe: bool
    security_flags: List[str]

    final_answer: Optional[str]

    chat_history: List[Any]


# llm-agent-security/
# │
# ├── app/
# │   ├── main.py                     # entrypoint API
# │   ├── config.py                  # настройки (env, keys)
# │
# │   ├── api/
# │   │   ├── routes.py              # FastAPI endpoints
# │   │   ├── schemas.py             # request/response models
# │
# │   ├── agent/
# │   │   ├── graph.py               # LangGraph definition
# │   │   ├── state.py               # state schema (typed)
# │   │   ├── nodes/
# │   │   │   ├── router.py
# │   │   │   ├── planner.py
# │   │   │   ├── executor.py
# │   │   │   ├── tool_selector.py
# │   │   │   ├── verifier.py
# │   │   │   ├── memory.py
# │
# │   ├── security/
# │   │   ├── prompt_injection_detector.py
# │   │   ├── policy_engine.py       # RBAC/ABAC logic
# │   │   ├── input_sanitizer.py
# │   │   ├── output_filter.py
# │   │   ├── tool_guard.py         # защита инструментов
# │
# │   ├── tools/
# │   │   ├── registry.py            # список разрешённых tools
# │   │   ├── db_tool.py
# │   │   ├── http_tool.py
# │   │   ├── file_tool.py
# │   │   ├── restricted_tools.py   # опасные инструменты (ограниченные)
# │
# │   ├── memory/
# │   │   ├── vector_store.py
# │   │   ├── conversation_memory.py
# │
# │   ├── observability/
# │   │   ├── logger.py
# │   │   ├── tracing.py
# │   │   ├── metrics.py
# │
# │   ├── tests/
# │   │   ├── injection_attacks/
# │   │   ├── unit/
# │   │   ├── integration/
# │
# ├── experiments/
# │   ├── attack_scenarios/
# │   ├── benchmarks/
# │   ├── evaluation.py
# │
# ├── docs/
# │   ├── architecture.md
# │   ├── threat_model.md
# │   ├── evaluation_report.md
# │
# ├── docker/
# ├── requirements.txt
# ├── README.md