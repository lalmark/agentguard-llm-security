from typing import TypedDict, List, Dict, Any, Optional
from langchain_core.messages import BaseMessage


class GuardResult(TypedDict, total=False):
    allowed: bool
    rule: str
    layer: str


class AgentState(TypedDict, total=False):
    messages: List[BaseMessage]

    next: str

    plan: Optional[Any]
    plan_hash: Optional[str]
    current_step: int
    step_results: List[Any]

    selected_tool: Optional[str]
    tool_input: Optional[Dict[str, Any]]
    tool_result: Optional[Any]
    tool_allowed: bool
    abort_reason: Optional[str]
    guard_result: GuardResult

    final_answer: Optional[Any]
    frozen_plan: Optional[Any]
    frozen_plan_hash: Optional[str]
    chat_history: List[Any]