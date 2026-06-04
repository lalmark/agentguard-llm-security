from typing import Any, Dict, List, Optional, TypedDict

from langchain_core.messages import BaseMessage


class AgentState(TypedDict, total=False):
    messages: List[BaseMessage]
    user_input: str
    security_mode: str
    security_enabled: bool

    next: str

    plan: List[Dict[str, Any]]
    current_step: int
    step_decision: str
    step_results: List[Any]
    executed_steps: List[Dict[str, Any]]

    selected_tool: Optional[str]
    tool_input: Dict[str, Any]
    tool_result: Optional[Any]

    is_safe: bool
    security_flags: List[str]
    security_blocked: bool
    blocked_by: str
    blocked_reason: str
    judge_result: Dict[str, Any]

    final_answer: Optional[str]

    chat_history: List[Any]
