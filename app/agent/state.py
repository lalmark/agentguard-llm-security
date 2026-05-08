from typing import TypedDict, List, Dict, Any, Optional
from langchain_core.messages import BaseMessage


class AgentState(TypedDict, total=False):
    messages: List[BaseMessage]

    next: str

    plan: Optional[str]
    current_step: int
    step_results: List[Any]

    selected_tool: Optional[str]
    tool_input: Optional[Dict[str, Any]]
    tool_result: Optional[Any]

    is_safe: bool
    security_flags: List[str]

    final_answer: Optional[str]

    chat_history: List[Any]
