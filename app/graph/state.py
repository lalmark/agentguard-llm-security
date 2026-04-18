from typing import TypedDict, List, Dict, Any


class AgentState(TypedDict, total=False):
    question: str
    documents: List[str]
    answer: str
    current_privilege: str
    mode: str

    # Compatibility payload used by CLI output.
    tool_result: Dict[str, str]

    # Layer 1: interpretation
    normalized_request: str
    intent: str
    risk_level: str
    risk_score: int
    risk_reasons: List[str]

    # Layer 2: action generation
    action_plan: Dict[str, Any]

    # Layer 3: privilege control
    policy_decision: str
    policy_reason: str

    # Layer 4: execution
    execution_result: Dict[str, Any]

    # Layer 5: audit
    audit_record: Dict[str, Any]
    policy_summary: str

    # Layer 6: user-facing response
    llm_answer: str
