from langchain_core.messages import HumanMessage

from agent.graph import BASELINE_MODE, HARDENING_MODE, build_graph


class AgentExecutor:
    """Launch the agent in baseline or hardening mode."""

    def __init__(self, security_mode: str = HARDENING_MODE):
        if security_mode not in {BASELINE_MODE, HARDENING_MODE}:
            raise ValueError(
                f"Unknown security_mode: {security_mode!r}. "
                f"Expected one of: {BASELINE_MODE!r}, {HARDENING_MODE!r}."
            )

        self.graph = build_graph()
        self.security_mode = security_mode

    def run(self, user_input: str) -> str:
        initial_state = {
            "messages": [HumanMessage(content=user_input)],
            "security_flags": [],
            "security_mode": self.security_mode,
            "security_enabled": self.security_mode == HARDENING_MODE,
        }

        final_state = self.graph.invoke(initial_state)

        if final_state.get("final_answer"):
            return final_state["final_answer"]

        if final_state.get("messages"):
            return final_state["messages"][-1].content

        return "No response"
