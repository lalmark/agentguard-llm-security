import uuid
from langchain_core.messages import HumanMessage
from agent.graph import build_graph


class AgentExecutor:
    """Класс, который запускает агента с возможностью управления сессиями."""

    def __init__(self):
        self.graph = build_graph()
        self.thread_id = self._new_thread()

    def _new_thread(self):
        return str(uuid.uuid4())
    
    def run(self, user_input: str) -> str:
        # 🛡 1. INPUT SECURITY CHECK
        # security_result = detect_injection(user_input)

        # if not security_result["is_safe"]:
        #     return "Request blocked by security policy."

        # 🧠 2. INIT STATE
        initial_state = {
            "messages": [
                HumanMessage(content=user_input)
            ],
            "security_flags": []
        }

        config = {
            "configurable": {
                "thread_id": self.thread_id
            }
        }

        # ⚙️ 3. EXECUTE GRAPH
        final_state = self.graph.invoke(initial_state, config=config)

        # 📦 4. GET OUTPUT
        if final_state.get("final_answer"):
            return final_state["final_answer"]

        if final_state.get("messages"):
            return final_state["messages"][-1].content

        # 🛡 5. OUTPUT FILTER (VERY IMPORTANT FOR DIPLOMA)
        # safe_output = filter_output(raw_output)

        return "No response"