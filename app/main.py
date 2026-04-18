from app.graph.graph import build_graph

app = build_graph()


def main():
    """Interactive CLI mode for communicating with the agent."""
    print("\n" + "=" * 60)
    print("SecurityAIAgent - Interactive Mode")
    print("=" * 60)
    print("Type your question (or 'exit' to quit)")
    print("Mock tool command: /exec ACTION (example: /exec DELETE_SYSTEM_LOGS)")
    print("Set mode: /mode baseline | /mode protected")
    print("Set privilege: /priv user | /priv admin | /priv root")
    print("=" * 60 + "\n")

    mode = "protected"
    current_privilege = "user"

    while True:
        try:
            question = input("Question: ").strip()

            if question.lower() in ["выход", "exit", "quit", "q"]:
                print("\nBye!\n")
                break

            if not question:
                print("Please enter a question.\n")
                continue

            if question.lower().startswith("/mode "):
                candidate = question.split(" ", 1)[1].strip().lower()
                if candidate in {"baseline", "protected"}:
                    mode = candidate
                    print(f"Mode set: {mode}\n")
                else:
                    print("Available: /mode baseline or /mode protected\n")
                continue

            if question.lower().startswith("/priv "):
                candidate = question.split(" ", 1)[1].strip().lower()
                if candidate in {"user", "admin", "root"}:
                    current_privilege = candidate
                    print(f"Privilege set: {current_privilege}\n")
                else:
                    print("Available: /priv user | /priv admin | /priv root\n")
                continue

            print("\nProcessing...\n")

            result = app.invoke(
                {
                    "question": question,
                    "documents": [],
                    "answer": "",
                    "current_privilege": current_privilege,
                    "mode": mode,
                    "tool_result": {},
                }
            )

            answer = result.get("answer", "No answer")
            print("-" * 60)
            print("ANSWER:")
            print(answer)
            llm_answer = result.get("llm_answer")
            if llm_answer:
                print("\nLLM ANSWER:")
                print(llm_answer)

            tool_result = result.get("tool_result", {})
            if tool_result:
                print("\nMOCK TOOL RESULT:")
                print(f"action: {tool_result.get('action')}")
                print(f"required_privilege: {tool_result.get('required_privilege')}")
                print(f"decision: {tool_result.get('decision')}")
                print(f"reason: {tool_result.get('reason')}")

            execution_result = result.get("execution_result", {})
            if execution_result:
                print("\nEXECUTION RESULT:")
                print(f"status: {execution_result.get('status')}")
                print(f"action: {execution_result.get('action')}")
                print(f"details: {execution_result.get('details')}")
                if execution_result.get("target"):
                    print(f"target: {execution_result.get('target')}")
                if execution_result.get("deleted_count") is not None:
                    print(f"deleted_count: {execution_result.get('deleted_count')}")
                if execution_result.get("preview"):
                    print(f"preview: {execution_result.get('preview')}")
                files = execution_result.get("files", [])
                if files:
                    print("files:")
                    for path in files:
                        print(f"- {path}")
                deleted_files = execution_result.get("deleted_files", [])
                if deleted_files:
                    print("deleted_files:")
                    for path in deleted_files:
                        print(f"- {path}")

            audit_record = result.get("audit_record", {})
            if audit_record:
                print("\nAUDIT:")
                print(f"time_utc: {audit_record.get('timestamp_utc')}")
                print(f"intent: {audit_record.get('intent')}")
                print(f"risk: {audit_record.get('risk_level')} ({audit_record.get('risk_score')})")
                print(f"log_path: {audit_record.get('audit_log_path')}")
            print("-" * 60 + "\n")

        except KeyboardInterrupt:
            print("\n\nInterrupted by user. Bye!\n")
            break
        except Exception as e:
            print(f"\nError: {e}\n")
            continue


if __name__ == "__main__":
    main()
