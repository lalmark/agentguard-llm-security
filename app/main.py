from agent.executor import AgentExecutor


if __name__ == "__main__":
    executor = AgentExecutor()
    print("Agent ready. Type 'exit' to quit.")

    while True:
        user_input = input("You: ")
        if user_input.lower() in ["exit", "quit"]:
            break

        response = executor.run(user_input)
        print(f"Agent: {response}")
