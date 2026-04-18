import os
from dotenv import load_dotenv

load_dotenv()

# Read model name from .env, default to 'llama2'
MODEL_NAME = os.getenv('MODEL_NAME', 'llama2')


def _prompt_to_text(prompt) -> str:
	"""Normalize different prompt formats to plain text."""
	try:
		if isinstance(prompt, (list, tuple)):
			return "\n".join(
				[m.get("content", "") if isinstance(m, dict) else str(m) for m in prompt]
			)
		if isinstance(prompt, dict):
			return prompt.get("input", "")
		return str(prompt)
	except Exception:
		return str(prompt)


class MockLLM:
	def invoke(self, prompt):
		text = _prompt_to_text(prompt).lower()
		if any(tok in text for tok in ["rm -rf", "sudo", "chmod 777", "kill -9"]):
			return "⚠️ MOCK RESPONSE: Обнаружена опасная команда. Выполнение заблокировано."
		return "✅ MOCK RESPONSE: LLM недоступен — это безопасный ответ-фолбэк."


# Try to import and wrap real Ollama client; on any failure use MockLLM.
try:
	from langchain_ollama.llms import OllamaLLM
	from app.config import settings

	class SafeLLM:
		def __init__(self, inner):
			self._inner = inner

		def invoke(self, prompt):
			try:
				# Prefer the underlying LLM's invoke/generate
				return self._inner.invoke(prompt)
			except Exception:
				# On runtime failure (e.g. Ollama server not reachable) fall back
				return MockLLM().invoke(prompt)

	try:
		real_llm = OllamaLLM(model=settings.MODEL_NAME)
		llm_model = SafeLLM(real_llm)
	except Exception:
		llm_model = MockLLM()

except Exception:
	llm_model = MockLLM()