import requests
from pathlib import Path
from typing import Dict, Any


class Llama2Wrapper:
    def __init__(
        self,
        model: str = "llama2",
        host: str = "http://localhost:11434"
    ):
        self.model = model
        self.host = host

        self.base_path = Path(__file__).parent / "prompts"

    # =========================
    # 📄 load prompt
    # =========================
    def _load_prompt(self, filename: str) -> str:
        path = self.base_path / filename
        return path.read_text(encoding="utf-8")

    # =========================
    # 🧠 base generation
    # =========================
    def _generate(self, system_prompt: str, user_input: str) -> str:
        prompt = f"[INST] <<SYS>>\n{system_prompt}\n<</SYS>>\n{user_input}\n[/INST]"

        response = requests.post(
            f"{self.host}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False
            }
        )

        return response.json().get("response", "").strip()

    # =========================
    # 🧭 router (decision making)
    # =========================
    def route(self, user_input: str) -> str:
        system = self._load_prompt("router_prompt.txt")
        result = self._generate(system, user_input)
        return result.lower().strip()

    # =========================
    # 🧠 planner (reasoning)
    # =========================
    def plan(self, user_input: str) -> str:
        system = self._load_prompt("system_prompt.txt")
        return self._generate(system, user_input)

    # =========================
    # 🛡 security classifier
    # =========================
    def security_check(self, user_input: str) -> Dict[str, Any]:
        system = self._load_prompt("security_prompt.txt")
        result = self._generate(system, user_input).lower()

        return {
            "raw": result,
            "is_safe": "safe" in result or "yes" in result
        }

    # =========================
    # 💬 general call (fallback)
    # =========================
    def call(self, user_input: str) -> str:
        system = self._load_prompt("system_prompt.txt")
        return self._generate(system, user_input)