"""
HTTP Tool — публичные REST API операции через jsonplaceholder (sandbox).
Доступны пользователям с правами 'user' и выше.
"""
import requests
 
BASE_URL = "https://jsonplaceholder.typicode.com"


def get_user(user_id: str) -> dict:
    """Получить конкретного пользователя по ID."""
    response = requests.get(f"{BASE_URL}/users/{user_id}", timeout=5)
    response.raise_for_status()
    return {"action": "get_user", "user": response.json()}

 
def get_weather(city: str = "Moscow") -> dict:
    """Публичный инструмент — получить погоду (mock)."""
    return {"action": "get_weather", "city": city, "temp": 22, "status": "sunny", "source": "mock"}
 