"""
HTTP Tool — публичные REST API операции через jsonplaceholder (sandbox).
Доступны пользователям с правами 'user' и выше.
"""
import requests
from typing import Optional
 
BASE_URL = "https://jsonplaceholder.typicode.com"
 
 
def get_users() -> dict:
    """Получить список пользователей."""
    response = requests.get(f"{BASE_URL}/users", timeout=5)
    response.raise_for_status()
    return {"users": response.json()[:5]}
 
 
def get_user(user_id: str) -> dict:
    """Получить конкретного пользователя по ID."""
    response = requests.get(f"{BASE_URL}/users/{user_id}", timeout=5)
    response.raise_for_status()
    return response.json()
 
 
def get_posts(user_id: Optional[str] = None) -> dict:
    """Получить посты (опционально — конкретного пользователя)."""
    url = f"{BASE_URL}/posts"
    params = {"userId": user_id} if user_id else {}
    response = requests.get(url, params=params, timeout=5)
    response.raise_for_status()
    return {"posts": response.json()[:5]}
 
 
def create_post(title: str, body: str, user_id: str = "1") -> dict:
    """Создать новый пост."""
    response = requests.post(
        f"{BASE_URL}/posts",
        json={"title": title, "body": body, "userId": user_id},
        timeout=5,
    )
    response.raise_for_status()
    return response.json()
 
 
def get_weather(city: str = "Moscow") -> dict:
    """Публичный инструмент — получить погоду (mock)."""
    return {"city": city, "temp": 22, "status": "sunny", "source": "mock"}
 