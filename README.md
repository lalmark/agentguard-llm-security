# 🔒 SecurityAIAgent

Интеллектуальный AI-агент для обработки вопросов безопасности с использованием современного pipeline'а LangChain и LangGraph.

## 🌟 Возможности

- **RAG (Retrieval-Augmented Generation)** - поиск и обработка релевантных документов
- **Агентский граф** - сложные цепочки рассуждений и взаимодействий
- **Интеграция с Ollama** - использование локальных LLM моделей
- **Модульная архитектура** - легко расширяемая система

## 📋 Требования

- Python 3.8+
- Ollama (установленная и запущенная)

## 🚀 Быстрый старт

### 1️⃣ Клонирование и подготовка окружения

```bash
python3 -m venv venv
source venv/bin/activate  # Для Windows: venv\Scripts\activate
```

### 2️⃣ Установка зависимостей

```bash
pip3 install -r requirements.txt
```

### 3️⃣ Конфигурация

Создайте файл `.env` в корневой директории:

```env
MODEL_NAME=llama2
```

### 4️⃣ Запуск

```bash
python3 -m app.main
```

## 📁 Структура проекта

```
SecurityAIAgent/
├── app/
│   ├── main.py              # Точка входа приложения
│   ├── config/
│   │   └── settings.py      # Конфигурация приложения
│   ├── graph/
│   │   ├── graph.py         # Построение графа агента
│   │   ├── state.py         # Состояние и схема данных
│   │   └── nodes/
│   │       ├── agent.py     # Логика агента
│   │       └── rag.py       # Логика RAG
│   ├── llm/
│   │   └── model.py         # Интеграция с моделями
│   └── prompts/
│       ├── agent_prompt.py  # Промпты для агента
│       └── messages.py      # Управление сообщениями
└── requirements.txt         # Зависимости проекта
```

## 📦 Зависимости

- **langchain** - фреймворк для работы с LLM
- **langchain-ollama** - интеграция с Ollama
- **langgraph** - граф-ориентированное программирование
- **python-dotenv** - управление переменными окружения

## 🔧 Использование

```python
from app.graph.graph import build_graph

# Инициализируем граф
app = build_graph()

# Запускаем агента с вопросом
result = app.invoke({
    "question": "Ваш вопрос",
    "documents": [],
    "answer": ""
})

print(result["answer"])
```

## 🤝 Контрибьютинг

Приветствуются pull requests и предложения по улучшению проекта!

## 📝 Лицензия

Проект лицензирован под MIT License

---

**Создано с ❤️ для безопасности информационных систем**

