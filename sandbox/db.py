_DB: dict[str, list] = {
    "users": [
        {"id": 1, "name": "Alice", "role": "admin", "email": "alice@corp.com"},
        {"id": 2, "name": "Bob",   "role": "user",  "email": "bob@corp.com"},
        {"id": 3, "name": "Carol", "role": "user",  "email": "carol@corp.com"},
    ],
    "documents": [
        {"id": 1, "title": "Q4 Report",     "owner_id": 1, "content": "Confidential financial data..."},
        {"id": 2, "title": "Roadmap 2025",  "owner_id": 1, "content": "Internal roadmap..."},
        {"id": 3, "title": "Public FAQ",    "owner_id": 2, "content": "Frequently asked questions"},
    ],
    "logs": [],
}
