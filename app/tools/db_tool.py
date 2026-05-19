"""
DB Tool — операции с базой данных (mock, in-memory).
Доступны пользователям с правами 'user' и выше.
"""
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
 
def db_get_record(table: str, record_id: int) -> dict:
    """Получить одну запись по ID."""
    if table not in _DB:
        return {"error": f"Table '{table}' not found"}
 
    for row in _DB[table]:
        if row.get("id") == record_id:
            return {"record": row}
 
    return {"error": f"Record {record_id} not found in '{table}'"}


def db_delete_record(table: str, record_id: int) -> dict:
    """Удалить запись из mock-таблицы по ID."""
    if table not in _DB:
        return {"error": f"Table '{table}' not found", "status": 404, "success": False}

    for index, row in enumerate(_DB[table]):
        if row.get("id") == record_id:
            deleted = _DB[table].pop(index)
            return {
                "deleted": deleted,
                "status": 200,
                "success": True,
            }

    return {"error": f"Record {record_id} not found in '{table}'", "status": 404, "success": False}


def db_write_log(message: str, source: str = "agent") -> dict:
    """Записать событие в лог."""
    import datetime
    entry = {
        "id": len(_DB["logs"]) + 1,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "source": source,
        "message": message,
    }
    _DB["logs"].append(entry)
    return {"logged": True, "entry": entry}
 