import os
import sqlite3
from datetime import datetime

# DB 파일 경로를 프로젝트 루트 디렉터리로 설정합니다.
DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "history.db"
)

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """데이터베이스 및 테이블이 존재하지 않는 경우 초기화합니다."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            scan_time TEXT NOT NULL,
            cwe TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            vulnerable INTEGER NOT NULL,
            details TEXT
        )
    """)
    conn.commit()
    conn.close()

def add_history(filename: str, cwe: str, risk_score: int, vulnerable: bool, details: str):
    """코드 스캔 이력을 기록합니다."""
    # DB 초기화 보장
    init_db()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO scan_history (filename, scan_time, cwe, risk_score, vulnerable, details)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (filename, now_str, cwe, risk_score, 1 if vulnerable else 0, details))
    conn.commit()
    conn.close()

def get_history():
    """모든 스캔 이력을 시간 역순으로 조회합니다."""
    init_db()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, filename, scan_time, cwe, risk_score, vulnerable, details FROM scan_history ORDER BY id DESC")
    rows = cursor.fetchall()
    
    history_list = []
    for row in rows:
        history_list.append({
            "id": row["id"],
            "filename": row["filename"],
            "scan_time": row["scan_time"],
            "cwe": row["cwe"],
            "risk_score": row["risk_score"],
            "vulnerable": bool(row["vulnerable"]),
            "details": row["details"]
        })
    conn.close()
    return history_list

def delete_history(record_id: int):
    """특정 이력 로그를 삭제합니다."""
    init_db()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scan_history WHERE id = ?", (record_id,))
    conn.commit()
    conn.close()

def clear_all_history():
    """전체 이력 로그를 비웁니다."""
    init_db()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scan_history")
    conn.commit()
    conn.close()
