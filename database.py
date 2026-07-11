import sqlite3
from datetime import datetime

DB_NAME = "proofpixel.db"


def create_database():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS url_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        prediction TEXT NOT NULL,
        checked_time TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()


def save_url(url, prediction):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO url_history(url, prediction, checked_time)
    VALUES (?, ?, ?)
    """, (url, prediction, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    conn.commit()
    conn.close()