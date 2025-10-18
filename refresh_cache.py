import sqlite3
import json
import time
import jwt
from helper import create_jwt_token
from tqdm import tqdm

DB_PATH = "cache.db"


def init_db():
    """Initialize the SQLite cache table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS jwt_cache (
            uid INTEGER PRIMARY KEY,
            token TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def get_jwt_token(uid: int, password: str, force_refresh: bool = True) -> str:
    """
    Create and cache a new JWT token.
    If force_refresh=False, it will reuse a valid token if it exists.
    Retries up to 5 times if token creation fails.
    """
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Skip cache if force_refresh=True
    if not force_refresh:
        c.execute("SELECT token FROM jwt_cache WHERE uid = ?", (uid,))
        row = c.fetchone()
        if row:
            token = row[0]
            try:
                payload = jwt.decode(token, options={"verify_signature": False})
                exp = payload.get("exp", 0)
                if exp > int(time.time()):
                    conn.close()
                    return token
            except jwt.DecodeError:
                pass

    # Always recreate token if force_refresh=True
    token = None
    for attempt in range(1, 6):
        try:
            token = create_jwt_token(uid, password)
            if token:
                break
        except Exception as e:
            print(f"[RETRY {attempt}/5] Failed to create JWT for UID {uid}: {e}")
            time.sleep(1)

    if not token:
        conn.close()
        raise RuntimeError(f"Failed to create JWT token for UID {uid} after 5 attempts")

    # Cache new token
    c.execute("""
        INSERT OR REPLACE INTO jwt_cache (uid, token, created_at)
        VALUES (?, ?, ?)
    """, (uid, token, int(time.time())))
    conn.commit()
    conn.close()

    return token


def main():
    init_db()

    # Load accounts from accounts.db
    conn = sqlite3.connect('accounts.db')
    cursor = conn.cursor()
    cursor.execute('SELECT uid, password FROM accounts')
    data = cursor.fetchall()
    conn.close()

    # Force refresh cache
    for uid, password in tqdm(data, desc="Refreshing cache"):
        get_jwt_token(uid, password, force_refresh=True)

    # Export cache to JSON
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT token FROM jwt_cache")
    tokens = [row[0] for row in cursor.fetchall()]
    conn.close()

    with open('cache.json', "w") as w:
        json.dump(tokens, w, indent=2)

    print(f"[DONE] Exported {len(tokens)} tokens to cache.json")


if __name__ == '__main__':
    main()
