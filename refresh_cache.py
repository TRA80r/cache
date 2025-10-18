import sqlite3
import json
import time
import jwt
from helper import create_jwt_token

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


def get_jwt_token(uid: int, password: str) -> str:
    """
    Return a cached JWT token if it's valid, otherwise create and cache a new one.
    Retries up to 5 times if token creation fails.
    """
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Try to get token from cache
    c.execute("SELECT token FROM jwt_cache WHERE uid = ?", (uid,))
    row = c.fetchone()

    if row:
        token = row[0]
        try:
            # Decode without verifying signature, just to check expiration
            payload = jwt.decode(token, options={"verify_signature": False})
            exp = payload.get("exp", 0)
            if exp > int(time.time()):
                conn.close()
                return token
            else:
                print(f"[CACHE] Token expired for UID {uid}")
        except jwt.DecodeError:
            print(f"[CACHE] Invalid token found for UID {uid}")

    # Retry creating new token up to 5 times
    token = None
    for attempt in range(1, 6):
        try:
            token = create_jwt_token(uid, password)
            if token:
                break
        except Exception as e:
            print(f"[RETRY {attempt}/5] Failed to create JWT token for UID {uid}: {e}")
        time.sleep(1)

    if not token:
        conn.close()
        return None
        raise RuntimeError(f"Failed to create JWT token for UID {uid} after 5 attempts")

    # Cache it
    c.execute("""
        INSERT OR REPLACE INTO jwt_cache (uid, token, created_at)
        VALUES (?, ?, ?)
    """, (uid, token, int(time.time())))
    conn.commit()
    conn.close()

    return token


def main():
    from tqdm import tqdm
    conn = sqlite3.connect('accounts.db')
    cursor = conn.cursor()
    cursor.execute('select * from accounts')
    data = cursor.fetchall()
    for uid,password in tqdm(data):
        get_jwt_token(uid,password)

    conn = sqlite3.connect("cache.db")
    cursor = conn.cursor()
    cursor.execute("SELECT token FROM jwt_cache")
    with open('cache.json',"w") as w:
        json.dump([i[0] for i in cursor.fetchall()],w)


if __name__ == '__main__':
    main()
