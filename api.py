from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
import uvicorn
import os

app = FastAPI(title="Sentinel IPS Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Use absolute path if necessary, but since you are in the folder:
DB_PATH = os.getenv("DB_PATH") if os.getenv("DB_PATH") else "sentinel_hits.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row 
    return conn

@app.get("/stats")
def get_stats():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # TABLE NAME CHANGED TO 'bans'
        cursor.execute("SELECT COUNT(*) as total FROM bans")
        total_hits = cursor.fetchone()["total"]
        
        cursor.execute("SELECT COUNT(DISTINCT ip) as unique_ips FROM bans")
        unique_ips = cursor.fetchone()["unique_ips"]
        
        conn.close()
        return {
            "total_incidents": total_hits,
            "unique_attackers": unique_ips
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/latest-hits")
def get_latest_hits(limit: int = 10):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # TABLE NAME CHANGED TO 'bans'
        # Adjusting column names based on your SELECT * output
        query = "SELECT ip, timestamp, reason FROM bans ORDER BY timestamp DESC LIMIT ?"
        cursor.execute(query, (limit,))
        hits = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        return hits
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=4446)