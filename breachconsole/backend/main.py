from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import os
import glob
import json
import asyncio
import logging
import datetime
import re
import sqlite3
import hashlib
from typing import List

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("BreachConsole")

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

import os
import glob

# Store connected clients
clients: List[WebSocket] = []
# Persistent history file (absolute path)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.path.join(BASE_DIR, "history.json")
DB_FILE = os.path.join(BASE_DIR, "events.db")
ARTIFACTS_DIR = os.path.join(os.path.dirname(os.path.dirname(BASE_DIR)), "artifacts")

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS events
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  event_type TEXT,
                  target TEXT,
                  payload TEXT,
                  timestamp TEXT,
                  fingerprint TEXT UNIQUE)''')
    conn.commit()
    conn.close()

def save_event_to_db(event):
    payload = event.get('payload', {})
    event_type = event.get('event', 'unknown')
    target = payload.get('target', payload.get('job_target', event.get('job', {}).get('target', 'unknown')))
    ts = event.get('ts', datetime.datetime.now(datetime.UTC).isoformat())
    
    # Create a unique fingerprint to avoid duplicates
    payload_str = json.dumps(payload, sort_keys=True)
    fingerprint = hashlib.md5(f"{ts}_{event_type}_{target}_{payload_str}".encode()).hexdigest()
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO events (event_type, target, payload, timestamp, fingerprint) VALUES (?, ?, ?, ?, ?)",
                  (event_type, target, payload_str, ts, fingerprint))
        conn.commit()
    except sqlite3.IntegrityError:
        pass # Duplicate
    finally:
        conn.close()

def get_recent_events(limit=10000):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT event_type, payload, timestamp FROM events ORDER BY timestamp ASC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    
    events = []
    for row in rows:
        try:
            events.append({
                "event": row[0],
                "payload": json.loads(row[1]),
                "ts": row[2]
            })
        except:
            continue
    return events

# Initialize database on module load
init_db()

# Store events for late joiners (last 10000 events)
event_history = []

def bootstrap_from_artifacts():
    """Scan artifacts folder and load events from both JSONL and Text logs."""
    global event_history
    found_events = []
    
    # Track the latest metrics for each target
    target_stats = {}
    
    # 1. Parse reconharvest.log (Text) for stage transitions
    log_pattern = os.path.join(ARTIFACTS_DIR, "**/recon/reconharvest.log")
    text_logs = glob.glob(log_pattern, recursive=True)
    
    for log_path in text_logs:
        try:
            rel_path = os.path.relpath(log_path, ARTIFACTS_DIR)
            target = rel_path.split(os.sep)[0]
            
            # Get file mod time as a fallback timestamp
            mod_time = os.path.getmtime(log_path)
            fallback_ts = datetime.datetime.fromtimestamp(mod_time, datetime.UTC).isoformat()
            
            with open(log_path, "r") as f:
                for line in f:
                    # Look for stage transitions: [*] Stage: name [STARTED/DONE]
                    match = re.search(r"\[\*\] Stage: ([a-z0-9_]+) \[(STARTED|DONE)\]", line)
                    if match:
                        stage = match.group(1)
                        status = match.group(2).lower()
                        
                        # Map internal stages to dashboard stages
                        mapped_stage = stage
                        if stage.startswith("discovery_"): mapped_stage = "discovery"
                        
                        event = {
                            "event": mapped_stage,
                            "payload": {
                                "msg": f"Stage {stage} {status}",
                                "status": "completed" if status == "done" else "started",
                                "target": target,
                                "stats": target_stats.get(target, {"subdomains": 0, "resolved": 0, "live_hosts": 0, "ports": 0})
                            },
                            "ts": fallback_ts
                        }
                        found_events.append(event)
        except Exception as e:
            logger.error(f"Error parsing text log {log_path}: {e}")

    # 2. Parse stage_status.jsonl (Structured) for metrics
    json_pattern = os.path.join(ARTIFACTS_DIR, "**/logs/stage_status.jsonl")
    json_logs = glob.glob(json_pattern, recursive=True)
    
    for log_path in json_logs:
        try:
            rel_path = os.path.relpath(log_path, ARTIFACTS_DIR)
            target = rel_path.split(os.sep)[0]
            if target not in target_stats:
                target_stats[target] = {"subdomains": 0, "resolved": 0, "live_hosts": 0, "ports": 0}
            
            with open(log_path, "r") as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        stage = data.get("stage", "log")
                        metrics = data.get("metrics", {})
                        
                        if stage == "subdomains":
                            val = metrics.get("total_subdomains") or metrics.get("subdomains") or metrics.get("count") or 0
                            target_stats[target]["subdomains"] = max(target_stats[target]["subdomains"], val)
                        elif stage == "dnsx":
                            val = metrics.get("resolved") or metrics.get("count") or 0
                            target_stats[target]["resolved"] = max(target_stats[target]["resolved"], val)
                        elif stage in ["httpx", "probe"]:
                            val = metrics.get("live_hosts") or metrics.get("live") or metrics.get("count") or 0
                            target_stats[target]["live_hosts"] = max(target_stats[target]["live_hosts"], val)
                        elif stage == "portscan":
                            val = metrics.get("ports") or metrics.get("count") or metrics.get("merged_total") or 0
                            target_stats[target]["ports"] = max(target_stats[target]["ports"], val)
                        
                        mapped_stage = stage
                        if stage.startswith("discovery_"): mapped_stage = "discovery"
                        
                        event = {
                            "event": mapped_stage,
                            "payload": {
                                "msg": data.get("detail", ""),
                                "status": data.get("status", ""),
                                "target": target,
                                "stats": dict(target_stats[target])
                            },
                            "ts": data.get("timestamp", "")
                        }
                        found_events.append(event)
                    except:
                        continue
        except Exception as e:
            logger.error(f"Error parsing json log {log_path}: {e}")
    
    # Sort by timestamp
    found_events.sort(key=lambda x: x.get("ts", ""))
    
    # Bulk insert into SQLite
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    for e in found_events:
        try:
            payload = e.get('payload', {})
            event_type = e.get('event', 'unknown')
            target = payload.get('target', 'unknown')
            ts = e.get('ts', '')
            payload_str = json.dumps(payload, sort_keys=True)
            fingerprint = hashlib.md5(f"{ts}_{event_type}_{target}_{payload_str}".encode()).hexdigest()
            
            c.execute("INSERT INTO events (event_type, target, payload, timestamp, fingerprint) VALUES (?, ?, ?, ?, ?)",
                      (event_type, target, payload_str, ts, fingerprint))
        except sqlite3.IntegrityError:
            continue
        except Exception as ex:
            logger.error(f"Error bulk inserting event: {ex}")
    conn.commit()
    conn.close()
    
    logger.info(f"Reconstructed and persisted {len(found_events)} events from artifacts.")

# Migration: Load history from old JSON file if it exists
if os.path.exists(HISTORY_FILE):
    try:
        with open(HISTORY_FILE, "r") as f:
            old_history = json.load(f)
            logger.info(f"Migrating {len(old_history)} events from history.json to SQLite")
            for e in old_history:
                save_event_to_db(e)
        # Rename so we don't migrate again
        os.rename(HISTORY_FILE, HISTORY_FILE + ".migrated")
    except Exception as e:
        logger.error(f"Error migrating history: {e}")

# Bootstrap from raw tool logs to catch anything missed while backend was down
bootstrap_from_artifacts()

# Load latest 10,000 events into memory for active clients
event_history = get_recent_events(10000)
logger.info(f"Ready with {len(event_history)} events in memory.")

@app.get("/")
async def root():
    return {"status": "BreachConsole Backend Running", "history_count": len(event_history)}

@app.post("/api/webhooks/breachpilot")
async def handle_webhook(request: Request):
    try:
        payload = await request.json()
        logger.info(f"Received event: {payload.get('event')}")
        
        # Persist to database
        save_event_to_db(payload)
        
        # Add to in-memory history for quick access
        event_history.append(payload)
        if len(event_history) > 10000:
            event_history.pop(0)
        
        # Broadcast to all connected clients
        disconnected = []
        for client in clients:
            try:
                await client.send_json(payload)
            except Exception as e:
                logger.error(f"Error broadcasting to client: {e}")
                disconnected.append(client)
        
        for client in disconnected:
            if client in clients:
                clients.remove(client)
                
        return {"status": "ok"}
    except Exception as e:
        logger.error(f"Error handling webhook: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/api/clear")
async def clear_history():
    global event_history
    event_history = []
    
    # Clear SQLite table
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM events")
    conn.commit()
    conn.close()
    
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)
    logger.info("Event history cleared from memory and database")
    return {"status": "ok"}

@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    logger.info("New WebSocket client connected")
    clients.append(websocket)
    
    # Send history to new client
    for event in event_history:
        try:
            await websocket.send_json(event)
        except:
            break
        
    try:
        while True:
            # Keep connection alive, listen for messages (though we don't expect any)
            await websocket.receive_text()
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
        if websocket in clients:
            clients.remove(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        if websocket in clients:
            clients.remove(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
