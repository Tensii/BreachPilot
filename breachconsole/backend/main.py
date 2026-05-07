from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import os
import glob
import json
import asyncio
import logging
import datetime
import re
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
ARTIFACTS_DIR = os.path.join(os.path.dirname(os.path.dirname(BASE_DIR)), "artifacts")

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
    
    # Merge and deduplicate
    existing_fingerprints = set()
    for e in event_history:
        fp = f"{e.get('ts')}_{e.get('event')}_{e.get('payload', {}).get('target')}"
        existing_fingerprints.add(fp)

    for e in found_events:
        fp = f"{e.get('ts')}_{e.get('event')}_{e.get('payload', {}).get('target')}"
        if fp not in existing_fingerprints:
            event_history.append(e)
            existing_fingerprints.add(fp)
            
    if len(event_history) > 10000:
        event_history = event_history[-10000:]
    
    logger.info(f"Reconstructed {len(found_events)} events from artifacts.")

# Load history from disk on startup
if os.path.exists(HISTORY_FILE):
    try:
        with open(HISTORY_FILE, "r") as f:
            event_history = json.load(f)
        logger.info(f"Loaded {len(event_history)} events from history.json")
    except Exception as e:
        logger.error(f"Error loading history: {e}")
        event_history = []

# Also bootstrap from raw tool logs to catch anything missed while backend was down
bootstrap_from_artifacts()

def save_history():
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(event_history, f)
    except Exception as e:
        logger.error(f"Error saving history: {e}")

@app.get("/")
async def root():
    return {"status": "BreachConsole Backend Running", "history_count": len(event_history)}

@app.post("/api/webhooks/breachpilot")
async def handle_webhook(request: Request):
    try:
        payload = await request.json()
        logger.info(f"Received event: {payload.get('event')}")
        
        # Add to history
        event_history.append(payload)
        if len(event_history) > 10000:
            event_history.pop(0)
        
        # Persist to disk
        save_history()
        
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
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)
    logger.info("Event history cleared and file removed")
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
