from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import json
import asyncio
import logging
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

# Store connected clients
clients: List[WebSocket] = []
# Store events for late joiners (last 100 events)
event_history = []

@app.get("/")
async def root():
    return {"status": "BreachConsole Backend Running"}

@app.post("/api/webhooks/breachpilot")
async def handle_webhook(request: Request):
    try:
        payload = await request.json()
        logger.info(f"Received event: {payload.get('event')}")
        
        # Add to history
        event_history.append(payload)
        if len(event_history) > 100:
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
    logger.info("Event history cleared")
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
