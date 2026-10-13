from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from typing import List
from app.models.threat import AlertEvent
from app.services.redis_service import redis_service
from app.services.alert_service import alert_ws_manager

router = APIRouter(tags=["Real-Time Alerts"])


@router.get("/api/alerts/history", response_model=List[AlertEvent], summary="Retrieve recent real-time security alerts")
async def get_alerts_history(limit: int = Query(50, ge=1, le=100)):
    return await redis_service.get_alert_history(limit=limit)


@router.websocket("/ws/alerts")
async def websocket_alerts_endpoint(websocket: WebSocket):
    await alert_ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive, listen for ping or client messages
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text('{"type": "pong"}')
    except WebSocketDisconnect:
        alert_ws_manager.disconnect(websocket)
    except Exception:
        alert_ws_manager.disconnect(websocket)
