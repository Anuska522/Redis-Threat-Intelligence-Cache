import asyncio
import json
import logging
from typing import Set
from fastapi import WebSocket
from app.services.redis_service import redis_service

logger = logging.getLogger("alert_service")


class AlertWebSocketManager:
    def __init__(self):
        self._active_connections: Set[WebSocket] = set()
        self._listener_task: asyncio.Task = None
        self._running: bool = False

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._active_connections.add(websocket)
        logger.info(f"WebSocket client connected. Active connections: {len(self._active_connections)}")

    def disconnect(self, websocket: WebSocket) -> None:
        self._active_connections.discard(websocket)
        logger.info(f"WebSocket client disconnected. Active connections: {len(self._active_connections)}")

    async def broadcast(self, message: str) -> None:
        dead_connections = set()
        for connection in list(self._active_connections):
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.warning(f"Failed to send to WebSocket client: {e}")
                dead_connections.add(connection)

        for dead in dead_connections:
            self._active_connections.discard(dead)

    async def _pubsub_listener(self) -> None:
        """Background listener subscribing to Redis Pub/Sub channel 'alerts'."""
        while self._running:
            pubsub = None
            try:
                await redis_service.connect()
                pubsub = redis_service.get_pubsub()
                await pubsub.subscribe("alerts")
                logger.info("Subscribed to Redis Pub/Sub 'alerts' channel successfully.")

                async for message in pubsub.listen():
                    if not self._running:
                        break
                    if message and message["type"] == "message":
                        data = message["data"]
                        if isinstance(data, bytes):
                            data = data.decode("utf-8")
                        await self.broadcast(data)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in Redis Pub/Sub listener: {e}. Reconnecting in 2 seconds...")
                await asyncio.sleep(2.0)
            finally:
                if pubsub:
                    try:
                        await pubsub.unsubscribe("alerts")
                        await pubsub.aclose()
                    except Exception:
                        pass

    def start_background_listener(self) -> None:
        if not self._running:
            self._running = True
            self._listener_task = asyncio.create_task(self._pubsub_listener())

    async def stop(self) -> None:
        self._running = False
        if self._listener_task:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass


alert_ws_manager = AlertWebSocketManager()
