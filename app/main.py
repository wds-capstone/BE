from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from app.packet_sniffer import PacketSniffer
from app.models import SystemStats
import asyncio
import json
from typing import List

app = FastAPI(title="NetGuard Security API")

# CORS 설정 - Vite 개발 서버 포트 추가!
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",   # React 기본 포트
        "http://localhost:5173",   # Vite 개발 서버
        "http://localhost:5174",   # Vite 대체 포트
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 패킷 스니퍼 인스턴스
sniffer = PacketSniffer()

# WebSocket 연결 관리
active_connections: List[WebSocket] = []

@app.on_event("startup")
async def startup_event():
    """서버 시작 시 패킷 캡처 시작"""
    print("=" * 60)
    print("🚀 NetGuard Security v10.2 서버 시작")
    print("=" * 60)
    print("📡 실시간 패킷 모니터링 활성화")
    print("🌐 WebSocket 엔드포인트: ws://localhost:8000/ws")
    print("🔗 REST API: http://localhost:8000/api/stats")
    print("=" * 60)
    
    # 주의: 관리자 권한 필요!
    # Windows: 관리자 권한으로 실행
    # Linux/Mac: sudo python run.py
    sniffer.start_sniffing()

@app.on_event("shutdown")
async def shutdown_event():
    """서버 종료 시 패킷 캡처 중지"""
    print("\n🛑 NetGuard Security 서버 종료")
    sniffer.stop_sniffing()

@app.get("/")
async def root():
    """루트 엔드포인트"""
    return {
        "message": "NetGuard Security API v10.2",
        "status": "running",
        "endpoints": {
            "stats": "/api/stats",
            "websocket": "/ws"
        }
    }

@app.get("/api/stats")
async def get_stats():
    """현재 통계 조회 (REST API)"""
    return sniffer.get_stats()

@app.get("/api/health")
async def health_check():
    """서버 상태 확인"""
    return {
        "status": "healthy",
        "sniffer_running": sniffer.is_running,
        "total_packets": sniffer.packet_count,
        "active_connections": len(active_connections)
    }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """실시간 데이터 전송을 위한 WebSocket"""
    await websocket.accept()
    active_connections.append(websocket)
    client_id = id(websocket)
    
    print(f"✅ 클라이언트 연결: {client_id} (총 {len(active_connections)}개)")
    
    try:
        while True:
            # 1초마다 통계 전송
            stats = sniffer.get_stats()
            await websocket.send_json(stats)
            await asyncio.sleep(1)
            
    except WebSocketDisconnect:
        active_connections.remove(websocket)
        print(f"❌ 클라이언트 연결 종료: {client_id} (남은 연결: {len(active_connections)}개)")
    except Exception as e:
        print(f"⚠️ WebSocket 오류: {e}")
        if websocket in active_connections:
            active_connections.remove(websocket)