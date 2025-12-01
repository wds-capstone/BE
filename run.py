import uvicorn

if __name__ == "__main__":
    print("=" * 50)
    print("🔒 NetGuard Security - Enterprise Network Monitoring")
    print("=" * 50)
    print("\n⚠️  주의: 패킷 캡처는 관리자 권한이 필요합니다!")
    print("   - Windows: 관리자 권한으로 실행")
    print("   - Linux/Mac: sudo python run.py\n")
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )