from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class PacketInfo(BaseModel):
    """개별 패킷 정보"""
    timestamp: str
    source_ip: str
    dest_ip: str
    protocol: str
    length: int
    port: Optional[int] = None

class ProtocolStats(BaseModel):
    """프로토콜 통계"""
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    arp: int = 0
    ddos: int = 0

class ThreatInfo(BaseModel):
    """위협 정보"""
    type: str
    ip: str
    time: str
    severity: str  # "높음", "중간", "낮음"

class SystemStats(BaseModel):
    """시스템 전체 통계"""
    total_packets: int
    avg_bandwidth: float
    peak_bandwidth: float
    active_threats: int
    active_connections: int
    protocol_stats: ProtocolStats
    threats: List[ThreatInfo]
    packet_change_rate: float
    threat_change: int