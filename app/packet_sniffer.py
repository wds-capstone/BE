from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from collections import defaultdict
from datetime import datetime
import threading
import time
from typing import Dict, List
from app.models import PacketInfo, ProtocolStats, ThreatInfo

class PacketSniffer:
    """Scapy를 사용한 실시간 패킷 캡처"""
    
    def __init__(self):
        self.is_running = False
        self.packet_count = 0
        self.prev_packet_count = 0  # 변화율 계산용
        self.protocol_stats = ProtocolStats()
        self.bandwidth_data: List[float] = []
        self.connection_count = 0
        self.threats: List[ThreatInfo] = []
        self.prev_threat_count = 0  # 위협 변화량 계산용
        self.ip_counter: Dict[str, int] = defaultdict(int)
        self.port_scan_detector: Dict[str, set] = defaultdict(set)
        self.last_update_time = time.time()
        
    def packet_callback(self, packet):
        """각 패킷을 처리하는 콜백"""
        try:
            self.packet_count += 1
            
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                packet_len = len(packet)
                
                # IP별 패킷 카운트 (DDoS 탐지용)
                self.ip_counter[src_ip] += 1
                
                # 대역폭 계산 (MB/s로 변환)
                # 패킷 크기(bytes) → MB
                bandwidth_mb = packet_len / (1024 * 1024)
                self.bandwidth_data.append(bandwidth_mb)
                
                # 프로토콜 분류
                if TCP in packet:
                    self.protocol_stats.tcp += 1
                    dst_port = packet[TCP].dport
                    
                    # 포트 스캔 탐지
                    self.port_scan_detector[src_ip].add(dst_port)
                    if len(self.port_scan_detector[src_ip]) > 20:
                        self._add_threat("포트 스캔", src_ip, "중간")
                    
                elif UDP in packet:
                    self.protocol_stats.udp += 1
                    
                elif ICMP in packet:
                    self.protocol_stats.icmp += 1
                    
                # DDoS 탐지 (특정 IP에서 너무 많은 패킷)
                if self.ip_counter[src_ip] > 100:
                    self._add_threat("DDoS 공격", src_ip, "높음")
                    self.protocol_stats.ddos += 1
                    
            elif ARP in packet:
                self.protocol_stats.arp += 1
                
        except Exception as e:
            print(f"⚠️ 패킷 처리 오류: {e}")
    
    def _add_threat(self, threat_type: str, ip: str, severity: str):
        """위협 로그 추가"""
        current_time = datetime.now().strftime("%H:%M:%S")
        
        # 중복 방지 (최근 5개 체크)
        recent_threats = self.threats[-5:] if len(self.threats) >= 5 else self.threats
        if not any(t.ip == ip and t.type == threat_type for t in recent_threats):
            threat = ThreatInfo(
                type=threat_type,
                ip=ip,
                time=current_time,
                severity=severity
            )
            self.threats.append(threat)
            
            # 최근 20개만 유지
            if len(self.threats) > 20:
                self.threats = self.threats[-20:]
            
            print(f"⚠️ 위협 탐지: {threat_type} - {ip} [{severity}]")
    
    def start_sniffing(self, interface: str = None):
        """패킷 캡처 시작"""
        self.is_running = True
        
        def sniff_thread():
            print(f"📡 패킷 캡처 시작... (인터페이스: {interface or '기본'})")
            try:
                sniff(
                    iface=interface,
                    prn=self.packet_callback,
                    store=False,
                    stop_filter=lambda x: not self.is_running
                )
            except PermissionError:
                print("❌ 권한 오류: 관리자 권한으로 실행해주세요!")
                print("   Windows: 관리자 권한으로 실행")
                print("   Linux/Mac: sudo python run.py")
                self.is_running = False
            except Exception as e:
                print(f"❌ 패킷 캡처 오류: {e}")
                self.is_running = False
        
        thread = threading.Thread(target=sniff_thread, daemon=True)
        thread.start()
    
    def stop_sniffing(self):
        """패킷 캡처 중지"""
        self.is_running = False
        print("🛑 패킷 캡처 중지")
    
    def get_stats(self) -> dict:
        """현재 통계 반환"""
        current_time = time.time()
        time_elapsed = current_time - self.last_update_time
        
        # 대역폭 계산 (최근 100개 패킷 기준)
        recent_bandwidth = self.bandwidth_data[-100:] if self.bandwidth_data else []
        
        # 평균 대역폭 (MB/s)
        if recent_bandwidth and time_elapsed > 0:
            # 총 데이터(MB) / 시간(초) = MB/s
            total_data_mb = sum(recent_bandwidth)
            avg_bandwidth = total_data_mb / time_elapsed if time_elapsed > 0 else 0
        else:
            avg_bandwidth = 0
        
        # 최대 대역폭
        peak_bandwidth = max(recent_bandwidth) * 100 if recent_bandwidth else 0  # 순간 최대값
        
        # 패킷 증가율 계산
        if self.prev_packet_count > 0:
            packet_change_rate = ((self.packet_count - self.prev_packet_count) / self.prev_packet_count) * 100
        else:
            packet_change_rate = 0
        
        # 위협 변화량 계산
        current_threat_count = len([t for t in self.threats if t.severity == "높음"])
        threat_change = current_threat_count - self.prev_threat_count
        
        # 이전 값 업데이트
        self.prev_packet_count = self.packet_count
        self.prev_threat_count = current_threat_count
        self.last_update_time = current_time
        
        # 활성 위협 수 (심각도 높음인 것만)
        active_threats = len([t for t in self.threats if t.severity == "높음"])
        
        stats = {
            "total_packets": self.packet_count,
            "avg_bandwidth": round(avg_bandwidth, 2),
            "peak_bandwidth": round(peak_bandwidth, 2),
            "active_threats": active_threats,
            "active_connections": len(self.ip_counter),
            "protocol_stats": self.protocol_stats.dict(),
            "threats": [t.dict() for t in self.threats[-10:]],  # 최근 10개
            "packet_change_rate": round(packet_change_rate, 2),
            "threat_change": threat_change
        }
        
        return stats
    
    def reset_stats(self):
        """통계 초기화"""
        print("🔄 통계 초기화")
        self.packet_count = 0
        self.prev_packet_count = 0
        self.protocol_stats = ProtocolStats()
        self.bandwidth_data = []
        self.ip_counter.clear()
        self.port_scan_detector.clear()
        self.threats = []
        self.prev_threat_count = 0
        self.last_update_time = time.time()