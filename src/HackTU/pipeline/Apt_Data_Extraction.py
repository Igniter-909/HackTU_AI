import os
from pathlib import Path
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass
from scapy.all import sniff
import pandas as pd
import numpy as np
from collections import defaultdict

@dataclass
class FlowStats:
    src_ip: str = None
    dst_ip: str = None
    src_port: int = None
    dst_port: int = None
    protocol: int = None
    start_time: float = None
    total_fwd_packets: int = 0
    total_bwd_packets: int = 0
    total_fwd_bytes: int = 0
    total_bwd_bytes: int = 0
    fwd_packet_lengths: List[int] = None
    bwd_packet_lengths: List[int] = None
    fwd_iat: List[float] = None
    bwd_iat: List[float] = None

    def __post_init__(self):
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []
        self.fwd_iat = []
        self.bwd_iat = []

class NetworkFlowAnalyzer:
    def __init__(self):
        self.flows = defaultdict(FlowStats)

    def _get_transport_info(self, packet) -> Tuple[int, int, bool]:
        """Extract transport layer information from packet."""
        if packet.haslayer('TCP'):
            transport_layer = packet['TCP']
            return transport_layer.sport, transport_layer.dport, True
        elif packet.haslayer('UDP'):
            transport_layer = packet['UDP']
            return transport_layer.sport, transport_layer.dport, True
        return None, None, False

    def _create_flow_key(self, src_ip: str, src_port: int, 
                        dst_ip: str, dst_port: int, protocol: int) -> Tuple:
        """Create a unique flow key."""
        return (src_ip, src_port, dst_ip, dst_port, protocol)

    def _initialize_flow(self, flow_key: Tuple, packet_data: Dict):
        """Initialize a new flow with basic information."""
        flow = self.flows[flow_key]
        flow.src_ip = packet_data['src_ip']
        flow.dst_ip = packet_data['dst_ip']
        flow.src_port = packet_data['src_port']
        flow.dst_port = packet_data['dst_port']
        flow.protocol = packet_data['protocol']
        flow.start_time = packet_data['time']

    def _update_flow_stats(self, flow: FlowStats, packet_len: int, 
                          packet_time: float, is_forward: bool):
        """Update statistical information for a flow."""
        if is_forward:
            flow.total_fwd_packets += 1
            flow.total_fwd_bytes += packet_len
            flow.fwd_packet_lengths.append(packet_len)
            if flow.fwd_iat:
                flow.fwd_iat.append(packet_time - flow.fwd_iat[-1])
            else:
                flow.fwd_iat.append(0)
        else:
            flow.total_bwd_packets += 1
            flow.total_bwd_bytes += packet_len
            flow.bwd_packet_lengths.append(packet_len)
            if flow.bwd_iat:
                flow.bwd_iat.append(packet_time - flow.bwd_iat[-1])
            else:
                flow.bwd_iat.append(0)

    def process_packet(self, packet):
        """Process a single packet and update flow statistics."""
        if not packet.haslayer('IP'):
            return

        ip_layer = packet['IP']
        src_port, dst_port, has_transport = self._get_transport_info(packet)
        
        if not has_transport:
            return

        packet_data = {
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': ip_layer.proto,
            'time': packet.time
        }

        flow_key = self._create_flow_key(
            packet_data['src_ip'], packet_data['src_port'],
            packet_data['dst_ip'], packet_data['dst_port'],
            packet_data['protocol']
        )
        reverse_flow_key = self._create_flow_key(
            packet_data['dst_ip'], packet_data['dst_port'],
            packet_data['src_ip'], packet_data['src_port'],
            packet_data['protocol']
        )

        if flow_key not in self.flows and reverse_flow_key not in self.flows:
            self._initialize_flow(flow_key, packet_data)

        flow = self.flows[flow_key] if flow_key in self.flows else self.flows[reverse_flow_key]
        is_forward = flow_key in self.flows
        self._update_flow_stats(flow, len(packet), packet_data['time'], is_forward)

    def capture_packets(self, count: int = 1000):
        """Capture specified number of packets."""
        sniff(prn=self.process_packet, count=count)

    def _calculate_flow_features(self) -> List[Dict[str, Any]]:
        """Calculate features for all flows."""
        flow_data = []
        for flow_key, stats in self.flows.items():
            flow_duration = ((stats.fwd_iat[-1] if stats.fwd_iat else 0) + 
                           (stats.bwd_iat[-1] if stats.bwd_iat else 0))
            
            flow_data.append({
                'Src IP': stats.src_ip,
                'Dst IP': stats.dst_ip,
                'Src Port': stats.src_port,
                'Dst Port': stats.dst_port,
                'Protocol': stats.protocol,
                'Flow Duration': flow_duration,
                'Total Fwd Packets': stats.total_fwd_packets,
                'Total Bwd Packets': stats.total_bwd_packets,
                'Total Length of Fwd Packets': stats.total_fwd_bytes,
                'Total Length of Bwd Packets': stats.total_bwd_bytes,
                'Fwd Packet Length Max': max(stats.fwd_packet_lengths) if stats.fwd_packet_lengths else 0,
                'Fwd Packet Length Min': min(stats.fwd_packet_lengths) if stats.fwd_packet_lengths else 0,
                'Fwd Packet Length Mean': np.mean(stats.fwd_packet_lengths) if stats.fwd_packet_lengths else 0,
                'Fwd Packet Length Std': np.std(stats.fwd_packet_lengths) if stats.fwd_packet_lengths else 0,
                'Bwd Packet Length Max': max(stats.bwd_packet_lengths) if stats.bwd_packet_lengths else 0,
                'Bwd Packet Length Min': min(stats.bwd_packet_lengths) if stats.bwd_packet_lengths else 0,
                'Bwd Packet Length Mean': np.mean(stats.bwd_packet_lengths) if stats.bwd_packet_lengths else 0,
                'Bwd Packet Length Std': np.std(stats.bwd_packet_lengths) if stats.bwd_packet_lengths else 0,
                'Flow Bytes/s': (stats.total_fwd_bytes + stats.total_bwd_bytes) / flow_duration if flow_duration else 0,
                'Flow Packets/s': (stats.total_fwd_packets + stats.total_bwd_packets) / flow_duration if flow_duration else 0
            })
        return flow_data

    def export_to_csv(self, filename: str = 'live_traffic_features.csv'):
        """Export flow statistics to CSV file in temp directory."""
        temp_dir = Path(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'temp'))
        temp_dir.mkdir(exist_ok=True)
        
        flow_data = self._calculate_flow_features()
        df = pd.DataFrame(flow_data)
        
        output_path = temp_dir / filename
        df.to_csv(output_path, index=False)
        print(f"Live traffic features extracted and saved to {output_path}")