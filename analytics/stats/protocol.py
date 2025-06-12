"""
协议统计模块

提供网络协议相关的统计功能
这是一个扩展示例，展示如何轻松添加新的统计项
"""

import time
from typing import Dict, List, Any
from collections import defaultdict, Counter
from .base import StatisticsBase, AggregableStatistics, StatisticsResult, statistics_registry
from ..adapters.schema import DataSchema


class ProtocolDistribution(AggregableStatistics):
    """协议分布统计"""
    
    def __init__(self):
        super().__init__(
            name="protocol_distribution",
            description="网络协议分布统计：各协议包数量、字节数分布"
        )
    
    def calculate(self, data: DataSchema) -> StatisticsResult:
        """计算协议分布统计"""
        start_time = time.time()
        
        packets = data.packets
        if not packets:
            return StatisticsResult(
                name=self.name,
                description=self.description,
                results={},
                metadata={}
            )
        
        # 统计协议分布
        protocol_packets = defaultdict(int)
        protocol_bytes = defaultdict(int)
        layer_distribution = defaultdict(int)
        
        for packet in packets:
            # 统计每层协议
            for layer in packet.layers:
                protocol_packets[layer] += 1
                protocol_bytes[layer] += packet.length
                layer_distribution[layer] += 1
            
            # 统计应用层协议（如果有）
            if packet.protocols:
                for protocol_name in packet.protocols.keys():
                    protocol_packets[protocol_name] += 1
                    protocol_bytes[protocol_name] += packet.length
        
        # 计算百分比
        total_packets = len(packets)
        total_bytes = sum(packet.length for packet in packets)
        
        protocol_stats = {}
        for protocol in protocol_packets:
            protocol_stats[protocol] = {
                'packet_count': protocol_packets[protocol],
                'byte_count': protocol_bytes[protocol],
                'packet_percentage': round((protocol_packets[protocol] / total_packets) * 100, 2),
                'byte_percentage': round((protocol_bytes[protocol] / total_bytes) * 100, 2)
            }
        
        results = {
            'protocol_statistics': protocol_stats,
            'layer_distribution': dict(layer_distribution),
            'unique_protocols': len(protocol_packets),
            'most_common_protocols': [
                {'protocol': p, 'count': c} 
                for p, c in Counter(protocol_packets).most_common(10)
            ]
        }
        
        return StatisticsResult(
            name=self.name,
            description=self.description,
            results=results,
            metadata={
                'file_name': data.file_info.file_name,
                'total_packets': total_packets
            },
            calculation_time=time.time() - start_time
        )
    
    def aggregate(self, results: List[StatisticsResult]) -> StatisticsResult:
        """聚合多个文件的协议统计"""
        if not results:
            return StatisticsResult(
                name=self.name,
                description=f"{self.description} (聚合)",
                results={},
                metadata={'file_count': 0}
            )
        
        # 聚合协议统计
        aggregated_protocols = defaultdict(lambda: {'packet_count': 0, 'byte_count': 0})
        aggregated_layers = defaultdict(int)
        total_packets = 0
        total_bytes = 0
        
        for result in results:
            protocol_stats = result.results.get('protocol_statistics', {})
            layer_dist = result.results.get('layer_distribution', {})
            
            for protocol, stats in protocol_stats.items():
                aggregated_protocols[protocol]['packet_count'] += stats['packet_count']
                aggregated_protocols[protocol]['byte_count'] += stats['byte_count']
            
            for layer, count in layer_dist.items():
                aggregated_layers[layer] += count
            
            total_packets += result.metadata.get('total_packets', 0)
        
        # 重新计算百分比
        if total_packets > 0:
            total_bytes = sum(p['byte_count'] for p in aggregated_protocols.values())
            
            for protocol in aggregated_protocols:
                aggregated_protocols[protocol]['packet_percentage'] = round(
                    (aggregated_protocols[protocol]['packet_count'] / total_packets) * 100, 2
                )
                if total_bytes > 0:
                    aggregated_protocols[protocol]['byte_percentage'] = round(
                        (aggregated_protocols[protocol]['byte_count'] / total_bytes) * 100, 2
                    )
        
        aggregated_results = {
            'protocol_statistics': dict(aggregated_protocols),
            'layer_distribution': dict(aggregated_layers),
            'unique_protocols': len(aggregated_protocols),
            'file_count': len(results),
            'total_packets': total_packets,
            'most_common_protocols': [
                {'protocol': p, 'count': stats['packet_count']} 
                for p, stats in sorted(aggregated_protocols.items(), 
                                     key=lambda x: x[1]['packet_count'], reverse=True)[:10]
            ]
        }
        
        return StatisticsResult(
            name=self.name,
            description=f"{self.description} (聚合)",
            results=aggregated_results,
            metadata={
                'file_count': len(results),
                'files': [r.metadata.get('file_name', 'unknown') for r in results]
            }
        )
    
    def get_required_fields(self) -> List[str]:
        return ['packets', 'layers', 'protocols']


class TCPConnectionAnalysis(StatisticsBase):
    """TCP连接分析"""
    
    def __init__(self):
        super().__init__(
            name="tcp_connection_analysis",
            description="TCP连接统计：连接数、状态分布、端口分析"
        )
    
    def calculate(self, data: DataSchema) -> StatisticsResult:
        """计算TCP连接统计"""
        start_time = time.time()
        
        packets = data.packets
        tcp_packets = [p for p in packets if 'TCP' in p.layers]
        
        if not tcp_packets:
            return StatisticsResult(
                name=self.name,
                description=self.description,
                results={'tcp_packets': 0},
                metadata={}
            )
        
        # 统计TCP连接信息
        connections = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        source_ports = defaultdict(int)
        dest_ports = defaultdict(int)
        tcp_flags = defaultdict(int)
        
        for packet in tcp_packets:
            tcp_info = packet.protocols.get('TCP', {})
            
            if tcp_info:
                # 提取连接信息（简化版）
                src_port = tcp_info.get('srcport', 'unknown')
                dst_port = tcp_info.get('dstport', 'unknown')
                flags = tcp_info.get('flags', {})
                
                # 统计端口
                source_ports[src_port] += 1
                dest_ports[dst_port] += 1
                
                # 统计标志位
                for flag_name, flag_value in flags.items():
                    if flag_value:
                        tcp_flags[flag_name] += 1
        
        results = {
            'tcp_packets': len(tcp_packets),
            'tcp_percentage': round((len(tcp_packets) / len(packets)) * 100, 2),
            'unique_source_ports': len(source_ports),
            'unique_dest_ports': len(dest_ports),
            'common_source_ports': [
                {'port': p, 'count': c} 
                for p, c in Counter(source_ports).most_common(10)
            ],
            'common_dest_ports': [
                {'port': p, 'count': c} 
                for p, c in Counter(dest_ports).most_common(10)
            ],
            'tcp_flags_distribution': dict(tcp_flags)
        }
        
        return StatisticsResult(
            name=self.name,
            description=self.description,
            results=results,
            metadata={
                'file_name': data.file_info.file_name
            },
            calculation_time=time.time() - start_time
        )
    
    def get_required_fields(self) -> List[str]:
        return ['packets', 'layers', 'protocols']


# 注册新的统计项
statistics_registry.register(ProtocolDistribution, "protocol")
statistics_registry.register(TCPConnectionAnalysis, "protocol") 