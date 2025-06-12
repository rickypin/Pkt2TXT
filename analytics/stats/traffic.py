"""
流量统计模块

提供各种网络流量相关的统计功能
包括数据传输量、包大小分布、时间分布等
"""

import time
from typing import Dict, List, Any
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from .base import StatisticsBase, AggregableStatistics, StatisticsResult, statistics_registry
from ..adapters.schema import DataSchema


class BasicTrafficStatistics(AggregableStatistics):
    """基础流量统计"""
    
    def __init__(self):
        super().__init__(
            name="basic_traffic",
            description="基础流量统计：总包数、总字节数、平均包大小等"
        )
    
    def calculate(self, data: DataSchema) -> StatisticsResult:
        """计算基础流量统计"""
        start_time = time.time()
        
        packets = data.packets
        if not packets:
            return StatisticsResult(
                name=self.name,
                description=self.description,
                results={},
                metadata={'file_count': 0}
            )
        
        # 基础统计
        total_packets = len(packets)
        total_bytes = sum(packet.length for packet in packets)
        avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0
        
        # 包大小统计
        packet_sizes = [packet.length for packet in packets]
        min_size = min(packet_sizes)
        max_size = max(packet_sizes)
        
        # 时间范围
        timestamps = [packet.timestamp for packet in packets]
        if timestamps and isinstance(timestamps[0], datetime):
            start_time_data = min(timestamps)
            end_time_data = max(timestamps)
            duration = (end_time_data - start_time_data).total_seconds()
        else:
            start_time_data = end_time_data = duration = None
        
        results = {
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'average_packet_size': round(avg_packet_size, 2),
            'min_packet_size': min_size,
            'max_packet_size': max_size,
            'start_time': start_time_data.isoformat() if start_time_data else None,
            'end_time': end_time_data.isoformat() if end_time_data else None,
            'duration_seconds': round(duration, 3) if duration else None,
            'packets_per_second': round(total_packets / duration, 2) if duration and duration > 0 else None,
            'bytes_per_second': round(total_bytes / duration, 2) if duration and duration > 0 else None
        }
        
        return StatisticsResult(
            name=self.name,
            description=self.description,
            results=results,
            metadata={
                'file_name': data.file_info.file_name,
                'file_count': 1
            },
            calculation_time=time.time() - start_time
        )
    
    def aggregate(self, results: List[StatisticsResult]) -> StatisticsResult:
        """聚合多个文件的流量统计"""
        if not results:
            return StatisticsResult(
                name=self.name,
                description=f"{self.description} (聚合)",
                results={},
                metadata={'file_count': 0}
            )
        
        total_packets = sum(r.results.get('total_packets', 0) for r in results)
        total_bytes = sum(r.results.get('total_bytes', 0) for r in results)
        
        # 计算聚合后的平均值
        avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0
        
        # 合并时间范围
        start_times = [r.results.get('start_time') for r in results if r.results.get('start_time')]
        end_times = [r.results.get('end_time') for r in results if r.results.get('end_time')]
        
        if start_times and end_times:
            start_times = [datetime.fromisoformat(t) for t in start_times]
            end_times = [datetime.fromisoformat(t) for t in end_times]
            overall_start = min(start_times)
            overall_end = max(end_times)
            overall_duration = (overall_end - overall_start).total_seconds()
        else:
            overall_start = overall_end = overall_duration = None
        
        aggregated_results = {
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'average_packet_size': round(avg_packet_size, 2),
            'file_count': len(results),
            'start_time': overall_start.isoformat() if overall_start else None,
            'end_time': overall_end.isoformat() if overall_end else None,
            'duration_seconds': round(overall_duration, 3) if overall_duration else None,
            'packets_per_second': round(total_packets / overall_duration, 2) if overall_duration and overall_duration > 0 else None,
            'bytes_per_second': round(total_bytes / overall_duration, 2) if overall_duration and overall_duration > 0 else None
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
        return ['packets', 'length', 'timestamp']


class PacketSizeDistribution(StatisticsBase):
    """包大小分布统计"""
    
    def __init__(self, bin_size: int = 64):
        super().__init__(
            name="packet_size_distribution",
            description="数据包大小分布统计"
        )
        self.bin_size = bin_size
    
    def calculate(self, data: DataSchema) -> StatisticsResult:
        """计算包大小分布"""
        start_time = time.time()
        
        packets = data.packets
        if not packets:
            return StatisticsResult(
                name=self.name,
                description=self.description,
                results={},
                metadata={}
            )
        
        # 收集包大小
        packet_sizes = [packet.length for packet in packets]
        
        # 创建分布区间
        max_size = max(packet_sizes)
        bins = list(range(0, max_size + self.bin_size, self.bin_size))
        
        # 计算分布
        distribution = defaultdict(int)
        for size in packet_sizes:
            bin_index = (size // self.bin_size) * self.bin_size
            distribution[bin_index] += 1
        
        # 转换为可序列化的格式
        size_distribution = {
            f"{k}-{k + self.bin_size - 1}": v 
            for k, v in sorted(distribution.items())
        }
        
        # 统计特殊大小的包
        common_sizes = Counter(packet_sizes).most_common(10)
        
        results = {
            'size_distribution': size_distribution,
            'bin_size': self.bin_size,
            'common_sizes': [{'size': size, 'count': count} for size, count in common_sizes],
            'total_packets': len(packets),
            'unique_sizes': len(set(packet_sizes))
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
        return ['packets', 'length']


class TimeBasedTrafficAnalysis(StatisticsBase):
    """基于时间的流量分析"""
    
    def __init__(self, interval_seconds: int = 60):
        super().__init__(
            name="time_based_traffic",
            description="基于时间间隔的流量分析"
        )
        self.interval_seconds = interval_seconds
    
    def calculate(self, data: DataSchema) -> StatisticsResult:
        """计算时间间隔流量统计"""
        start_time = time.time()
        
        packets = data.packets
        if not packets:
            return StatisticsResult(
                name=self.name,
                description=self.description,
                results={},
                metadata={}
            )
        
        # 按时间间隔分组
        time_intervals = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        
        for packet in packets:
            if isinstance(packet.timestamp, datetime):
                # 计算时间间隔
                interval_start = packet.timestamp.replace(
                    second=(packet.timestamp.second // self.interval_seconds) * self.interval_seconds,
                    microsecond=0
                )
                interval_key = interval_start.isoformat()
                
                time_intervals[interval_key]['packets'] += 1
                time_intervals[interval_key]['bytes'] += packet.length
        
        # 转换为列表格式
        time_series = []
        for interval, stats in sorted(time_intervals.items()):
            time_series.append({
                'timestamp': interval,
                'packets': stats['packets'],
                'bytes': stats['bytes'],
                'packets_per_second': stats['packets'] / self.interval_seconds,
                'bytes_per_second': stats['bytes'] / self.interval_seconds
            })
        
        # 计算峰值
        if time_series:
            peak_packets = max(time_series, key=lambda x: x['packets'])
            peak_bytes = max(time_series, key=lambda x: x['bytes'])
        else:
            peak_packets = peak_bytes = None
        
        results = {
            'time_series': time_series,
            'interval_seconds': self.interval_seconds,
            'total_intervals': len(time_series),
            'peak_packets_interval': peak_packets,
            'peak_bytes_interval': peak_bytes
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
        return ['packets', 'timestamp', 'length']


# 注册统计项
statistics_registry.register(BasicTrafficStatistics, "traffic")
statistics_registry.register(PacketSizeDistribution, "traffic")
statistics_registry.register(TimeBasedTrafficAnalysis, "traffic") 