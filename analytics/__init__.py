"""
数据统计分析模块

为PCAP解码器提供强大的数据统计和分析功能
支持多种统计维度：流量、协议、安全、性能等
"""

__version__ = "1.0.0"
__author__ = "PCAP Analytics Team"

from .core.analyzer import AnalyticsEngine
from .core.aggregator import DataAggregator
from .core.reporter import ReportGenerator
from .adapters.json_adapter import JSONDataAdapter
from .stats.base import StatisticsBase

# 公共接口
__all__ = [
    'AnalyticsEngine',
    'DataAggregator', 
    'ReportGenerator',
    'JSONDataAdapter',
    'StatisticsBase'
]

# 模块配置
DEFAULT_CONFIG = {
    'enable_real_time': False,
    'batch_size': 1000,
    'output_formats': ['json'],
    'statistics_modules': [
        'traffic',
        'protocol',
        'security',
        'performance'
    ]
} 