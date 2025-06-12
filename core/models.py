"""
核心数据模型模块
定义了解码过程中的主要数据结构
"""

from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class PacketInfo:
    """数据包信息"""
    number: int
    timestamp: str
    length: int
    layers: List[str]
    protocols: Dict[str, Dict[str, Any]]

@dataclass
class DecodeResult:
    """解码结果"""
    file_path: str
    file_size: int
    packet_count: int
    packets: List[PacketInfo]
    decode_time: float
    errors: List[str] 