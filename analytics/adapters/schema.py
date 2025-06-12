"""
数据模式定义

定义标准化的数据结构，用于适配器之间的数据交换
提供数据验证和类型转换功能
"""

from dataclasses import dataclass
from typing import Dict, List, Any, Optional, Union
from datetime import datetime


@dataclass
class PacketSchema:
    """标准化的数据包结构"""
    number: int
    timestamp: Union[str, datetime]
    length: int
    layers: List[str]
    protocols: Dict[str, Any]
    
    def __post_init__(self):
        """数据后处理和验证"""
        if isinstance(self.timestamp, str):
            # 尝试解析时间戳字符串
            try:
                self.timestamp = datetime.fromisoformat(self.timestamp.replace('Z', '+00:00'))
            except ValueError:
                # 如果解析失败，保持原始字符串格式
                pass


@dataclass 
class FileInfoSchema:
    """文件信息结构"""
    input_file: str
    file_name: str
    file_size: int
    packet_count: int
    decode_time: float
    processing_timestamp: Union[str, datetime]


@dataclass
class ProtocolStatsSchema:
    """协议统计结构"""
    total_packets: int
    protocol_distribution: Dict[str, int]
    unique_protocols: List[str]
    layer_distribution: Optional[Dict[str, int]] = None
    protocol_combinations: Optional[Dict[str, int]] = None
    protocol_count: Optional[int] = None
    average_layers_per_packet: Optional[float] = None


@dataclass
class DataSchema:
    """完整的数据文件结构"""
    metadata: Dict[str, Any]
    file_info: FileInfoSchema
    protocol_statistics: ProtocolStatsSchema
    packets: List[PacketSchema]
    errors: Optional[Dict[str, Any]] = None
    
    @classmethod
    def from_json_data(cls, json_data: Dict[str, Any]) -> 'DataSchema':
        """从JSON数据创建DataSchema实例"""
        # 解析文件信息
        file_info = FileInfoSchema(**json_data['file_info'])
        
        # 解析协议统计
        protocol_stats = ProtocolStatsSchema(**json_data['protocol_statistics'])
        
        # 解析数据包列表
        packets = [PacketSchema(**packet_data) for packet_data in json_data['packets']]
        
        return cls(
            metadata=json_data['metadata'],
            file_info=file_info,
            protocol_statistics=protocol_stats,
            packets=packets,
            errors=json_data.get('errors')
        )


class DataValidator:
    """数据验证器"""
    
    @staticmethod
    def validate_packet(packet_data: Dict[str, Any]) -> bool:
        """验证单个数据包数据的完整性"""
        required_fields = ['number', 'timestamp', 'length', 'layers', 'protocols']
        return all(field in packet_data for field in required_fields)
    
    @staticmethod
    def validate_file_data(file_data: Dict[str, Any]) -> bool:
        """验证整个文件数据的完整性"""
        required_sections = ['metadata', 'file_info', 'protocol_statistics', 'packets']
        return all(section in file_data for section in required_sections)
    
    @staticmethod
    def get_validation_errors(file_data: Dict[str, Any]) -> List[str]:
        """获取详细的验证错误信息"""
        errors = []
        
        # 检查必需的顶级字段
        required_sections = ['metadata', 'file_info', 'protocol_statistics', 'packets']
        for section in required_sections:
            if section not in file_data:
                errors.append(f"缺少必需的数据段: {section}")
        
        # 检查数据包格式
        if 'packets' in file_data:
            for i, packet in enumerate(file_data['packets']):
                if not DataValidator.validate_packet(packet):
                    errors.append(f"数据包 {i} 格式不正确")
        
        return errors 