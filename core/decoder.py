"""
数据包解码器模块
使用PyShark解码PCAP/PCAPNG文件
"""

import logging
import os
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import pyshark

# 导入协议提取器（如果存在）
try:
    from .extractor import ProtocolExtractor
    HAS_EXTRACTOR = True
except ImportError:
    HAS_EXTRACTOR = False

logger = logging.getLogger(__name__)


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


class PacketDecoder:
    """数据包解码器"""
    
    def __init__(self, max_packets: Optional[int] = None):
        """
        初始化解码器
        
        Args:
            max_packets: 最大处理包数，None表示处理所有包
        """
        self.max_packets = max_packets

    def _validate_file(self, file_path: str):
        """验证文件是否存在且可读"""
        from pathlib import Path
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"文件不存在: {file_path}")
        
        if not path.is_file():
            raise OSError(f"不是有效文件: {file_path}")
        
        if not os.access(file_path, os.R_OK):
            raise PermissionError(f"无法读取文件: {file_path}")
    
    def decode_file(self, file_path: str) -> DecodeResult:
        """
        解码单个PCAP文件
        
        Args:
            file_path: PCAP文件路径
            
        Returns:
            DecodeResult: 解码结果
        """
        import time
        from pathlib import Path
        
        start_time = time.time()
        self._validate_file(file_path)
        file_size = Path(file_path).stat().st_size
        packets = []
        errors = []
        
        try:
            # 使用PyShark打开文件
            cap = pyshark.FileCapture(file_path)
            
            packet_count = 0
            for packet in cap:
                try:
                    # 解析数据包
                    packet_info = self._parse_packet(packet, packet_count + 1)
                    packets.append(packet_info)
                    packet_count += 1
                    
                    # 检查最大包数限制
                    if self.max_packets and packet_count >= self.max_packets:
                        logger.info(f"达到最大包数限制: {self.max_packets}")
                        break
                        
                except Exception as e:
                    error_msg = f"解析包 {packet_count + 1} 失败: {e}"
                    logger.warning(error_msg)
                    errors.append(error_msg)
                    packet_count += 1
            
            cap.close()
            
        except Exception as e:
            error_msg = f"打开文件失败: {e}"
            logger.error(error_msg)
            errors.append(error_msg)
            packet_count = 0
        
        decode_time = time.time() - start_time
        
        return DecodeResult(
            file_path=file_path,
            file_size=file_size,
            packet_count=packet_count,
            packets=packets,
            decode_time=decode_time,
            errors=errors
        )
    
    def _parse_packet(self, packet, packet_number: int) -> PacketInfo:
        """
        解析单个数据包
        
        Args:
            packet: PyShark数据包对象
            packet_number: 包序号
            
        Returns:
            PacketInfo: 数据包信息
        """
        # 获取基本信息
        timestamp = str(packet.sniff_time) if hasattr(packet, 'sniff_time') else 'unknown'
        length = int(packet.length) if hasattr(packet, 'length') else 0
        
        # 获取协议层
        layers = []
        protocols = {}
        
        for layer in packet.layers:
            # 安全获取层名称
            if isinstance(layer, str):
                layer_name = layer.upper()
                layers.append(layer_name)
                protocols[layer_name] = {'layer_name': layer_name, 'type': 'string_layer'}
            elif hasattr(layer, 'layer_name'):
                layer_name = layer.layer_name.upper()
                layers.append(layer_name)
                # 提取协议字段
                protocols[layer_name] = self._extract_layer_fields(layer)
            else:
                # 处理其他情况
                layer_name = str(type(layer).__name__).upper()
                layers.append(layer_name)
                protocols[layer_name] = {'layer_name': layer_name, 'type': 'unknown_layer'}
        
        return PacketInfo(
            number=packet_number,
            timestamp=timestamp,
            length=length,
            layers=layers,
            protocols=protocols
        )
    
    def _extract_layer_fields(self, layer) -> Dict[str, Any]:
        """
        提取协议层字段（增强实现）
        
        Args:
            layer: PyShark协议层对象
            
        Returns:
            Dict[str, Any]: 协议字段字典
        """
        fields = {}
        protocol_name = layer.layer_name.upper()
        
        try:
            # 使用ProtocolExtractor进行详细字段提取（如果可用）
            if HAS_EXTRACTOR:
                extractor = ProtocolExtractor()
                protocol_info = extractor._extract_protocol_fields(layer, 0)
                
                if protocol_info:
                    # 转换为字典格式
                    fields['layer_name'] = protocol_name
                    fields['summary'] = protocol_info.summary
                    
                    # 添加字段信息
                    field_data = {}
                    for field in protocol_info.fields:
                        field_data[field.name] = {
                            'value': field.value,
                            'type': field.field_type,
                            'description': field.description
                        }
                    fields['fields'] = field_data
                    
                    # 添加协议统计
                    fields['field_count'] = len(protocol_info.fields)
                else:
                    # 降级到基础实现
                    fields = self._extract_basic_fields(layer)
            else:
                # 降级到基础实现
                fields = self._extract_basic_fields(layer)
                        
        except Exception as e:
            logger.debug(f"增强字段提取失败 {protocol_name}: {e}")
            # 降级到基础实现
            fields = self._extract_basic_fields(layer)
        
        return fields
    
    def _extract_basic_fields(self, layer) -> Dict[str, Any]:
        """基础字段提取实现"""
        fields = {}
        
        try:
            # 获取层的基本信息
            fields['layer_name'] = layer.layer_name
            
            # 基础字段提取
            for field_name in dir(layer):
                if not field_name.startswith('_') and not callable(getattr(layer, field_name)):
                    try:
                        value = getattr(layer, field_name)
                        if isinstance(value, (str, int, float, bool)):
                            fields[field_name] = value
                    except:
                        continue
                        
        except Exception as e:
            logger.debug(f"基础字段提取失败 {layer.layer_name}: {e}")
            fields['error'] = str(e)
        
        return fields 