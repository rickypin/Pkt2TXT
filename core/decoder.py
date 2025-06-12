"""
数据包解码器模块
使用PyShark解码PCAP/PCAPNG文件
"""

import logging
import os
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass
import pyshark
from scapy.all import rdpcap, Scapy_Exception, PcapReader
from scapy.packet import Packet as ScapyPacket
from pathlib import Path

# 导入协议提取器（如果存在）
try:
    from core.extractor import ProtocolExtractor
    HAS_EXTRACTOR = True
except ImportError:
    HAS_EXTRACTOR = False

from utils.helpers import get_file_size_mb
from utils.errors import DecodeError
from .models import PacketInfo, DecodeResult

logger = logging.getLogger(__name__)

# 定义进度回调函数类型
ProgressCallback = Callable[[int, int], None]

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
    
    def __init__(self, max_packets: Optional[int] = None, streaming_threshold_mb: float = 100.0):
        """
        初始化解码器
        
        Args:
            max_packets: 最大处理包数，None表示处理所有包
            streaming_threshold_mb: 流式读取的阈值，单位MB
        """
        self.max_packets = max_packets
        self.streaming_threshold_mb = streaming_threshold_mb
        self.pcap_reader = None

    def _validate_file(self, file_path: str):
        """验证文件是否存在且可读"""
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"文件不存在: {file_path}")
        
        if not path.is_file():
            raise OSError(f"不是有效文件: {file_path}")
        
        if not os.access(file_path, os.R_OK):
            raise PermissionError(f"无法读取文件: {file_path}")
    
    def decode_file(self, file_path: str, progress_callback: Optional[ProgressCallback] = None) -> DecodeResult:
        """
        解码PCAP文件，自动选择流式或一次性读取
        
        Args:
            file_path: PCAP文件路径
            progress_callback: 进度回调函数
            
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
            file_size_mb = get_file_size_mb(file_path)
            
            if file_size_mb > self.streaming_threshold_mb:
                logger.info(f"文件大小 ({file_size_mb:.2f}MB) 超过阈值，使用流式读取: {file_path}")
                return self._decode_streaming(file_path, progress_callback)
            else:
                logger.info(f"文件大小 ({file_size_mb:.2f}MB) 未超过阈值，使用一次性读取: {file_path}")
                return self._decode_all_at_once(file_path, progress_callback)
            
        except Exception as e:
            error_msg = f"解码失败: {e}"
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
    
    def _decode_all_at_once(self, file_path: str, progress_callback: Optional[ProgressCallback] = None) -> DecodeResult:
        """一次性读取并解码整个文件"""
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
                        
                    if progress_callback and (packet_count + 1) % 100 == 0:  # 每处理100个包回调一次
                        progress_callback(packet_count + 1, packet_count)
                    
                except Exception as e:
                    error_msg = f"解析包 {packet_count + 1} 失败: {e}"
                    logger.warning(error_msg)
                    errors.append(error_msg)
                    packet_count += 1
            
            cap.close()
            
            if progress_callback:
                progress_callback(packet_count, packet_count) # 确保最后一次回调被调用
            
        except Scapy_Exception as e:
            raise DecodeError(file_path, "Scapy加载失败", e)
        
        decode_time = time.time() - start_time
        
        return DecodeResult(
            file_path=file_path,
            file_size=file_size,
            packet_count=packet_count,
            packets=packets,
            decode_time=decode_time,
            errors=errors
        )
    
    def _decode_streaming(self, file_path: str, progress_callback: Optional[ProgressCallback] = None) -> DecodeResult:
        """流式读取并解码文件"""
        start_time = time.time()
        packets = []
        
        try:
            with PcapReader(file_path) as pcap_reader:
                self.pcap_reader = pcap_reader
                # 注意：PcapReader 没有简单的方法来预先获取总包数。
                # 如果需要总数用于进度条，需要先迭代一次，这会抵消流式读取的优势。
                # 因此，这里的进度回调将不提供 total。
                for i, scapy_packet in enumerate(pcap_reader):
                    if self.max_packets and i >= self.max_packets:
                        break
                    packets.append(self._process_packet(scapy_packet, i))
                    if progress_callback and (i + 1) % 100 == 0: # 每100个包回调
                        progress_callback(i + 1, -1) # -1 表示总数未知

            if progress_callback:
                progress_callback(len(packets), -1) # 结束时回调

            return DecodeResult(
                file_path=file_path,
                file_size=Path(file_path).stat().st_size,
                packet_count=len(packets),
                packets=packets,
                decode_time=time.time() - start_time,
                errors=[]
            )
        except (Scapy_Exception, EOFError) as e:
            raise DecodeError(file_path, "Scapy流式读取失败", e)
        finally:
            self.cleanup()
            
    def _process_packet(self, scapy_packet: ScapyPacket, index: int) -> PacketInfo:
        """处理单个Scapy包"""
        # 获取基本信息
        timestamp = str(scapy_packet.sniff_time) if hasattr(scapy_packet, 'sniff_time') else 'unknown'
        length = int(scapy_packet.len) if hasattr(scapy_packet, 'len') else 0
        
        # 获取协议层
        layers = []
        protocols = {}
        
        for layer in scapy_packet.layers:
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
            number=index,
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

    def cleanup(self):
        """清理资源"""
        self.pcap_reader = None

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