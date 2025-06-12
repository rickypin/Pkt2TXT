"""
协议字段提取器模块
负责从PyShark解析的数据包中提取详细的协议字段信息
"""

import logging
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass
import pyshark

logger = logging.getLogger(__name__)


@dataclass
class ProtocolField:
    """协议字段信息"""
    name: str
    value: Any
    description: Optional[str] = None
    field_type: Optional[str] = None
    raw_value: Optional[str] = None


@dataclass
class ProtocolInfo:
    """协议信息"""
    protocol: str
    layer_index: int
    fields: List[ProtocolField]
    summary: Optional[str] = None


class ProtocolExtractor:
    """协议字段提取器"""
    
    def __init__(self):
        """初始化提取器"""
        self.supported_protocols = {
            'ETH', 'IP', 'IPV6', 'TCP', 'UDP', 
            'TLS', 'SSL', 'HTTP', 'HTTPS', 'DNS',
            'VLAN', 'MPLS', 'GRE', 'VXLAN', 'ARP'
        }
        
        # 协议专用字段映射
        self.protocol_fields = {
            'ETH': ['src', 'dst', 'type'],
            'IP': ['src', 'dst', 'version', 'proto', 'len', 'ttl', 'flags'],
            'TCP': ['srcport', 'dstport', 'seq', 'ack', 'window', 'flags'],
            'UDP': ['srcport', 'dstport', 'length', 'checksum'],
            'VLAN': ['id', 'priority', 'type'],
            'TLS': ['version', 'content_type', 'length'],
            'DNS': ['qry_name', 'qry_type', 'flags']
        }
    
    def extract_fields(self, packet_data):
        """
        从单个数据包对象中提取协议字段信息
        
        Args:
            packet_data: 数据包对象（来自DecodeResult.packets）
            
        Returns:
            None: 直接修改packet_data.protocols字典
        """
        try:
            # 检查packet_data是否有protocols属性
            if not hasattr(packet_data, 'protocols'):
                logger.warning("数据包对象缺少protocols属性")
                return
                
            # 为每个协议提取详细字段
            for protocol_name in packet_data.protocols.keys():
                if protocol_name in self.supported_protocols:
                    # 这里只是增强现有的协议信息，不重新解析
                    # 因为实际的协议解析已经在decoder中完成了
                    self._enhance_protocol_info(packet_data.protocols[protocol_name], protocol_name)
                    
        except Exception as e:
            logger.error(f"提取数据包字段失败: {e}")
    
    def _enhance_protocol_info(self, protocol_data: dict, protocol_name: str):
        """
        增强协议信息
        
        Args:
            protocol_data: 协议数据字典
            protocol_name: 协议名称
        """
        try:
            # 确保有fields字段
            if 'fields' not in protocol_data:
                protocol_data['fields'] = {}
            
            # 可以在这里添加更多的字段处理逻辑
            # 例如字段验证、类型转换、格式化等
            
            # 添加协议特定的元数据
            protocol_data['enhanced'] = True
            protocol_data['extractor_version'] = '1.0.0'
            
        except Exception as e:
            logger.debug(f"增强协议信息失败 {protocol_name}: {e}")
    
    def extract_from_file(self, file_path: str, max_packets: int = 10) -> List[ProtocolInfo]:
        """
        从文件中提取协议信息
        
        Args:
            file_path: PCAP文件路径
            max_packets: 最大处理包数
            
        Returns:
            List[ProtocolInfo]: 协议信息列表
        """
        protocols = []
        
        try:
            cap = pyshark.FileCapture(file_path)
            
            packet_count = 0
            for packet in cap:
                if packet_count >= max_packets:
                    break
                    
                for i, layer in enumerate(packet.layers):
                    protocol_info = self._extract_protocol_fields(layer, i)
                    if protocol_info:
                        protocols.append(protocol_info)
                
                packet_count += 1
                # 只处理第一个包进行快速验证
                break
            
            cap.close()
            
        except Exception as e:
            logger.error(f"提取协议信息失败: {e}")
        
        return protocols
    
    def _extract_protocol_fields(self, layer, layer_index: int) -> Optional[ProtocolInfo]:
        """
        提取单个协议层的字段信息
        
        Args:
            layer: PyShark协议层对象
            layer_index: 层索引
            
        Returns:
            Optional[ProtocolInfo]: 协议信息
        """
        protocol_name = layer.layer_name.upper()
        
        if protocol_name not in self.supported_protocols:
            logger.debug(f"不支持的协议: {protocol_name}")
            return None
        
        fields = []
        
        try:
            # 使用协议专用字段提取方法
            if protocol_name in self.protocol_fields:
                fields.extend(self._extract_specific_fields(layer, protocol_name))
            
            # 通用字段提取
            fields.extend(self._extract_generic_fields(layer))
            
            # 获取协议摘要
            summary = self._get_protocol_summary(layer, protocol_name)
            
        except Exception as e:
            logger.warning(f"提取协议字段失败 {protocol_name}: {e}")
            fields = [ProtocolField(name="error", value=str(e), field_type="error")]
            summary = None
        
        return ProtocolInfo(
            protocol=protocol_name,
            layer_index=layer_index,
            fields=fields,
            summary=summary
        )
    
    def _extract_specific_fields(self, layer, protocol: str) -> List[ProtocolField]:
        """提取协议专用字段"""
        fields = []
        target_fields = self.protocol_fields.get(protocol, [])
        
        for field_name in target_fields:
            try:
                if hasattr(layer, field_name):
                    value = getattr(layer, field_name)
                    if value is not None:
                        field = ProtocolField(
                            name=field_name,
                            value=str(value),
                            field_type=type(value).__name__,
                            description=f"{protocol}协议{field_name}字段"
                        )
                        fields.append(field)
            except Exception as e:
                logger.debug(f"提取{protocol}.{field_name}失败: {e}")
                continue
        
        return fields
    
    def _extract_generic_fields(self, layer) -> List[ProtocolField]:
        """提取通用字段"""
        fields = []
        
        try:
            # 获取层的所有属性
            field_names = [attr for attr in dir(layer) 
                          if not attr.startswith('_') and not callable(getattr(layer, attr))]
            
            for field_name in field_names[:10]:  # 限制字段数量
                try:
                    value = getattr(layer, field_name)
                    if value is not None and isinstance(value, (str, int, float)):
                        field = ProtocolField(
                            name=field_name,
                            value=str(value),
                            field_type=type(value).__name__
                        )
                        fields.append(field)
                except:
                    continue
                    
        except Exception as e:
            logger.debug(f"通用字段提取失败: {e}")
        
        return fields
    
    def _get_protocol_summary(self, layer, protocol: str) -> Optional[str]:
        """获取协议摘要信息"""
        try:
            if protocol == 'IP' and hasattr(layer, 'src') and hasattr(layer, 'dst'):
                return f"{layer.src} -> {layer.dst}"
            elif protocol == 'TCP' and hasattr(layer, 'srcport') and hasattr(layer, 'dstport'):
                return f"Port {layer.srcport} -> {layer.dstport}"
            elif protocol == 'VLAN' and hasattr(layer, 'id'):
                return f"VLAN ID: {layer.id}"
            elif hasattr(layer, '_layer_name'):
                return f"{protocol} Layer"
        except:
            pass
        
        return None
    
    def get_protocol_statistics(self, protocols: List[ProtocolInfo]) -> Dict[str, int]:
        """
        获取协议统计信息
        
        Args:
            protocols: 协议信息列表
            
        Returns:
            Dict[str, int]: 协议统计
        """
        stats = {}
        for protocol in protocols:
            stats[protocol.protocol] = stats.get(protocol.protocol, 0) + 1
        return stats
    
    def format_protocol_info(self, protocols: List[ProtocolInfo]) -> str:
        """格式化协议信息为可读字符串"""
        output = []
        
        for proto in protocols:
            output.append(f"\n=== {proto.protocol} (Layer {proto.layer_index}) ===")
            if proto.summary:
                output.append(f"摘要: {proto.summary}")
            
            output.append("字段:")
            for field in proto.fields[:5]:  # 限制显示字段数
                output.append(f"  {field.name}: {field.value}")
        
        return "\n".join(output) 