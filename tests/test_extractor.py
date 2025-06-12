#!/usr/bin/env python3
"""
单元测试: 协议字段提取器
测试各种协议字段的提取功能和摘要生成
"""

import pytest
from unittest.mock import Mock, patch

from pcap_decoder.core.extractor import ProtocolExtractor, ProtocolInfo, ProtocolField
from pcap_decoder.utils.errors import PCAPDecoderError


class TestProtocolExtractor:
    """协议字段提取器单元测试"""
    
    def setup_method(self):
        """测试前置设置"""
        self.extractor = ProtocolExtractor()
        
    def test_extractor_initialization(self):
        """测试提取器初始化"""
        extractor = ProtocolExtractor()
        assert extractor is not None
        
        # 验证支持的协议列表
        supported_protocols = extractor.supported_protocols
        expected_protocols = {
            'ETH', 'IP', 'IPV6', 'TCP', 'UDP', 'TLS', 'SSL', 
            'HTTP', 'HTTPS', 'DNS', 'VLAN', 'MPLS', 'GRE', 'VXLAN', 'ARP'
        }
        assert set(supported_protocols) == expected_protocols
        
    def test_extract_protocol_fields_eth(self):
        """测试以太网协议字段提取"""
        mock_layer = Mock()
        mock_layer.layer_name = 'eth'
        mock_layer.src = '00:11:22:33:44:55'
        mock_layer.dst = 'aa:bb:cc:dd:ee:ff'
        mock_layer.type = '0x0800'
        
        result = self.extractor._extract_protocol_fields(mock_layer, 0)
        
        assert isinstance(result, ProtocolInfo)
        assert result.protocol == 'ETH'
        assert len(result.fields) > 0
        
        # 验证提取的字段
        field_names = [field.name for field in result.fields]
        assert 'src' in field_names
        assert 'dst' in field_names
        assert 'type' in field_names 