#!/usr/bin/env python3
"""
集成测试: 端到端PCAP解码流程
测试完整的解码管道，从目录扫描到字段提取
"""

import pytest
import tempfile
import os
import json
from pathlib import Path
from unittest.mock import patch, Mock

from pcap_decoder.core.scanner import DirectoryScanner
from pcap_decoder.core.decoder import PacketDecoder
from pcap_decoder.core.extractor import ProtocolExtractor
from pcap_decoder.core.formatter import JSONFormatter
from pcap_decoder.core.processor import EnhancedBatchProcessor
from pcap_decoder.utils.errors import PCAPDecoderError


class TestIntegration:
    """端到端集成测试"""
    
    def setup_method(self):
        """测试前置设置"""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_root = Path(self.temp_dir.name)
        self.output_dir = self.test_root / "output"
        self.output_dir.mkdir()
        
    def teardown_method(self):
        """测试后清理"""
        self.temp_dir.cleanup()
        
    def create_test_data_structure(self):
        """创建测试数据结构"""
        # 创建测试目录结构
        (self.test_root / "data" / "plain_ip").mkdir(parents=True)
        (self.test_root / "data" / "vlan").mkdir(parents=True)
        (self.test_root / "data" / "empty").mkdir(parents=True)
        
        # 创建模拟PCAP文件
        test_files = [
            "data/plain_ip/test1.pcap",
            "data/plain_ip/test2.pcapng", 
            "data/vlan/vlan_test.pcap",
            "data/vlan/readme.txt"  # 非PCAP文件，应被忽略
        ]
        
        for file_path in test_files:
            file_full_path = self.test_root / file_path
            if file_path.endswith(('.pcap', '.pcapng')):
                # 创建简单的PCAP文件头
                content = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00'
                content += b'\x00\x00\x00\x00\x00\x00\x00\x00'
                content += b'\x00\x00\x04\x00\x01\x00\x00\x00'
                file_full_path.write_bytes(content)
            else:
                file_full_path.write_text("This is not a PCAP file")
                
        return str(self.test_root / "data")
        
    def test_end_to_end_directory_scan_and_decode(self):
        """测试端到端目录扫描和解码"""
        test_data_dir = self.create_test_data_structure()
        
        # 1. 目录扫描
        scanner = DirectoryScanner()
        discovered_files = scanner.scan_directory(test_data_dir)
        
        # 验证发现了正确数量的PCAP文件
        assert len(discovered_files) == 3  # 3个PCAP文件
        
        # 验证只包含PCAP文件
        for file_path in discovered_files:
            assert file_path.endswith(('.pcap', '.pcapng'))
            
        # 2. 使用Mock解码文件
        decoder = PacketDecoder()
        extractor = ProtocolExtractor()
        
        with patch('pyshark.FileCapture') as mock_file_capture:
            # 模拟PyShark返回的包
            mock_packet = Mock()
            mock_packet.layers = ['ETH', 'IP', 'TCP']
            mock_packet.length = 100
            mock_packet.sniff_time = "2024-01-01 12:00:00"
            
            mock_capture = Mock()
            mock_capture.__iter__ = Mock(return_value=iter([mock_packet]))
            mock_file_capture.return_value = mock_capture
            
            # 解码第一个文件
            first_file = discovered_files[0]
            decode_result = decoder.decode_file(first_file)
            
            assert decode_result.packet_count == 1
            assert len(decode_result.packets) == 1
            
            # 提取字段
            mock_packet_with_layers = Mock()
            mock_packet_with_layers.layers = ['ETH', 'IP', 'TCP']
            mock_packet_with_layers.eth = Mock()
            mock_packet_with_layers.eth.src = '00:11:22:33:44:55'
            mock_packet_with_layers.eth.dst = 'aa:bb:cc:dd:ee:ff'
            
            extracted_data = extractor.extract_fields(mock_packet_with_layers)
            assert 'ETH' in extracted_data.protocols if extracted_data else {}
            
    def test_batch_processing_integration(self):
        """测试批量处理集成"""
        test_data_dir = self.create_test_data_structure()
        
        with patch('pyshark.FileCapture') as mock_file_capture:
            # 模拟成功的解码
            mock_packet = Mock()
            mock_packet.layers = ['ETH', 'IP', 'TCP']
            mock_packet.length = 100
            mock_packet.sniff_time = "2024-01-01 12:00:00"
            
            mock_capture = Mock()
            mock_capture.__iter__ = Mock(return_value=iter([mock_packet]))
            mock_file_capture.return_value = mock_capture
            
            # 使用批量处理器
            import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            processor = EnhancedBatchProcessor(temp_dir)
            
            # 处理目录
            results = processor.process_directory(
                input_dir=test_data_dir,
                output_dir=str(self.output_dir),
                max_packets=10
            )
            
            # 验证批量处理结果
            assert 'processed_files' in results
            assert 'total_packets' in results
            assert 'errors' in results
            
            # 应该处理了发现的PCAP文件
            assert results['processed_files'] > 0
            
    def test_error_handling_integration(self):
        """测试错误处理集成"""
        test_data_dir = self.create_test_data_structure()
        
        # 创建一个损坏的PCAP文件
        broken_file = self.test_root / "data" / "broken.pcap"
        broken_file.write_bytes(b"invalid pcap content")
        
        with patch('pyshark.FileCapture') as mock_file_capture:
            # 模拟PyShark抛出异常
            mock_file_capture.side_effect = Exception("Corrupted PCAP file")
            
            import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            processor = EnhancedBatchProcessor(temp_dir)
            
            # 处理应该继续，即使有错误文件
            results = processor.process_directory(
                input_dir=test_data_dir,
                output_dir=str(self.output_dir),
                max_packets=10
            )
            
            # 应该记录错误但不崩溃
            assert 'errors' in results
            assert len(results['errors']) > 0
            
    def test_output_format_integration(self):
        """测试输出格式集成"""
        test_data_dir = self.create_test_data_structure()
        
        with patch('pyshark.FileCapture') as mock_file_capture:
            # 模拟完整的包数据
            mock_packet = Mock()
            mock_packet.layers = ['ETH', 'IP', 'TCP']
            mock_packet.length = 100
            mock_packet.sniff_time = "2024-01-01 12:00:00"
            
            # 添加层属性
            mock_packet.eth = Mock()
            mock_packet.eth.src = '00:11:22:33:44:55'
            mock_packet.eth.dst = 'aa:bb:cc:dd:ee:ff'
            
            mock_packet.ip = Mock()
            mock_packet.ip.src = '192.168.1.1'
            mock_packet.ip.dst = '10.0.0.1'
            
            mock_packet.tcp = Mock()
            mock_packet.tcp.srcport = '80'
            mock_packet.tcp.dstport = '12345'
            
            mock_capture = Mock()
            mock_capture.__iter__ = Mock(return_value=iter([mock_packet]))
            mock_file_capture.return_value = mock_capture
            
            # 处理单个文件并验证输出
            scanner = DirectoryScanner()
            decoder = PacketDecoder()
            extractor = ProtocolExtractor()
            import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            formatter = JSONFormatter(temp_dir)
            
            files = scanner.scan_directory(test_data_dir)
            if files:
                first_file = files[0]
                
                # 解码
                decode_result = decoder.decode_file(first_file)
                
                # 提取字段（使用包含层属性的包）
                extracted_data = extractor.extract_fields(mock_packet)
                
                # 格式化输出
                output_data = formatter.format_result(first_file, decode_result, extracted_data)
                
                # 验证输出结构
                assert 'file_info' in output_data
                assert 'packets' in output_data
                assert 'protocols' in output_data
                
                # 验证文件信息
                assert output_data['file_info']['file_path'] == first_file
                assert output_data['file_info']['packet_count'] == 1
                
    def test_multiple_protocol_support(self):
        """测试多协议支持"""
        protocol_test_cases = [
            {
                'name': 'Plain IP/TCP',
                'layers': ['ETH', 'IP', 'TCP'],
                'eth_attrs': {'src': '00:11:22:33:44:55', 'dst': 'aa:bb:cc:dd:ee:ff'},
                'ip_attrs': {'src': '192.168.1.1', 'dst': '10.0.0.1'},
                'tcp_attrs': {'srcport': '80', 'dstport': '12345'}
            },
            {
                'name': 'VLAN',
                'layers': ['ETH', 'VLAN', 'IP', 'TCP'],
                'eth_attrs': {'src': '00:11:22:33:44:55', 'dst': 'aa:bb:cc:dd:ee:ff'},
                'vlan_attrs': {'id': '100', 'pri': '3'},
                'ip_attrs': {'src': '192.168.1.1', 'dst': '10.0.0.1'},
                'tcp_attrs': {'srcport': '80', 'dstport': '12345'}
            },
            {
                'name': 'UDP',
                'layers': ['ETH', 'IP', 'UDP'],
                'eth_attrs': {'src': '00:11:22:33:44:55', 'dst': 'aa:bb:cc:dd:ee:ff'},
                'ip_attrs': {'src': '192.168.1.1', 'dst': '10.0.0.1'},
                'udp_attrs': {'srcport': '53', 'dstport': '12345'}
            }
        ]
        
        extractor = ProtocolExtractor()
        
        for test_case in protocol_test_cases:
            # 创建模拟包
            mock_packet = Mock()
            mock_packet.layers = test_case['layers']
            
            # 设置层属性
            for layer in test_case['layers']:
                layer_name = layer.lower()
                layer_attrs_key = f"{layer_name}_attrs"
                
                if layer_attrs_key in test_case:
                    mock_layer = Mock()
                    for attr_name, attr_value in test_case[layer_attrs_key].items():
                        setattr(mock_layer, attr_name, attr_value)
                    setattr(mock_packet, layer_name, mock_layer)
                    
            # 提取字段
            extracted_data = extractor.extract_fields(mock_packet)
            
            # 验证提取的协议
            for layer in test_case['layers']:
                if f"{layer.lower()}_attrs" in test_case:
                    assert layer in extracted_data.protocols if extracted_data else {}, f"Missing {layer} in {test_case['name']}"
                    
    def test_performance_integration(self):
        """测试性能集成"""
        import time
        
        test_data_dir = self.create_test_data_structure()
        
        with patch('pyshark.FileCapture') as mock_file_capture:
            # 模拟多个包的处理
            mock_packets = []
            for i in range(50):  # 50个包
                mock_packet = Mock()
                mock_packet.layers = ['ETH', 'IP', 'TCP']
                mock_packet.length = 100
                mock_packet.sniff_time = f"2024-01-01 12:00:{i:02d}"
                mock_packets.append(mock_packet)
                
            mock_capture = Mock()
            mock_capture.__iter__ = Mock(return_value=iter(mock_packets))
            mock_file_capture.return_value = mock_capture
            
            import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            processor = EnhancedBatchProcessor(temp_dir)
            
            start_time = time.time()
            results = processor.process_directory(
                input_dir=test_data_dir,
                output_dir=str(self.output_dir),
                max_packets=50
            )
            end_time = time.time()
            
            processing_time = end_time - start_time
            
            # 性能验证
            assert processing_time < 5.0  # 应该在5秒内完成
            assert results['processed_files'] > 0
            
    def test_output_file_generation(self):
        """测试输出文件生成"""
        test_data_dir = self.create_test_data_structure()
        
        with patch('pyshark.FileCapture') as mock_file_capture:
            mock_packet = Mock()
            mock_packet.layers = ['ETH', 'IP', 'TCP']
            mock_packet.length = 100
            mock_packet.sniff_time = "2024-01-01 12:00:00"
            
            mock_capture = Mock()
            mock_capture.__iter__ = Mock(return_value=iter([mock_packet]))
            mock_file_capture.return_value = mock_capture
            
            import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            processor = EnhancedBatchProcessor(temp_dir)
            results = processor.process_directory(
                input_dir=test_data_dir,
                output_dir=str(self.output_dir),
                max_packets=10
            )
            
            # 验证输出文件是否生成
            output_files = list(self.output_dir.glob("*.json"))
            
            # 应该生成了JSON输出文件
            assert len(output_files) > 0
            
            # 验证JSON文件格式
            for json_file in output_files:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    
                # 验证JSON结构
                assert 'file_info' in data
                assert 'packets' in data
                assert isinstance(data['packets'], list)
                
    def test_empty_directory_handling(self):
        """测试空目录处理"""
        empty_dir = self.test_root / "empty_test"
        empty_dir.mkdir()
        
        scanner = DirectoryScanner()
        files = scanner.scan_directory(str(empty_dir))
        
        # 空目录应该返回空列表，不抛异常
        assert files == []
        
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            processor = EnhancedBatchProcessor(temp_dir)
        results = processor.process_directory(
            input_dir=str(empty_dir),
            output_dir=str(self.output_dir),
            max_packets=10
        )
        
        # 空目录处理应该成功，但没有处理文件
        assert results['processed_files'] == 0
        assert len(results['errors']) == 0 