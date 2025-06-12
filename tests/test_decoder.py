#!/usr/bin/env python3
"""
单元测试: PacketDecoder
测试PCAP文件解码器的所有功能，包括各种协议和错误处理
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock, Mock

from pcap_decoder.core.decoder import PacketDecoder, DecodeResult
from pcap_decoder.utils.errors import FileError, DecodeError


class TestPacketDecoder:
    """PacketDecoder单元测试"""
    
    def setup_method(self):
        """测试前置设置"""
        self.decoder = PacketDecoder()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_root = Path(self.temp_dir.name)
        
    def teardown_method(self):
        """测试后清理"""
        self.temp_dir.cleanup()
        
    def create_dummy_pcap_file(self, filename="test.pcap", content=None):
        """创建测试用的PCAP文件"""
        test_file = self.test_root / filename
        if content is None:
            # 创建基本的PCAP文件头（简化版）
            content = b'\xd4\xc3\xb2\xa1'  # PCAP magic number
            content += b'\x02\x00\x04\x00'  # 版本和其他头部信息
            content += b'\x00\x00\x00\x00\x00\x00\x00\x00'  # 时间戳和长度字段
            content += b'\x00\x00\x04\x00\x01\x00\x00\x00'  # 数据链路类型
        test_file.write_bytes(content)
        return str(test_file)
        
    def test_decoder_initialization(self):
        """测试解码器初始化"""
        decoder = PacketDecoder()
        assert decoder is not None
        
        # 测试可以创建多个实例
        decoder2 = PacketDecoder()
        assert decoder2 is not None
        assert decoder is not decoder2
        
    def test_decode_file_nonexistent(self):
        """测试解码不存在的文件"""
        nonexistent_file = str(self.test_root / "nonexistent.pcap")
        
        with pytest.raises(FileError):
            try:
            self.decoder.decode_file(nonexistent_file)
            assert False, "应该抛出异常"
        except (FileNotFoundError, OSError):
            pass  # 预期的异常
            
    def test_decode_file_not_pcap(self):
        """测试解码非PCAP文件"""
        text_file = self.test_root / "test.txt"
        text_file.write_text("这不是PCAP文件")
        
        result = self.decoder.decode_file(str(text_file)
        assert len(result.errors) > 0  # 应该有错误)
            
    def test_decode_file_empty_file(self):
        """测试解码空文件"""
        empty_file = self.test_root / "empty.pcap"
        empty_file.touch()
        
        result = self.decoder.decode_file(str(empty_file)
        assert len(result.errors) > 0  # 应该有错误)
            
    def test_decode_file_invalid_pcap(self):
        """测试解码损坏的PCAP文件"""
        invalid_file = self.create_dummy_pcap_file("invalid.pcap", b"invalid pcap data")
        
        result = self.decoder.decode_file(invalid_file)
        assert len(result.errors) > 0  # 应该有错误
            
    @patch('pyshark.FileCapture')
    def test_decode_file_pyshark_success(self, mock_file_capture):
        """测试PyShark成功解码"""
        # 模拟PyShark解码结果
        mock_packet1 = Mock()
        mock_packet1.layers = ['ETH', 'IP', 'TCP']
        mock_packet1.length = 100
        mock_packet1.sniff_time = "2024-01-01 12:00:00"
        
        mock_packet2 = Mock()
        mock_packet2.layers = ['ETH', 'IP', 'UDP']
        mock_packet2.length = 80
        mock_packet2.sniff_time = "2024-01-01 12:00:01"
        
        mock_capture = Mock()
        mock_capture.__iter__ = Mock(return_value=iter([mock_packet1, mock_packet2]))
        mock_capture.__len__ = Mock(return_value=2)
        mock_file_capture.return_value = mock_capture
        
        test_file = self.create_dummy_pcap_file()
        result = self.decoder.decode_file(test_file)
        
        # 验证结果
        assert isinstance(result, DecodeResult)
        assert len(result.packets) == 2
        assert result.file_path == test_file
        assert result.packet_count == 2
        assert len(result.errors) == 0
        
    @patch('pyshark.FileCapture')
    def test_decode_file_with_max_packets(self, mock_file_capture):
        """测试限制最大包数量解码"""
        # 模拟5个包
        mock_packets = []
        for i in range(5):
            mock_packet = Mock()
            mock_packet.layers = ['ETH', 'IP', 'TCP']
            mock_packet.length = 100 + i
            mock_packet.sniff_time = f"2024-01-01 12:00:{i:02d}"
            mock_packets.append(mock_packet)
            
        mock_capture = Mock()
        mock_capture.__iter__ = Mock(return_value=iter(mock_packets))
        mock_file_capture.return_value = mock_capture
        
        test_file = self.create_dummy_pcap_file()
        result = decoder = PacketDecoder(max_packets=3)
        result = decoder.decode_file(test_file)
        
        # 应该只处理3个包
        assert len(result.packets) == 3
        assert result.packet_count == 3
        
    @patch('pyshark.FileCapture')
    def test_decode_file_pyshark_exception(self, mock_file_capture):
        """测试PyShark抛出异常"""
        mock_file_capture.side_effect = Exception("PyShark解码失败")
        
        test_file = self.create_dummy_pcap_file()
        
        result = self.decoder.decode_file(test_file)
        assert len(result.errors) > 0  # 应该有错误
            
    @patch('pyshark.FileCapture')
    def test_decode_file_partial_packet_errors(self, mock_file_capture):
        """测试部分包解码错误"""
        # 模拟一些正常包和一些错误包
        mock_packet1 = Mock()
        mock_packet1.layers = ['ETH', 'IP', 'TCP']
        mock_packet1.length = 100
        mock_packet1.sniff_time = "2024-01-01 12:00:00"
        
        # 错误包（缺少属性）
        mock_packet2 = Mock()
        mock_packet2.layers = ['ETH', 'IP']
        mock_packet2.length = None  # 这会导致错误
        
        mock_packet3 = Mock()
        mock_packet3.layers = ['ETH', 'IP', 'UDP']
        mock_packet3.length = 80
        mock_packet3.sniff_time = "2024-01-01 12:00:02"
        
        mock_capture = Mock()
        mock_capture.__iter__ = Mock(return_value=iter([mock_packet1, mock_packet2, mock_packet3]))
        mock_file_capture.return_value = mock_capture
        
        test_file = self.create_dummy_pcap_file()
        result = self.decoder.decode_file(test_file)
        
        # 应该成功处理2个包，1个包有错误
        assert len(result.packets) == 2  # 只有正常的包
        assert len(result.errors) == 1   # 一个错误
        
    def test_validate_file_exists(self):
        """测试文件存在性验证"""
        # 存在的文件
        test_file = self.create_dummy_pcap_file()
        self.decoder._validate_file(test_file)  # 不应抛异常
        
        # 不存在的文件
        nonexistent = str(self.test_root / "nonexistent.pcap")
        with pytest.raises(FileError):
            self.decoder._validate_file(nonexistent)
            
    def test_validate_file_readable(self):
        """测试文件可读性验证"""
        test_file = self.create_dummy_pcap_file()
        
        if os.name == 'posix':
            # 移除读权限
            os.chmod(test_file, 0o000)
            try:
                with pytest.raises(FileError):
                    self.decoder._validate_file(test_file)
            finally:
                # 恢复权限
                os.chmod(test_file, 0o644)
        else:
            # Windows系统跳过权限测试
            pytest.skip("权限测试仅在Unix系统运行")
            
    def test_parse_packet_normal(self):
        """测试正常包处理"""
        mock_packet = Mock()
        mock_packet.layers = ['ETH', 'IP', 'TCP']
        mock_packet.length = 100
        mock_packet.sniff_time = "2024-01-01 12:00:00"
        
        packet_info = self.decoder._parse_packet(mock_packet, 0)
        
        assert packet_info is not None
        assert 'index' in packet_info
        assert 'layers' in packet_info
        assert 'length' in packet_info
        assert 'timestamp' in packet_info
        
    def test_parse_packet_missing_attributes(self):
        """测试缺少属性的包处理"""
        mock_packet = Mock()
        mock_packet.layers = ['ETH', 'IP']
        # 故意不设置length和sniff_time
        del mock_packet.length
        del mock_packet.sniff_time
        
        packet_info = self.decoder._parse_packet(mock_packet, 0)
        
        # 应该返回None（处理失败）
        assert packet_info is None
        
    def test_parse_packet_exception(self):
        """测试包处理异常"""
        mock_packet = Mock()
        mock_packet.layers = Mock(side_effect=Exception("包处理错误"))
        
        packet_info = self.decoder._parse_packet(mock_packet, 0)
        
        # 应该返回None（处理失败）
        assert packet_info is None
        
    def test_decoding_result_initialization(self):
        """测试DecodeResult初始化"""
        result = DecodeResult("test.pcap")
        
        assert result.file_path == "test.pcap"
        assert result.packets == []
        assert result.errors == []
        assert result.packet_count == 0
        assert result.start_time is not None
        assert result.end_time is None
        
    def test_decoding_result_add_packet(self):
        """测试添加包到结果"""
        result = DecodeResult("test.pcap")
        
        packet_info = {
            'index': 0,
            'layers': ['ETH', 'IP', 'TCP'],
            'length': 100,
            'timestamp': '2024-01-01 12:00:00'
        }
        
        result.add_packet(packet_info)
        
        assert len(result.packets) == 1
        assert result.packet_count == 1
        assert result.packets[0] == packet_info
        
    def test_decoding_result_add_error(self):
        """测试添加错误到结果"""
        result = DecodeResult("test.pcap")
        
        error_info = {
            'packet_index': 5,
            'error_type': 'DecodeError',
            'message': '包解码失败'
        }
        
        result.add_error(error_info)
        
        assert len(result.errors) == 1
        assert result.errors[0] == error_info
        
    def test_decoding_result_finalize(self):
        """测试结果完成"""
        result = DecodeResult("test.pcap")
        
        # 添加一些数据
        result.add_packet({'index': 0, 'layers': ['ETH']})
        result.add_packet({'index': 1, 'layers': ['ETH']})
        result.add_error({'packet_index': 2, 'error': 'test'})
        
        result.finalize()
        
        assert result.end_time is not None
        assert result.packet_count == 2
        
    @patch('pyshark.FileCapture')
    def test_decode_file_large_file_simulation(self, mock_file_capture):
        """测试大文件解码模拟"""
        # 模拟大量包
        large_packet_count = 1000
        mock_packets = []
        
        for i in range(large_packet_count):
            mock_packet = Mock()
            mock_packet.layers = ['ETH', 'IP', 'TCP']
            mock_packet.length = 100
            mock_packet.sniff_time = f"2024-01-01 12:{i//60:02d}:{i%60:02d}"
            mock_packets.append(mock_packet)
            
        mock_capture = Mock()
        mock_capture.__iter__ = Mock(return_value=iter(mock_packets))
        mock_file_capture.return_value = mock_capture
        
        test_file = self.create_dummy_pcap_file()
        result = decoder = PacketDecoder(max_packets=100)
        result = decoder.decode_file(test_file)
        
        # 应该只处理100个包（受max_packets限制）
        assert len(result.packets) == 100
        assert result.packet_count == 100
        
    def test_decode_file_various_protocols(self):
        """测试各种协议处理"""
        protocols_to_test = [
            ['ETH', 'IP', 'TCP'],
            ['ETH', 'IP', 'UDP'],
            ['ETH', 'VLAN', 'IP', 'TCP'],
            ['ETH', 'IP', 'ICMP'],
            ['ETH', 'ARP'],
            ['ETH', 'IP', 'TCP', 'TLS'],
        ]
        
        with patch('pyshark.FileCapture') as mock_file_capture:
            for i, protocol_stack in enumerate(protocols_to_test):
                mock_packet = Mock()
                mock_packet.layers = protocol_stack
                mock_packet.length = 100 + i
                mock_packet.sniff_time = f"2024-01-01 12:00:{i:02d}"
                
                mock_capture = Mock()
                mock_capture.__iter__ = Mock(return_value=iter([mock_packet]))
                mock_file_capture.return_value = mock_capture
                
                test_file = self.create_dummy_pcap_file(f"test_{i}.pcap")
                result = self.decoder.decode_file(test_file)
                
                assert len(result.packets) == 1
                assert result.packets[0]['layers'] == protocol_stack
                
    def test_decode_file_performance_timing(self):
        """测试解码性能"""
        import time
        
        with patch('pyshark.FileCapture') as mock_file_capture:
            # 模拟少量包以确保快速完成
            mock_packet = Mock()
            mock_packet.layers = ['ETH', 'IP', 'TCP']
            mock_packet.length = 100
            mock_packet.sniff_time = "2024-01-01 12:00:00"
            
            mock_capture = Mock()
            mock_capture.__iter__ = Mock(return_value=iter([mock_packet] * 10))
            mock_file_capture.return_value = mock_capture
            
            test_file = self.create_dummy_pcap_file()
            
            start_time = time.time()
            result = self.decoder.decode_file(test_file)
            end_time = time.time()
            
            decode_time = end_time - start_time
            
            # 模拟解码应该很快
            assert decode_time < 1.0
            assert len(result.packets) == 10 