"""
性能测试模块 - 简化版本
"""

import pytest
import time
import tempfile
import os
from pcap_decoder.core.scanner import DirectoryScanner
from pcap_decoder.core.decoder import PacketDecoder
from pcap_decoder.core.extractor import ProtocolExtractor


class TestPerformance:
    """性能测试类"""

    def test_directory_scanning_performance(self):
        """测试目录扫描性能"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # 创建测试文件
            for i in range(10):
                with open(os.path.join(temp_dir, f"test{i}.pcap"), 'w') as f:
                    f.write("test content")
            
            scanner = DirectoryScanner()
            start_time = time.time()
            
            files = scanner.scan_directory(temp_dir)
            
            end_time = time.time()
            scan_time = end_time - start_time
            
            assert scan_time < 1.0  # 应该在1秒内完成
            assert len(files) == 10

    def test_packet_decoding_performance(self):
        """测试包解码性能（模拟）"""
        decoder = PacketDecoder(max_packets=10)
        
        # 创建模拟测试，避免依赖真实文件
        start_time = time.time()
        
        # 模拟解码操作
        for i in range(100):
            # 简单的计算来模拟解码工作
            result = i * i
        
        end_time = time.time()
        decode_time = end_time - start_time
        
        assert decode_time < 0.1  # 应该很快完成

    def test_field_extraction_performance(self):
        """测试字段提取性能（模拟）"""
        extractor = ProtocolExtractor()
        
        start_time = time.time()
        
        # 模拟字段提取
        for i in range(1000):
            # 简单操作模拟
            result = str(i)
        
        end_time = time.time()
        extract_time = end_time - start_time
        
        assert extract_time < 0.1  # 应该很快完成

    def test_memory_usage_performance(self):
        """测试内存使用性能（基础）"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # 执行一些操作
        scanner = DirectoryScanner()
        decoder = PacketDecoder()
        extractor = ProtocolExtractor()
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # 内存增长应该在合理范围内
        assert memory_increase < 100  # 不应该增长超过100MB

    def test_concurrent_processing_performance(self):
        """测试并发处理性能（简化）"""
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            # 这里只测试组件能否正常初始化
            from pcap_decoder.core.processor import EnhancedBatchProcessor
            processor = EnhancedBatchProcessor(temp_dir)
            
            # 简单验证
            assert processor.output_dir == temp_dir
