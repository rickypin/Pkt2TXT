import pytest
import tempfile
from pcap_decoder.core.processor import EnhancedBatchProcessor

class TestEnhancedBatchProcessor:
    def test_init_with_output_dir(self):
        '''测试处理器正确初始化'''
        with tempfile.TemporaryDirectory() as temp_dir:
            processor = EnhancedBatchProcessor(temp_dir)
            assert processor.output_dir == temp_dir
    
    def test_process_empty_files(self):
        '''测试处理空文件列表'''
        with tempfile.TemporaryDirectory() as temp_dir:
            processor = EnhancedBatchProcessor(temp_dir)
            result = processor.process_files([])
            assert result is not None
