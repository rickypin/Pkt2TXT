import pytest
import tempfile
import json
from pcap_decoder.core.formatter import JSONFormatter

class TestJSONFormatter:
    def test_format_result(self):
        '''测试结果格式化'''
        formatter = JSONFormatter()
        
        # 创建测试数据
        result_data = {
            'file_path': 'test.pcap',
            'packet_count': 10,
            'packets': []
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            formatter.format_to_file(result_data, f.name)
            
            # 验证文件可以被读取
            with open(f.name, 'r') as read_f:
                loaded_data = json.load(read_f)
                assert loaded_data['file_path'] == 'test.pcap'
                assert loaded_data['packet_count'] == 10
