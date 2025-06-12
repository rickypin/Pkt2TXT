"""
PyTest配置文件
为PCAP解码器测试提供fixtures和配置
"""

import pytest
import tempfile
import shutil
from pathlib import Path


@pytest.fixture
def temp_dir():
    """创建临时目录fixture"""
    temp_path = tempfile.mkdtemp()
    yield temp_path
    shutil.rmtree(temp_path)


@pytest.fixture
def sample_pcap_files():
    """提供测试PCAP文件列表"""
    # 这个fixture将在有实际测试数据时使用
    return []


@pytest.fixture
def test_config():
    """提供测试配置"""
    from pcap_decoder.utils.config import Config
    
    config = Config()
    config.processing.max_workers = 1  # 测试时使用单进程
    config.processing.verbose = False  # 测试时关闭详细输出
    config.decoder.max_packets = 10    # 测试时限制包数
    
    return config


@pytest.fixture(scope="session")
def test_data_dir():
    """测试数据目录"""
    # 指向PktMask项目的测试数据
    current_dir = Path(__file__).parent
    project_root = current_dir.parent.parent.parent  # 回到PktMask根目录
    test_data_path = project_root / "tests" / "data" / "samples"
    
    if test_data_path.exists():
        return str(test_data_path)
    else:
        # 如果没有找到PktMask的测试数据，返回None
        return None 