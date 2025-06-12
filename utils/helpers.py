"""
通用辅助函数模块
"""

import os
import logging
from typing import Union
from pathlib import Path

logger = logging.getLogger(__name__)

def get_file_size_mb(file_path: Union[str, Path]) -> float:
    """
    获取文件大小（MB）
    
    Args:
        file_path: 文件路径
        
    Returns:
        float: 文件大小（MB）
    """
    try:
        size_bytes = os.path.getsize(file_path)
        return size_bytes / (1024 * 1024)
    except OSError as e:
        logger.error(f"无法获取文件大小: {file_path}, 错误: {e}")
        return 0.0 