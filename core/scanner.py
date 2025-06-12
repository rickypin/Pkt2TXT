"""
目录扫描器模块
实现两层深度的目录遍历，识别PCAP/PCAPNG文件
"""

import os
from pathlib import Path
from typing import List, Set
import logging

logger = logging.getLogger(__name__)


class DirectoryScanner:
    """目录扫描器，负责发现PCAP/PCAPNG文件"""
    
    # 支持的文件扩展名
    SUPPORTED_EXTENSIONS = {'.pcap', '.pcapng', '.cap'}
    
    def __init__(self):
        self.found_files = []
        self.ignored_files = []
        self.error_paths = []
    
    def scan_directory(self, root_dir: str, max_depth: int = 2) -> List[str]:
        """
        扫描目录，查找PCAP/PCAPNG文件
        
        Args:
            root_dir: 根目录路径
            max_depth: 最大扫描深度 (默认2层)
            
        Returns:
            List[str]: 发现的PCAP文件路径列表
        """
        root_path = Path(root_dir)
        
        if not root_path.exists():
            raise FileNotFoundError(f"目录不存在: {root_dir}")
        
        if not root_path.is_dir():
            raise NotADirectoryError(f"路径不是目录: {root_dir}")
        
        self.found_files = []
        self.ignored_files = []
        self.error_paths = []
        
        self._scan_recursive(root_path, current_depth=0, max_depth=max_depth)
        
        logger.info(f"扫描完成: 发现 {len(self.found_files)} 个PCAP文件")
        if self.ignored_files:
            logger.info(f"忽略 {len(self.ignored_files)} 个非PCAP文件")
        if self.error_paths:
            logger.warning(f"访问失败 {len(self.error_paths)} 个路径")
        
        return sorted(self.found_files)
    
    def _scan_recursive(self, current_path: Path, current_depth: int, max_depth: int):
        """递归扫描目录"""
        
        if current_depth >= max_depth:
            return
        
        try:
            # 获取目录内容
            entries = list(current_path.iterdir())
            
            # 如果是空目录，直接返回
            if not entries:
                logger.debug(f"空目录: {current_path}")
                return
            
            for entry in entries:
                try:
                    if entry.is_file():
                        # 检查文件扩展名
                        if entry.suffix.lower() in self.SUPPORTED_EXTENSIONS:
                            self.found_files.append(str(entry.absolute()))
                            logger.debug(f"发现PCAP文件: {entry}")
                        else:
                            self.ignored_files.append(str(entry.absolute()))
                    
                    elif entry.is_dir():
                        # 递归扫描子目录
                        self._scan_recursive(entry, current_depth + 1, max_depth)
                
                except (PermissionError, OSError) as e:
                    logger.warning(f"无法访问路径 {entry}: {e}")
                    self.error_paths.append(str(entry))
        
        except (PermissionError, OSError) as e:
            logger.error(f"无法访问目录 {current_path}: {e}")
            self.error_paths.append(str(current_path))
    
    def get_scan_statistics(self) -> dict:
        """获取扫描统计信息"""
        return {
            'found_files': len(self.found_files),
            'ignored_files': len(self.ignored_files),
            'error_paths': len(self.error_paths),
            'total_processed': len(self.found_files) + len(self.ignored_files) + len(self.error_paths)
        }
    
    def filter_by_size(self, min_size: int = 0, max_size: int = None) -> List[str]:
        """
        根据文件大小过滤文件列表
        
        Args:
            min_size: 最小文件大小 (字节)
            max_size: 最大文件大小 (字节, None表示无限制)
            
        Returns:
            List[str]: 过滤后的文件列表
        """
        filtered_files = []
        
        for file_path in self.found_files:
            try:
                file_size = Path(file_path).stat().st_size
                if file_size >= min_size:
                    if max_size is None or file_size <= max_size:
                        filtered_files.append(file_path)
            except OSError:
                # 文件可能在扫描后被删除
                continue
        
        return filtered_files 