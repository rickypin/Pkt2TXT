"""
JSON数据适配器

负责读取和解析现有PCAP解码器的JSON输出
提供统一的数据接口供统计模块使用
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Iterator, Optional, Union
from .schema import DataSchema, DataValidator

logger = logging.getLogger(__name__)


class JSONDataAdapter:
    """JSON数据适配器"""
    
    def __init__(self, validate_data: bool = True):
        """
        初始化适配器
        
        Args:
            validate_data: 是否验证输入数据的完整性
        """
        self.validate_data = validate_data
        self.validator = DataValidator()
    
    def load_single_file(self, file_path: Union[str, Path]) -> DataSchema:
        """
        加载单个JSON文件
        
        Args:
            file_path: JSON文件路径
            
        Returns:
            DataSchema: 标准化的数据结构
            
        Raises:
            FileNotFoundError: 文件不存在
            ValueError: 数据格式不正确
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"数据文件不存在: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                json_data = json.load(f)
            
            # 数据验证
            if self.validate_data:
                self._validate_json_data(json_data, file_path)
            
            # 转换为标准化格式
            data_schema = DataSchema.from_json_data(json_data)
            
            logger.info(f"成功加载数据文件: {file_path} ({data_schema.file_info.packet_count} 包)")
            return data_schema
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON解析错误 {file_path}: {e}")
            raise ValueError(f"无效的JSON格式: {e}")
        except Exception as e:
            logger.error(f"加载数据文件失败 {file_path}: {e}")
            raise
    
    def load_batch_files(self, file_paths: List[Union[str, Path]]) -> Iterator[DataSchema]:
        """
        批量加载多个JSON文件
        
        Args:
            file_paths: JSON文件路径列表
            
        Yields:
            DataSchema: 每个文件的标准化数据结构
        """
        for file_path in file_paths:
            try:
                yield self.load_single_file(file_path)
            except Exception as e:
                logger.warning(f"跳过无法加载的文件 {file_path}: {e}")
                continue
    
    def scan_directory(self, directory: Union[str, Path], pattern: str = "*.json") -> List[Path]:
        """
        扫描目录中的JSON文件（递归搜索）
        
        Args:
            directory: 目录路径
            pattern: 文件匹配模式
            
        Returns:
            List[Path]: JSON文件路径列表
        """
        directory = Path(directory)
        
        if not directory.exists():
            logger.warning(f"目录不存在: {directory}")
            return []
        
        # 使用 rglob 进行递归搜索
        json_files = list(directory.rglob(pattern))
        logger.info(f"在目录 {directory} 中找到 {len(json_files)} 个JSON文件")
        
        return sorted(json_files)
    
    def get_file_summary(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """
        获取文件摘要信息（不完整加载文件）
        
        Args:
            file_path: JSON文件路径
            
        Returns:
            Dict[str, Any]: 文件摘要信息
        """
        file_path = Path(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # 只读取必要的元数据，避免加载所有包数据
                json_data = json.load(f)
            
            summary = {
                'file_path': str(file_path),
                'file_size_mb': file_path.stat().st_size / (1024 * 1024),
                'metadata': json_data.get('metadata', {}),
                'file_info': json_data.get('file_info', {}),
                'protocol_statistics': json_data.get('protocol_statistics', {}),
                'packet_count': len(json_data.get('packets', [])),
                'has_errors': 'errors' in json_data
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"获取文件摘要失败 {file_path}: {e}")
            return {
                'file_path': str(file_path),
                'error': str(e)
            }
    
    def _validate_json_data(self, json_data: Dict[str, Any], file_path: Path):
        """
        验证JSON数据的完整性
        
        Args:
            json_data: JSON数据字典
            file_path: 文件路径（用于错误报告）
            
        Raises:
            ValueError: 数据格式不正确
        """
        if not self.validator.validate_file_data(json_data):
            errors = self.validator.get_validation_errors(json_data)
            error_msg = f"数据格式验证失败 {file_path}:\n" + "\n".join(f"  - {error}" for error in errors)
            raise ValueError(error_msg)
    
    def get_compatible_version(self, metadata: Dict[str, Any]) -> Optional[str]:
        """
        检查数据格式版本兼容性
        
        Args:
            metadata: 元数据字典
            
        Returns:
            Optional[str]: 兼容的格式版本，如果不兼容则返回None
        """
        format_version = metadata.get('format_version', '1.0.0')
        decoder_version = metadata.get('decoder_version', '1.0.0')
        
        # 定义兼容的版本范围
        compatible_format_versions = ['1.0.0', '1.1.0']
        compatible_decoder_versions = ['1.0.0']
        
        if (format_version in compatible_format_versions and 
            decoder_version in compatible_decoder_versions):
            return format_version
        
        return None


class StreamingJSONAdapter(JSONDataAdapter):
    """流式JSON适配器，用于处理大型JSON文件"""
    
    def __init__(self, chunk_size: int = 1000, **kwargs):
        """
        初始化流式适配器
        
        Args:
            chunk_size: 每次处理的包数量
        """
        super().__init__(**kwargs)
        self.chunk_size = chunk_size
    
    def load_packets_stream(self, file_path: Union[str, Path]) -> Iterator[List[Dict[str, Any]]]:
        """
        流式加载数据包
        
        Args:
            file_path: JSON文件路径
            
        Yields:
            List[Dict[str, Any]]: 数据包批次
        """
        file_path = Path(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                json_data = json.load(f)
            
            packets = json_data.get('packets', [])
            
            # 分批返回数据包
            for i in range(0, len(packets), self.chunk_size):
                chunk = packets[i:i + self.chunk_size]
                yield chunk
                
        except Exception as e:
            logger.error(f"流式加载失败 {file_path}: {e}")
            raise 