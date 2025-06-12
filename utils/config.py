"""
配置管理模块
处理PCAP解码器的配置参数
"""

import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class DecoderConfig:
    """解码器配置"""
    max_packets: Optional[int] = None
    timeout_seconds: int = 300
    enable_deep_inspection: bool = True
    extract_payload: bool = False
    supported_protocols: List[str] = field(default_factory=lambda: [
        'ETH', 'IP', 'IPV6', 'TCP', 'UDP', 
        'TLS', 'SSL', 'HTTP', 'DNS',
        'VLAN', 'MPLS', 'GRE', 'VXLAN'
    ])


@dataclass
class ProcessingConfig:
    """处理配置"""
    max_workers: int = 1
    batch_size: int = 10
    memory_limit_mb: int = 1024
    enable_progress_bar: bool = True
    verbose: bool = False


@dataclass
class OutputConfig:
    """输出配置"""
    output_format: str = 'json'
    indent_json: bool = True
    compress_output: bool = False
    include_metadata: bool = True
    include_statistics: bool = True


@dataclass
class ErrorHandlingConfig:
    """错误处理配置"""
    continue_on_error: bool = True
    max_errors_per_file: int = 10
    generate_error_report: bool = False
    log_level: str = 'INFO'


class Config:
    """主配置类"""
    
    def __init__(self):
        """初始化配置"""
        self.decoder = DecoderConfig()
        self.processing = ProcessingConfig()
        self.output = OutputConfig()
        self.error_handling = ErrorHandlingConfig()
        
        # 日志配置
        self._setup_logging()
    
    def _setup_logging(self):
        """设置日志配置"""
        log_level = getattr(logging, self.error_handling.log_level.upper(), logging.INFO)
        
        # 配置根日志记录器
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # 设置pyshark日志级别为WARNING以减少噪音
        logging.getLogger('pyshark').setLevel(logging.WARNING)
    
    def update_from_cli_args(self, **kwargs):
        """
        从CLI参数更新配置
        
        Args:
            **kwargs: CLI参数
        """
        # 处理配置
        if 'jobs' in kwargs and kwargs['jobs']:
            self.processing.max_workers = kwargs['jobs']
        
        if 'verbose' in kwargs and kwargs['verbose']:
            self.processing.verbose = kwargs['verbose']
            self.error_handling.log_level = 'DEBUG'
            self._setup_logging()
        
        # 解码器配置
        if 'max_packets' in kwargs and kwargs['max_packets']:
            self.decoder.max_packets = kwargs['max_packets']
        
        # 错误处理配置
        if 'error_report' in kwargs and kwargs['error_report']:
            self.error_handling.generate_error_report = kwargs['error_report']
        
        logger.info(f"配置已更新: workers={self.processing.max_workers}, "
                   f"verbose={self.processing.verbose}, "
                   f"max_packets={self.decoder.max_packets}")
    
    def validate(self, input_dir: str, output_dir: str) -> List[str]:
        """
        验证配置和路径
        
        Args:
            input_dir: 输入目录
            output_dir: 输出目录
            
        Returns:
            List[str]: 验证错误列表
        """
        errors = []
        
        # 验证输入目录
        input_path = Path(input_dir)
        if not input_path.exists():
            errors.append(f"输入目录不存在: {input_dir}")
        elif not input_path.is_dir():
            errors.append(f"输入路径不是目录: {input_dir}")
        
        # 验证输出目录可创建
        output_path = Path(output_dir)
        try:
            output_path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f"无法创建输出目录: {e}")
        
        # 验证处理配置
        if self.processing.max_workers < 1:
            errors.append("并发进程数必须大于0")
        
        if self.processing.max_workers > 32:
            errors.append("并发进程数不建议超过32")
        
        # 验证解码器配置
        if self.decoder.max_packets is not None and self.decoder.max_packets < 1:
            errors.append("最大包数必须大于0")
        
        if self.decoder.timeout_seconds < 1:
            errors.append("超时时间必须大于0")
        
        # 验证内存限制
        if self.processing.memory_limit_mb < 100:
            errors.append("内存限制不应小于100MB")
        
        return errors
    
    def get_summary(self) -> Dict[str, Any]:
        """
        获取配置摘要
        
        Returns:
            Dict[str, Any]: 配置摘要
        """
        return {
            'decoder': {
                'max_packets': self.decoder.max_packets,
                'timeout_seconds': self.decoder.timeout_seconds,
                'enable_deep_inspection': self.decoder.enable_deep_inspection,
                'supported_protocols_count': len(self.decoder.supported_protocols)
            },
            'processing': {
                'max_workers': self.processing.max_workers,
                'batch_size': self.processing.batch_size,
                'memory_limit_mb': self.processing.memory_limit_mb,
                'verbose': self.processing.verbose
            },
            'output': {
                'format': self.output.output_format,
                'include_metadata': self.output.include_metadata,
                'include_statistics': self.output.include_statistics
            },
            'error_handling': {
                'continue_on_error': self.error_handling.continue_on_error,
                'max_errors_per_file': self.error_handling.max_errors_per_file,
                'generate_error_report': self.error_handling.generate_error_report,
                'log_level': self.error_handling.log_level
            }
        }
    
    def save_to_file(self, config_path: str):
        """
        保存配置到文件
        
        Args:
            config_path: 配置文件路径
        """
        import json
        
        config_data = self.get_summary()
        
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"配置已保存到: {config_path}")
            
        except Exception as e:
            logger.error(f"保存配置文件失败: {e}")
            raise
    
    def load_from_file(self, config_path: str):
        """
        从文件加载配置
        
        Args:
            config_path: 配置文件路径
        """
        import json
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            # 更新配置对象
            if 'decoder' in config_data:
                decoder_config = config_data['decoder']
                self.decoder.max_packets = decoder_config.get('max_packets')
                self.decoder.timeout_seconds = decoder_config.get('timeout_seconds', 300)
                self.decoder.enable_deep_inspection = decoder_config.get('enable_deep_inspection', True)
            
            if 'processing' in config_data:
                processing_config = config_data['processing']
                self.processing.max_workers = processing_config.get('max_workers', 1)
                self.processing.batch_size = processing_config.get('batch_size', 10)
                self.processing.memory_limit_mb = processing_config.get('memory_limit_mb', 1024)
                self.processing.verbose = processing_config.get('verbose', False)
            
            if 'error_handling' in config_data:
                error_config = config_data['error_handling']
                self.error_handling.continue_on_error = error_config.get('continue_on_error', True)
                self.error_handling.max_errors_per_file = error_config.get('max_errors_per_file', 10)
                self.error_handling.generate_error_report = error_config.get('generate_error_report', False)
                self.error_handling.log_level = error_config.get('log_level', 'INFO')
            
            # 重新设置日志
            self._setup_logging()
            
            logger.info(f"配置已从文件加载: {config_path}")
            
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
            raise 