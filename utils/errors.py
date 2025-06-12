"""
错误处理模块
定义PCAP解码器的各种异常类型
"""

import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


class PCAPDecoderError(Exception):
    """PCAP解码器基础异常类"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        初始化异常
        
        Args:
            message: 错误信息
            details: 错误详情字典
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.timestamp = None
        
        # 记录错误日志
        logger.error(f"PCAPDecoderError: {message}")
        if details:
            logger.error(f"错误详情: {details}")


class FileError(PCAPDecoderError):
    """文件相关错误"""
    
    def __init__(self, file_path: str, operation: str, original_error: Exception = None):
        """
        初始化文件错误
        
        Args:
            file_path: 文件路径
            operation: 操作类型
            original_error: 原始异常
        """
        message = f"文件操作失败: {operation} - {file_path}"
        details = {
            'file_path': file_path,
            'operation': operation,
            'original_error': str(original_error) if original_error else None,
            'error_type': type(original_error).__name__ if original_error else None
        }
        
        super().__init__(message, details)
        self.file_path = file_path
        self.operation = operation
        self.original_error = original_error


class DecodeError(PCAPDecoderError):
    """解码相关错误"""
    
    def __init__(self, file_path: str, packet_number: Optional[int] = None, 
                 protocol: Optional[str] = None, original_error: Exception = None):
        """
        初始化解码错误
        
        Args:
            file_path: 文件路径
            packet_number: 数据包编号
            protocol: 协议类型
            original_error: 原始异常
        """
        if packet_number:
            message = f"数据包解码失败: 文件 {file_path}, 包 #{packet_number}"
        else:
            message = f"文件解码失败: {file_path}"
            
        if protocol:
            message += f", 协议: {protocol}"
            
        details = {
            'file_path': file_path,
            'packet_number': packet_number,
            'protocol': protocol,
            'original_error': str(original_error) if original_error else None,
            'error_type': type(original_error).__name__ if original_error else None
        }
        
        super().__init__(message, details)
        self.file_path = file_path
        self.packet_number = packet_number
        self.protocol = protocol
        self.original_error = original_error


class ValidationError(PCAPDecoderError):
    """验证相关错误"""
    
    def __init__(self, validation_type: str, expected: Any, actual: Any, context: str = ""):
        """
        初始化验证错误
        
        Args:
            validation_type: 验证类型
            expected: 期望值
            actual: 实际值
            context: 上下文信息
        """
        message = f"验证失败: {validation_type}"
        if context:
            message += f" ({context})"
            
        details = {
            'validation_type': validation_type,
            'expected': expected,
            'actual': actual,
            'context': context
        }
        
        super().__init__(message, details)
        self.validation_type = validation_type
        self.expected = expected
        self.actual = actual
        self.context = context


class ErrorCollector:
    """错误收集器，用于批量处理时收集和管理错误"""
    
    def __init__(self):
        """初始化错误收集器"""
        self.errors = []
        self.warnings = []
        self.file_errors = {}
    
    def add_error(self, error: PCAPDecoderError, file_path: str = None):
        """
        添加错误
        
        Args:
            error: 错误对象
            file_path: 文件路径（可选）
        """
        import time
        
        error_record = {
            'timestamp': time.time(),
            'error': error,
            'message': error.message,
            'details': error.details,
            'file_path': file_path or error.details.get('file_path'),
            'error_type': type(error).__name__
        }
        
        self.errors.append(error_record)
        
        # 按文件组织错误
        file_key = file_path or error.details.get('file_path', 'unknown')
        if file_key not in self.file_errors:
            self.file_errors[file_key] = []
        self.file_errors[file_key].append(error_record)
    
    def add_warning(self, message: str, file_path: str = None, details: Dict[str, Any] = None):
        """
        添加警告
        
        Args:
            message: 警告信息
            file_path: 文件路径
            details: 详细信息
        """
        import time
        
        warning_record = {
            'timestamp': time.time(),
            'message': message,
            'file_path': file_path,
            'details': details or {}
        }
        
        self.warnings.append(warning_record)
        
        # 记录警告日志
        logger.warning(f"Warning: {message}")
        if file_path:
            logger.warning(f"文件: {file_path}")
    
    def get_error_summary(self) -> Dict[str, Any]:
        """
        获取错误汇总
        
        Returns:
            Dict[str, Any]: 错误汇总信息
        """
        error_types = {}
        for error_record in self.errors:
            error_type = error_record['error_type']
            error_types[error_type] = error_types.get(error_type, 0) + 1
        
        files_with_errors = len(self.file_errors)
        total_errors = len(self.errors)
        total_warnings = len(self.warnings)
        
        return {
            'total_errors': total_errors,
            'total_warnings': total_warnings,
            'files_with_errors': files_with_errors,
            'error_types': error_types,
            'files_affected': list(self.file_errors.keys())
        }
    
    def generate_error_report(self) -> Dict[str, Any]:
        """
        生成详细的错误报告
        
        Returns:
            Dict[str, Any]: 详细错误报告
        """
        from datetime import datetime
        
        return {
            'report_generated': datetime.now().isoformat(),
            'summary': self.get_error_summary(),
            'errors_by_file': {
                file_path: [
                    {
                        'timestamp': error['timestamp'],
                        'message': error['message'],
                        'error_type': error['error_type'],
                        'details': error['details']
                    }
                    for error in errors
                ]
                for file_path, errors in self.file_errors.items()
            },
            'warnings': [
                {
                    'timestamp': w['timestamp'],
                    'message': w['message'],
                    'file_path': w['file_path'],
                    'details': w['details']
                }
                for w in self.warnings
            ],
            'all_errors': [
                {
                    'timestamp': e['timestamp'],
                    'message': e['message'],
                    'error_type': e['error_type'],
                    'file_path': e['file_path'],
                    'details': e['details']
                }
                for e in self.errors
            ]
        }
    
    def has_errors(self) -> bool:
        """检查是否有错误"""
        return len(self.errors) > 0
    
    def has_warnings(self) -> bool:
        """检查是否有警告"""
        return len(self.warnings) > 0
    
    def clear(self):
        """清除所有错误和警告"""
        self.errors.clear()
        self.warnings.clear()
        self.file_errors.clear() 