"""
统计模块基类

定义所有统计项的通用接口和扩展机制
支持插件化的统计项开发
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from ..adapters.schema import DataSchema, PacketSchema


@dataclass
class StatisticsResult:
    """统计结果数据类"""
    name: str                           # 统计项名称
    description: str                    # 统计项描述
    results: Dict[str, Any]             # 统计结果
    metadata: Dict[str, Any]            # 元数据信息
    calculation_time: float = 0.0       # 计算耗时


class StatisticsBase(ABC):
    """统计基类 - 所有统计项的基础接口"""
    
    def __init__(self, name: str, description: str = ""):
        """
        初始化统计项
        
        Args:
            name: 统计项名称
            description: 统计项描述
        """
        self.name = name
        self.description = description
        self.enabled = True
        self.dependencies = []  # 依赖的其他统计项
    
    @abstractmethod
    def calculate(self, data: DataSchema) -> StatisticsResult:
        """
        计算统计结果
        
        Args:
            data: 标准化的数据结构
            
        Returns:
            StatisticsResult: 统计结果
        """
        pass
    
    @abstractmethod
    def get_required_fields(self) -> List[str]:
        """
        获取必需的数据字段
        
        Returns:
            List[str]: 必需字段列表
        """
        pass
    
    def validate_data(self, data: DataSchema) -> bool:
        """
        验证数据是否满足统计要求
        
        Args:
            data: 数据结构
            
        Returns:
            bool: 是否满足要求
        """
        required_fields = self.get_required_fields()
        # 基本验证逻辑
        return len(data.packets) > 0
    
    def get_configuration_schema(self) -> Dict[str, Any]:
        """
        获取配置架构（用于动态配置）
        
        Returns:
            Dict[str, Any]: 配置架构
        """
        return {
            'name': self.name,
            'description': self.description,
            'enabled': self.enabled,
            'required_fields': self.get_required_fields(),
            'dependencies': self.dependencies
        }


class AggregableStatistics(StatisticsBase):
    """可聚合统计基类 - 支持多文件聚合的统计项"""
    
    @abstractmethod
    def aggregate(self, results: List[StatisticsResult]) -> StatisticsResult:
        """
        聚合多个统计结果
        
        Args:
            results: 统计结果列表
            
        Returns:
            StatisticsResult: 聚合后的结果
        """
        pass
    
    def can_aggregate(self, results: List[StatisticsResult]) -> bool:
        """
        检查是否可以聚合
        
        Args:
            results: 统计结果列表
            
        Returns:
            bool: 是否可以聚合
        """
        return all(result.name == self.name for result in results)


class IncrementalStatistics(StatisticsBase):
    """增量统计基类 - 支持增量更新的统计项"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state = {}  # 保存中间状态
    
    @abstractmethod
    def update(self, packet: PacketSchema) -> None:
        """
        增量更新统计状态
        
        Args:
            packet: 新的数据包
        """
        pass
    
    @abstractmethod
    def get_current_result(self) -> StatisticsResult:
        """
        获取当前统计结果
        
        Returns:
            StatisticsResult: 当前结果
        """
        pass
    
    def reset(self) -> None:
        """重置统计状态"""
        self.state = {}


class ParameterizedStatistics(StatisticsBase):
    """参数化统计基类 - 支持运行时参数配置的统计项"""
    
    def __init__(self, *args, **kwargs):
        # 提取参数
        self.parameters = kwargs.pop('parameters', {})
        super().__init__(*args, **kwargs)
    
    def set_parameter(self, key: str, value: Any) -> None:
        """
        设置参数
        
        Args:
            key: 参数名
            value: 参数值
        """
        self.parameters[key] = value
    
    def get_parameter(self, key: str, default: Any = None) -> Any:
        """
        获取参数值
        
        Args:
            key: 参数名
            default: 默认值
            
        Returns:
            Any: 参数值
        """
        return self.parameters.get(key, default)
    
    @abstractmethod
    def get_parameter_schema(self) -> Dict[str, Any]:
        """
        获取参数配置架构
        
        Returns:
            Dict[str, Any]: 参数架构
        """
        pass


class StatisticsRegistry:
    """统计项注册表 - 管理所有可用的统计项"""
    
    def __init__(self):
        self._statistics = {}
        self._categories = {}
    
    def register(self, statistics_class: type, category: str = "general") -> None:
        """
        注册统计项
        
        Args:
            statistics_class: 统计项类
            category: 统计类别
        """
        # 创建临时实例获取名称
        temp_instance = statistics_class()
        name = temp_instance.name
        
        self._statistics[name] = statistics_class
        
        if category not in self._categories:
            self._categories[category] = []
        self._categories[category].append(name)
    
    def get_statistics(self, name: str) -> Optional[type]:
        """
        获取统计项类
        
        Args:
            name: 统计项名称
            
        Returns:
            Optional[type]: 统计项类
        """
        return self._statistics.get(name)
    
    def get_category_statistics(self, category: str) -> List[str]:
        """
        获取指定类别的统计项
        
        Args:
            category: 类别名称
            
        Returns:
            List[str]: 统计项名称列表
        """
        return self._categories.get(category, [])
    
    def list_all_statistics(self) -> Dict[str, List[str]]:
        """
        列出所有统计项
        
        Returns:
            Dict[str, List[str]]: 按类别组织的统计项
        """
        return self._categories.copy()
    
    def create_instance(self, name: str, *args, **kwargs) -> Optional[StatisticsBase]:
        """
        创建统计项实例
        
        Args:
            name: 统计项名称
            *args, **kwargs: 构造参数
            
        Returns:
            Optional[StatisticsBase]: 统计项实例
        """
        statistics_class = self.get_statistics(name)
        if statistics_class:
            return statistics_class(*args, **kwargs)
        return None


# 全局注册表实例
statistics_registry = StatisticsRegistry() 