"""
数据适配器模块

负责处理不同数据源的适配和标准化
支持现有JSON输出格式，以及未来可能的其他格式
"""

from .json_adapter import JSONDataAdapter
from .schema import DataSchema, PacketSchema

__all__ = [
    'JSONDataAdapter',
    'DataSchema', 
    'PacketSchema'
] 