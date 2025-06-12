"""
数据聚合器

负责将多个分析结果进行聚合和合并
支持各种聚合策略和自定义聚合规则
"""

import logging
from typing import Dict, List, Any, Optional
from ..stats.base import StatisticsResult, AggregableStatistics

logger = logging.getLogger(__name__)


class DataAggregator:
    """数据聚合器"""
    
    def __init__(self):
        """初始化聚合器"""
        self.aggregation_strategies = {
            'sum': self._sum_aggregation,
            'average': self._average_aggregation,
            'max': self._max_aggregation,
            'min': self._min_aggregation,
            'merge': self._merge_aggregation
        }
    
    def aggregate_statistics_results(self, results_list: List[StatisticsResult], 
                                   strategy: str = 'merge') -> StatisticsResult:
        """
        聚合统计结果
        
        Args:
            results_list: 统计结果列表
            strategy: 聚合策略
            
        Returns:
            StatisticsResult: 聚合后的结果
        """
        if not results_list:
            raise ValueError("结果列表不能为空")
        
        if len(results_list) == 1:
            return results_list[0]
        
        # 检查结果类型一致性
        base_result = results_list[0]
        if not all(r.name == base_result.name for r in results_list):
            raise ValueError("聚合的统计结果必须是同一类型")
        
        # 执行聚合
        aggregation_func = self.aggregation_strategies.get(strategy, self._merge_aggregation)
        aggregated_data = aggregation_func([r.results for r in results_list])
        
        # 合并元数据
        aggregated_metadata = self._merge_metadata([r.metadata for r in results_list])
        
        # 计算总耗时
        total_time = sum(r.calculation_time for r in results_list)
        
        return StatisticsResult(
            name=base_result.name,
            description=base_result.description,
            results=aggregated_data,
            metadata={
                **aggregated_metadata,
                'aggregated_from': len(results_list),
                'aggregation_strategy': strategy
            },
            calculation_time=total_time
        )
    
    def aggregate_analysis_results(self, analysis_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        聚合完整的分析结果
        
        Args:
            analysis_results: 分析结果列表
            
        Returns:
            Dict[str, Any]: 聚合后的分析结果
        """
        if not analysis_results:
            return {}
        
        # 提取所有统计项
        all_statistics = {}
        for result in analysis_results:
            statistics = result.get('statistics', {})
            for stat_name, stat_data in statistics.items():
                if 'error' not in stat_data:
                    if stat_name not in all_statistics:
                        all_statistics[stat_name] = []
                    
                    # 重构StatisticsResult对象
                    stat_result = StatisticsResult(
                        name=stat_data.get('name', stat_name),
                        description=stat_data.get('description', ''),
                        results=stat_data.get('results', {}),
                        metadata=stat_data.get('metadata', {}),
                        calculation_time=stat_data.get('calculation_time', 0.0)
                    )
                    all_statistics[stat_name].append(stat_result)
        
        # 聚合每个统计项
        aggregated_statistics = {}
        for stat_name, stat_results in all_statistics.items():
            try:
                aggregated_result = self.aggregate_statistics_results(stat_results, 'merge')
                aggregated_statistics[stat_name] = aggregated_result.__dict__
            except Exception as e:
                logger.warning(f"聚合统计项 {stat_name} 失败: {e}")
        
        # 合并文件信息
        file_info = self._aggregate_file_info([r.get('file_info', {}) for r in analysis_results])
        
        # 合并元数据
        metadata = self._aggregate_metadata([r.get('metadata', {}) for r in analysis_results])
        
        return {
            'file_info': file_info,
            'statistics': aggregated_statistics,
            'metadata': metadata,
            'aggregation_summary': {
                'total_files': len(analysis_results),
                'aggregated_statistics': len(aggregated_statistics)
            }
        }
    
    def _sum_aggregation(self, data_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """求和聚合"""
        aggregated = {}
        
        for data in data_list:
            for key, value in data.items():
                if isinstance(value, (int, float)):
                    aggregated[key] = aggregated.get(key, 0) + value
                elif isinstance(value, dict):
                    if key not in aggregated:
                        aggregated[key] = {}
                    aggregated[key] = self._sum_aggregation([aggregated.get(key, {}), value])
        
        return aggregated
    
    def _average_aggregation(self, data_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """平均值聚合"""
        summed = self._sum_aggregation(data_list)
        count = len(data_list)
        
        def average_values(data):
            if isinstance(data, dict):
                return {k: average_values(v) for k, v in data.items()}
            elif isinstance(data, (int, float)):
                return data / count
            else:
                return data
        
        return average_values(summed)
    
    def _max_aggregation(self, data_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """最大值聚合"""
        aggregated = {}
        
        for data in data_list:
            for key, value in data.items():
                if isinstance(value, (int, float)):
                    aggregated[key] = max(aggregated.get(key, float('-inf')), value)
                elif isinstance(value, dict) and key in aggregated:
                    aggregated[key] = self._max_aggregation([aggregated[key], value])
                else:
                    aggregated[key] = value
        
        return aggregated
    
    def _min_aggregation(self, data_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """最小值聚合"""
        aggregated = {}
        
        for data in data_list:
            for key, value in data.items():
                if isinstance(value, (int, float)):
                    aggregated[key] = min(aggregated.get(key, float('inf')), value)
                elif isinstance(value, dict) and key in aggregated:
                    aggregated[key] = self._min_aggregation([aggregated[key], value])
                else:
                    aggregated[key] = value
        
        return aggregated
    
    def _merge_aggregation(self, data_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """合并聚合（智能合并不同类型的数据）"""
        aggregated = {}
        
        for data in data_list:
            for key, value in data.items():
                if key not in aggregated:
                    aggregated[key] = value
                else:
                    existing_value = aggregated[key]
                    
                    # 数值相加
                    if isinstance(value, (int, float)) and isinstance(existing_value, (int, float)):
                        aggregated[key] = existing_value + value
                    
                    # 列表合并
                    elif isinstance(value, list) and isinstance(existing_value, list):
                        aggregated[key] = existing_value + value
                    
                    # 字典递归合并
                    elif isinstance(value, dict) and isinstance(existing_value, dict):
                        aggregated[key] = self._merge_aggregation([existing_value, value])
                    
                    # 字符串连接
                    elif isinstance(value, str) and isinstance(existing_value, str):
                        if value != existing_value:
                            aggregated[key] = f"{existing_value}, {value}"
                    
                    # 其他情况保留最新值
                    else:
                        aggregated[key] = value
        
        return aggregated
    
    def _merge_metadata(self, metadata_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """合并元数据"""
        merged = {}
        
        for metadata in metadata_list:
            for key, value in metadata.items():
                if key not in merged:
                    merged[key] = value
                else:
                    # 特殊处理某些字段
                    if key == 'enabled_statistics':
                        # 合并启用的统计项列表
                        if isinstance(value, list) and isinstance(merged[key], list):
                            merged[key] = list(set(merged[key] + value))
                    elif key in ['analysis_timestamp', 'analyzer_version']:
                        # 保留最新的时间戳和版本
                        merged[key] = value
                    else:
                        # 其他情况创建列表保存所有值
                        if not isinstance(merged[key], list):
                            merged[key] = [merged[key]]
                        if value not in merged[key]:
                            merged[key].append(value)
        
        return merged
    
    def _aggregate_file_info(self, file_info_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """聚合文件信息"""
        if not file_info_list:
            return {}
        
        total_packets = sum(info.get('packet_count', 0) for info in file_info_list)
        total_time = sum(info.get('analysis_time', 0) for info in file_info_list)
        
        file_paths = [info.get('file_path', '') for info in file_info_list if info.get('file_path')]
        
        return {
            'aggregated_files': len(file_info_list),
            'file_paths': file_paths,
            'total_packet_count': total_packets,
            'total_analysis_time': total_time,
            'average_analysis_time': total_time / len(file_info_list) if file_info_list else 0
        }
    
    def _aggregate_metadata(self, metadata_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """聚合元数据"""
        merged = self._merge_metadata(metadata_list)
        
        # 添加聚合特定的元数据
        merged.update({
            'aggregation_count': len(metadata_list),
            'aggregation_type': 'multi_file'
        })
        
        return merged 