"""
数据统计分析引擎

协调各统计模块的执行，提供统一的分析接口
支持单文件和批量分析，支持并行处理
"""

import time
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..adapters.json_adapter import JSONDataAdapter
from ..stats.base import StatisticsBase, StatisticsResult, statistics_registry

logger = logging.getLogger(__name__)


class AnalyticsEngine:
    """数据统计分析引擎"""
    
    def __init__(self, enable_parallel: bool = True, max_workers: int = 4):
        """
        初始化分析引擎
        
        Args:
            enable_parallel: 是否启用并行处理
            max_workers: 最大工作线程数
        """
        self.enable_parallel = enable_parallel
        self.max_workers = max_workers
        self.data_adapter = JSONDataAdapter(validate_data=True)
        self.enabled_statistics = {}
        
        # 自动注册所有可用的统计项
        self._register_default_statistics()
    
    def _register_default_statistics(self):
        """注册默认的统计项"""
        try:
            # 导入统计模块以触发注册
            from ..stats import traffic, protocol
            
            # 启用默认统计项
            default_stats = [
                'basic_traffic',
                'packet_size_distribution', 
                'protocol_distribution',
                'top_protocols'
            ]
            
            for stat_name in default_stats:
                stat_class = statistics_registry.get_statistics(stat_name)
                if stat_class:
                    self.enabled_statistics[stat_name] = stat_class()
                    logger.debug(f"已启用统计项: {stat_name}")
        
        except ImportError as e:
            logger.warning(f"导入统计模块失败: {e}")
    
    def enable_statistics(self, statistics_names: List[str]):
        """
        启用指定的统计项
        
        Args:
            statistics_names: 统计项名称列表
        """
        self.enabled_statistics.clear()
        
        for stat_name in statistics_names:
            stat_class = statistics_registry.get_statistics(stat_name)
            if stat_class:
                self.enabled_statistics[stat_name] = stat_class()
                logger.info(f"已启用统计项: {stat_name}")
            else:
                logger.warning(f"未找到统计项: {stat_name}")
    
    def disable_statistics(self, statistics_names: List[str]):
        """
        禁用指定的统计项
        
        Args:
            statistics_names: 统计项名称列表
        """
        for stat_name in statistics_names:
            if stat_name in self.enabled_statistics:
                del self.enabled_statistics[stat_name]
                logger.info(f"已禁用统计项: {stat_name}")
    
    def get_available_statistics(self) -> Dict[str, Dict[str, Any]]:
        """
        获取所有可用的统计项信息
        
        Returns:
            Dict[str, Dict[str, Any]]: 统计项信息字典
        """
        available_stats = {}
        
        # 获取所有注册的统计项
        all_stats = statistics_registry.list_all_statistics()
        
        for category, stat_names in all_stats.items():
            for stat_name in stat_names:
                stat_class = statistics_registry.get_statistics(stat_name)
                if stat_class:
                    # 创建临时实例获取信息
                    temp_instance = stat_class()
                    available_stats[stat_name] = {
                        'name': temp_instance.name,
                        'description': temp_instance.description,
                        'category': category,
                        'enabled': stat_name in self.enabled_statistics,
                        'required_fields': temp_instance.get_required_fields()
                    }
        
        return available_stats
    
    def analyze_single_file(self, file_path: Union[str, Path], 
                           statistics_names: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        分析单个JSON文件
        
        Args:
            file_path: JSON文件路径
            statistics_names: 指定要运行的统计项，None表示使用当前启用的统计项
            
        Returns:
            Dict[str, Any]: 分析结果
        """
        start_time = time.time()
        
        try:
            # 加载数据
            data = self.data_adapter.load_single_file(file_path)
            
            # 确定要运行的统计项
            stats_to_run = self._get_statistics_to_run(statistics_names)
            
            # 执行统计计算
            if self.enable_parallel and len(stats_to_run) > 1:
                results = self._run_statistics_parallel(data, stats_to_run)
            else:
                results = self._run_statistics_sequential(data, stats_to_run)
            
            # 构建最终结果
            analysis_time = time.time() - start_time
            
            final_results = {
                'file_info': {
                    'file_path': str(file_path),
                    'packet_count': data.file_info.packet_count,
                    'analysis_time': analysis_time
                },
                'statistics': results,
                'metadata': {
                    'analyzer_version': '1.0.0',
                    'enabled_statistics': list(stats_to_run.keys()),
                    'analysis_timestamp': time.time()
                }
            }
            
            logger.info(f"文件分析完成: {file_path}, 耗时: {analysis_time:.2f}秒")
            return final_results
            
        except Exception as e:
            logger.error(f"分析文件失败 {file_path}: {e}")
            return {
                'file_info': {'file_path': str(file_path)},
                'error': str(e),
                'analysis_time': time.time() - start_time
            }
    
    def analyze_directory(self, directory_path: Union[str, Path],
                         statistics_names: Optional[List[str]] = None,
                         aggregate_results: bool = True,
                         file_pattern: str = "*.json") -> Dict[str, Any]:
        """
        分析目录中的所有JSON文件
        
        Args:
            directory_path: 目录路径
            statistics_names: 指定要运行的统计项
            aggregate_results: 是否聚合结果
            file_pattern: 文件匹配模式
            
        Returns:
            Dict[str, Any]: 批量分析结果
        """
        start_time = time.time()
        
        # 扫描JSON文件
        json_files = self.data_adapter.scan_directory(directory_path, file_pattern)
        
        if not json_files:
            return {
                'summary': {
                    'total_files': 0,
                    'successful_files': 0,
                    'failed_files': 0,
                    'analysis_time': time.time() - start_time
                },
                'results': [],
                'errors': []
            }
        
        # 批量分析
        individual_results = []
        errors = []
        
        logger.info(f"开始批量分析 {len(json_files)} 个文件")
        
        for json_file in json_files:
            result = self.analyze_single_file(json_file, statistics_names)
            
            if 'error' in result:
                errors.append(result)
            else:
                individual_results.append(result)
        
        # 生成摘要
        analysis_time = time.time() - start_time
        summary = {
            'total_files': len(json_files),
            'successful_files': len(individual_results),
            'failed_files': len(errors),
            'analysis_time': analysis_time
        }
        
        final_results = {
            'summary': summary,
            'results': individual_results,
            'errors': errors
        }
        
        # 聚合结果（如果请求且有多个成功结果）
        if aggregate_results and len(individual_results) > 1:
            try:
                aggregated = self._aggregate_results(individual_results)
                final_results['aggregated_results'] = aggregated
                logger.info(f"已聚合 {len(individual_results)} 个文件的结果")
            except Exception as e:
                logger.warning(f"结果聚合失败: {e}")
        
        logger.info(f"批量分析完成: {summary['successful_files']}/{summary['total_files']} 成功, 耗时: {analysis_time:.2f}秒")
        return final_results
    
    def _get_statistics_to_run(self, statistics_names: Optional[List[str]]) -> Dict[str, StatisticsBase]:
        """获取要运行的统计项"""
        if statistics_names is None:
            return self.enabled_statistics.copy()
        
        stats_to_run = {}
        for stat_name in statistics_names:
            if stat_name in self.enabled_statistics:
                stats_to_run[stat_name] = self.enabled_statistics[stat_name]
            else:
                # 尝试临时创建
                stat_class = statistics_registry.get_statistics(stat_name)
                if stat_class:
                    stats_to_run[stat_name] = stat_class()
                else:
                    logger.warning(f"统计项不存在: {stat_name}")
        
        return stats_to_run
    
    def _run_statistics_sequential(self, data, stats_to_run: Dict[str, StatisticsBase]) -> Dict[str, Any]:
        """顺序执行统计计算"""
        results = {}
        
        for stat_name, stat_instance in stats_to_run.items():
            try:
                start_time = time.time()
                result = stat_instance.calculate(data)
                result.calculation_time = time.time() - start_time
                results[stat_name] = result.__dict__
                logger.debug(f"统计项 {stat_name} 计算完成, 耗时: {result.calculation_time:.3f}秒")
            except Exception as e:
                logger.error(f"统计项 {stat_name} 计算失败: {e}")
                results[stat_name] = {'error': str(e)}
        
        return results
    
    def _run_statistics_parallel(self, data, stats_to_run: Dict[str, StatisticsBase]) -> Dict[str, Any]:
        """并行执行统计计算"""
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 提交所有任务
            future_to_stat = {
                executor.submit(self._calculate_single_statistic, stat_instance, data): stat_name
                for stat_name, stat_instance in stats_to_run.items()
            }
            
            # 收集结果
            for future in as_completed(future_to_stat):
                stat_name = future_to_stat[future]
                try:
                    result = future.result()
                    results[stat_name] = result
                    logger.debug(f"统计项 {stat_name} 并行计算完成")
                except Exception as e:
                    logger.error(f"统计项 {stat_name} 并行计算失败: {e}")
                    results[stat_name] = {'error': str(e)}
        
        return results
    
    def _calculate_single_statistic(self, stat_instance: StatisticsBase, data) -> Dict[str, Any]:
        """计算单个统计项（用于并行执行）"""
        start_time = time.time()
        result = stat_instance.calculate(data)
        result.calculation_time = time.time() - start_time
        return result.__dict__
    
    def _aggregate_results(self, individual_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """聚合多个文件的分析结果"""
        aggregated = {}
        
        # 获取所有统计项名称
        all_stat_names = set()
        for result in individual_results:
            all_stat_names.update(result.get('statistics', {}).keys())
        
        # 对每个统计项进行聚合
        for stat_name in all_stat_names:
            try:
                stat_class = statistics_registry.get_statistics(stat_name)
                if stat_class and hasattr(stat_class(), 'aggregate'):
                    # 收集该统计项的所有结果
                    stat_results = []
                    for result in individual_results:
                        if stat_name in result.get('statistics', {}):
                            stat_data = result['statistics'][stat_name]
                            if 'error' not in stat_data:
                                # 重构 StatisticsResult 对象
                                stat_result = StatisticsResult(
                                    name=stat_data.get('name', stat_name),
                                    description=stat_data.get('description', ''),
                                    results=stat_data.get('results', {}),
                                    metadata=stat_data.get('metadata', {}),
                                    calculation_time=stat_data.get('calculation_time', 0.0)
                                )
                                stat_results.append(stat_result)
                    
                    # 执行聚合
                    if stat_results:
                        aggregated_result = stat_class().aggregate(stat_results)
                        aggregated[stat_name] = aggregated_result.__dict__
            
            except Exception as e:
                logger.warning(f"聚合统计项 {stat_name} 失败: {e}")
        
        return aggregated 