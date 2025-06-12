#!/usr/bin/env python3
"""
数据统计分析CLI工具

独立的CLI工具，用于分析PCAP解码器的输出数据
"""

import click
import json
import logging
from pathlib import Path
from typing import List, Optional

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """PCAP数据统计分析工具"""
    pass


@cli.command()
@click.option('-i', '--input', 'input_path', required=False, 
              help='输入文件路径或目录')
@click.option('-o', '--output', 'output_path', required=False,
              help='输出目录路径')
@click.option('--statistics', 'statistics_list', multiple=True,
              help='指定运行的统计项（可多次使用）')
@click.option('--list-stats', is_flag=True,
              help='列出所有可用的统计项')
@click.option('--parallel/--no-parallel', default=True,
              help='是否启用并行处理')
@click.option('--aggregate/--no-aggregate', default=True,
              help='是否聚合批量结果')
@click.option('-v', '--verbose', is_flag=True,
              help='详细输出模式')
def analyze(input_path: str, 
           output_path: str,
           statistics_list: tuple,
           list_stats: bool,
           parallel: bool,
           aggregate: bool,
           verbose: bool):
    """分析PCAP解码器的JSON输出数据"""
    
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        from analytics.core.analyzer import AnalyticsEngine
        
        # 创建分析引擎
        engine = AnalyticsEngine(enable_parallel=parallel)
        
        # 如果只是列出统计项
        if list_stats:
            available_stats = engine.get_available_statistics()
            click.echo("可用的统计项:")
            for name, info in available_stats.items():
                click.echo(f"  {name}: {info['description']}")
                click.echo(f"    启用状态: {info['enabled']}")
                click.echo(f"    必需字段: {', '.join(info['required_fields'])}")
                click.echo()
            return
        
        # 检查必需的参数
        if not input_path:
            click.echo("错误: 需要指定输入文件路径 (-i/--input)", err=True)
            return
        
        if not output_path:
            click.echo("错误: 需要指定输出目录路径 (-o/--output)", err=True)
            return
        
        # 创建输出目录
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        input_file_path = Path(input_path)
        
        # 确定统计项列表
        stats_to_run = list(statistics_list) if statistics_list else None
        
        # 执行分析
        if input_file_path.is_file():
            # 单文件分析
            click.echo(f"分析单个文件: {input_path}")
            results = engine.analyze_single_file(input_path, stats_to_run)
            
            # 保存结果
            output_file = output_dir / f"{input_file_path.stem}_analytics.json"
            save_results(results, output_file)
            click.echo(f"结果已保存到: {output_file}")
            
        elif input_file_path.is_dir():
            # 目录分析
            click.echo(f"分析目录: {input_path}")
            results = engine.analyze_directory(input_path, 
                                             statistics_names=stats_to_run,
                                             aggregate_results=aggregate)
            
            # 保存结果
            output_file = output_dir / "batch_analytics.json"
            save_results(results, output_file)
            click.echo(f"批量分析结果已保存到: {output_file}")
            
            # 显示摘要
            summary = results.get('summary', {})
            click.echo(f"\n分析摘要:")
            click.echo(f"  总文件数: {summary.get('total_files', 0)}")
            click.echo(f"  成功处理: {summary.get('successful_files', 0)}")
            click.echo(f"  失败文件: {summary.get('failed_files', 0)}")
            click.echo(f"  分析耗时: {summary.get('analysis_time', 0):.2f}秒")
            
        else:
            click.echo(f"错误: 输入路径不存在或无效: {input_path}", err=True)
            return
            
        click.echo("分析完成！")
        
    except ImportError as e:
        click.echo(f"错误: 无法导入analytics模块 - {e}", err=True)
        click.echo("请确保analytics模块已正确安装和配置")
    except Exception as e:
        click.echo(f"分析失败: {e}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()


@cli.command()
@click.option('-i', '--input', 'input_path', required=True,
              help='JSON数据文件路径')
def validate(input_path: str):
    """验证JSON数据文件格式"""
    try:
        from analytics.adapters.json_adapter import JSONDataAdapter
        
        adapter = JSONDataAdapter(validate_data=True)
        
        # 获取文件摘要
        summary = adapter.get_file_summary(input_path)
        
        if 'error' in summary:
            click.echo(f"文件验证失败: {summary['error']}", err=True)
            return
        
        click.echo(f"文件验证成功: {input_path}")
        click.echo(f"  文件大小: {summary['file_size_mb']:.2f} MB")
        click.echo(f"  数据包数: {summary['packet_count']}")
        click.echo(f"  包含错误: {'是' if summary['has_errors'] else '否'}")
        
        # 检查版本兼容性
        metadata = summary.get('metadata', {})
        compatible_version = adapter.get_compatible_version(metadata)
        if compatible_version:
            click.echo(f"  格式版本: {metadata.get('format_version', 'unknown')} (兼容)")
        else:
            click.echo(f"  格式版本: {metadata.get('format_version', 'unknown')} (不兼容)", err=True)
        
    except Exception as e:
        click.echo(f"验证失败: {e}", err=True)


@cli.command()
def list_statistics():
    """列出所有可用的统计项"""
    try:
        from analytics.stats.base import statistics_registry
        
        # 导入所有统计模块以触发注册
        from analytics.stats import traffic, protocol
        
        all_stats = statistics_registry.list_all_statistics()
        
        click.echo("已注册的统计项:")
        for category, stat_names in all_stats.items():
            click.echo(f"\n{category.upper()}类别:")
            for stat_name in stat_names:
                stat_class = statistics_registry.get_statistics(stat_name)
                if stat_class:
                    # 创建临时实例获取描述信息
                    instance = stat_class()
                    click.echo(f"  {instance.name}: {instance.description}")
        
    except Exception as e:
        click.echo(f"获取统计项列表失败: {e}", err=True)


def save_results(results: dict, output_file: Path):
    """保存分析结果到文件"""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    except Exception as e:
        logger.error(f"保存结果失败: {e}")
        raise


if __name__ == '__main__':
    cli() 