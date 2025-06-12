"""
命令行接口模块
提供PCAP解码器的命令行参数解析和主要入口点
"""

import click
import os
import sys
import logging
from pathlib import Path
from __init__ import __version__
from core import BatchProcessor
from utils.progress import create_progress_monitor, ProgressUpdate
from typing import Optional


def setup_logging(verbose: bool):
    """设置日志配置"""
    level = logging.INFO if verbose else logging.WARNING
    
    # 配置日志格式
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # 设置控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    # 配置根日志记录器
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.addHandler(console_handler)
    
    # 静默第三方库的日志
    logging.getLogger('scapy').setLevel(logging.ERROR)
    logging.getLogger('pyshark').setLevel(logging.ERROR)


@click.command()
@click.option('-i', '--input', 'input_dir', required=True, 
              help='输入目录路径，包含PCAP/PCAPNG文件')
@click.option('-o', '--output', 'output_dir', default=None,
              help='输出目录路径，用于保存JSON结果 (默认: 与输入文件同目录)')
@click.option('-j', '--jobs', default=None, type=int,
              help='并发处理进程数 (默认: CPU核心数)')
@click.option('--max-packets', default=None, type=int,
              help='每个文件最大处理包数 (默认: 无限制)')
@click.option('--timeout', default=300, type=int,
              help='单个文件处理超时时间（秒），默认300秒')
@click.option('--dry-run', is_flag=True,
              help='试运行模式，只扫描文件不实际处理')
@click.option('-v', '--verbose', is_flag=True,
              help='详细输出模式')
@click.option('--error-report', is_flag=True,
              help='生成错误报告')
@click.option('--streaming-threshold', default=1000, type=int,
              help='流式输出阈值，包数超过此值使用流式输出（默认1000）')
@click.version_option(version=__version__)
def main(input_dir, output_dir, jobs, max_packets, timeout, dry_run, verbose, 
         error_report, streaming_threshold):
    """
    PCAP/PCAPNG 批量解码器
    
    批量解码指定目录下的PCAP/PCAPNG文件，输出详细的协议字段信息到JSON文件。
    支持多进程并行处理，自动识别多种封装协议。
    
    示例:
        pcap_decoder -i /path/to/pcaps -o /path/to/output
        pcap_decoder -i ./samples -o ./results -j 4 --verbose
        pcap_decoder -i ./data -o ./output --max-packets 100 --timeout 120
    """
    
    # 设置日志
    setup_logging(verbose)
    logger = logging.getLogger(__name__)
    
    # 输入验证
    input_path = Path(input_dir)
    if not input_path.exists():
        click.echo(f"❌ 错误: 输入目录不存在: {input_dir}", err=True)
        sys.exit(1)
    
    if not input_path.is_dir():
        click.echo(f"❌ 错误: 输入路径不是目录: {input_dir}", err=True)
        sys.exit(1)
    
    # 如果指定了输出目录，则创建它
    if output_dir:
        output_path = Path(output_dir)
        try:
            output_path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            click.echo(f"❌ 错误: 无法创建输出目录: {e}", err=True)
            sys.exit(1)
    else:
        # 当 output_dir 为 None 时，输出路径将基于输入文件
        output_path = "与输入文件同目录"

    if verbose:
        click.echo(f"🔧 PCAP解码器 v{__version__}")
        click.echo(f"📂 输入目录: {input_path.absolute()}")
        if output_dir:
            click.echo(f"📁 输出目录: {Path(output_dir).absolute()}")
        else:
            click.echo(f"📁 输出目录: 与输入文件同目录")
        if jobs:
            click.echo(f"⚙️  并发进程: {jobs}")
        else:
            click.echo(f"⚙️  并发进程: 自动检测")
        if max_packets:
            click.echo(f"📦 最大包数限制: {max_packets}")
        click.echo(f"⏱️  超时设置: {timeout}秒")
        click.echo(f"🔄 流式输出阈值: {streaming_threshold}包")
        if dry_run:
            click.echo("🧪 模式: 试运行")
    
    try:
        if dry_run:
            # 试运行模式：只扫描文件
            _run_dry_mode(input_dir, verbose)
        else:
            # 实际处理模式
            _run_processing_mode(
                input_dir, output_dir, jobs, max_packets, timeout,
                verbose, error_report, streaming_threshold
            )
    except KeyboardInterrupt:
        click.echo("\n⚠️  用户中断处理")
        sys.exit(1)
    except Exception as e:
        logger.error(f"处理过程中发生错误: {e}")
        click.echo(f"❌ 处理失败: {e}", err=True)
        sys.exit(1)


def _run_dry_mode(input_dir: str, verbose: bool):
    """运行试运行模式"""
    from core.scanner import DirectoryScanner
    
    click.echo("🔍 扫描文件...")
    scanner = DirectoryScanner()
    files = scanner.scan_directory(input_dir, max_depth=2)
    
    if not files:
        click.echo("⚠️  未找到PCAP/PCAPNG文件")
        return
    
    click.echo(f"✅ 发现 {len(files)} 个文件")
    
    if verbose:
        click.echo("\n📋 文件列表:")
        for i, file_path in enumerate(files, 1):
            file_size = Path(file_path).stat().st_size
            size_str = _format_file_size(file_size)
            click.echo(f"  {i:2d}. {Path(file_path).name} ({size_str})")
        
        total_size = sum(Path(f).stat().st_size for f in files)
        click.echo(f"\n📊 统计信息:")
        click.echo(f"   总文件数: {len(files)}")
        click.echo(f"   总大小: {_format_file_size(total_size)}")
    
    click.echo("🧪 试运行完成")


def _run_processing_mode(input_dir: str, output_dir: Optional[str], jobs: int, 
                        max_packets: int, timeout: int, verbose: bool,
                        error_report: bool, streaming_threshold: int):
    """运行实际处理模式"""
    
    # 动态导入以避免循环依赖或过早初始化
    from core.processor import EnhancedBatchProcessor
    
    # 初始化批量处理器
    processor = EnhancedBatchProcessor(
        output_dir=output_dir,
        max_workers=jobs,
        task_timeout=timeout,
        max_packets=max_packets,
        enable_resource_monitoring=not verbose  # 在非详细模式下启用资源监控
    )
    
    # 更新格式化器的流式输出阈值
    # 注意: 此功能需要 Processor 支持
    
    # 创建进度监控器
    progress_monitor = create_progress_monitor(
        verbose=verbose,
        multi_process=True,
        show_detailed_stats=verbose
    )
    
    # 准备进度回调函数
    def progress_callback(completed: int, total: int):
        # 这个回调会被批量处理器调用
        pass  # 进度更新由BatchProcessor内部处理
    
    # 开始处理
    try:
        click.echo("🚀 开始批量处理...")
        
        # 执行批量处理
        result_summary = processor.process_files(
            input_dir=input_dir,
            progress_callback=progress_callback,
            save_error_report=error_report
        )
        
        # 显示最终结果
        _display_final_results(result_summary, verbose, error_report, output_dir)
        
    except Exception as e:
        logging.getLogger(__name__).error(f"批量处理失败: {e}")
        raise


def _display_final_results(summary: dict, verbose: bool, error_report: bool, output_dir: Optional[str]):
    """显示最终处理结果"""
    processing = summary.get('processing_summary', {})
    performance = summary.get('performance_metrics', {})
    config = summary.get('configuration', {})
    errors = summary.get('errors', [])
    
    # 基本结果
    click.echo("\n" + "="*60)
    click.echo("🎉 批量处理完成!")
    click.echo("="*60)
    
    # 处理统计
    click.echo(f"📊 处理统计:")
    click.echo(f"   总文件数: {processing.get('total_files', 0)}")
    click.echo(f"   成功处理: {processing.get('successful_files', 0)} ✅")
    click.echo(f"   处理失败: {processing.get('failed_files', 0)} ❌")
    click.echo(f"   成功率: {processing.get('success_rate', 0):.1f}%")
    click.echo(f"   总处理包数: {processing.get('total_packets_processed', 0):,}")
    
    # 性能指标
    if verbose:
        click.echo(f"\n⚡ 性能指标:")
        click.echo(f"   总耗时: {processing.get('total_processing_time', 0):.3f}s")
        click.echo(f"   处理速度: {performance.get('packets_per_second', 0):.1f} 包/s")
        click.echo(f"   文件处理速度: {performance.get('average_time_per_file', 0):.3f}s/文件")
        click.echo(f"   并行效率: {performance.get('parallelization_efficiency', 0):.1f}%")
        
        # 配置信息
        click.echo(f"\n⚙️  配置信息:")
        click.echo(f"   工作进程数: {config.get('max_workers', 0)}")
        click.echo(f"   任务超时: {config.get('task_timeout', 0)}s")
        if config.get('max_packets_per_file'):
            click.echo(f"   包数限制: {config.get('max_packets_per_file')}")
    
    # 错误报告
    if errors:
        click.echo(f"\n❌ 错误详情 ({len(errors)} 个):")
        for error in errors[:5]:  # 只显示前5个错误
            file_name = Path(error['file']).name
            click.echo(f"   • {file_name}: {error['error']}")
        
        if len(errors) > 5:
            click.echo(f"   ... 还有 {len(errors) - 5} 个错误")
        
        # 生成错误报告文件
        if error_report:
            error_report_path = Path(output_dir) / 'error_report.txt'
            with open(error_report_path, 'w', encoding='utf-8') as f:
                f.write("PCAP解码器错误报告\n")
                f.write("="*50 + "\n\n")
                for i, error in enumerate(errors, 1):
                    f.write(f"{i}. 文件: {error['file']}\n")
                    f.write(f"   错误: {error['error']}\n")
                    f.write(f"   处理时间: {error.get('processing_time', 0):.3f}s\n\n")
            
            click.echo(f"📝 错误报告已保存: {error_report_path}")
    
    # 输出文件位置
    click.echo(f"\n📁 输出文件位置: {output_dir}")
    click.echo(f"📄 查看汇总报告: {output_dir}/batch_summary_report.json")
    click.echo("="*60)


def _format_file_size(size_bytes: int) -> str:
    """格式化文件大小"""
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024*1024:
        return f"{size_bytes/1024:.1f}KB"
    elif size_bytes < 1024*1024*1024:
        return f"{size_bytes/(1024*1024):.1f}MB"
    else:
        return f"{size_bytes/(1024*1024*1024):.1f}GB"


if __name__ == '__main__':
    main() 