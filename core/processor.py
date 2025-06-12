"""
批量处理器模块
支持多进程并发处理PCAP文件，包含任务分配、队列管理、超时控制、资源管理等功能
"""

import logging
import multiprocessing as mp
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FutureTimeoutError, as_completed
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass
import signal
import queue

from core.scanner import DirectoryScanner
from core.decoder import PacketDecoder, DecodeResult
from core.extractor import ProtocolExtractor
from core.formatter import JSONFormatter
from utils.resource_manager import ResourceManager, MemoryThresholds, DiskThresholds
from utils.errors import ErrorCollector, FileError, DecodeError
from utils.helpers import get_file_size_mb

logger = logging.getLogger(__name__)

# 定义一个更具体的进度更新类型
@dataclass
class ProgressUpdate:
    """进度更新信息"""
    task_id: int
    file_path: str
    processed: int
    total: int
    done: bool = False
    error: Optional[str] = None


@dataclass
class ProcessingTask:
    """处理任务数据类"""
    file_path: str
    output_dir: str
    max_packets: Optional[int] = None
    task_id: int = 0


@dataclass
class ProcessingResult:
    """处理结果数据类"""
    task: ProcessingTask
    success: bool
    decode_result: Optional[DecodeResult] = None
    output_file: Optional[str] = None
    error: Optional[str] = None
    processing_time: float = 0.0
    resource_usage: Optional[Dict[str, Any]] = None


class TaskTimeoutError(Exception):
    """任务超时异常"""
    pass


def process_single_file(
    task: ProcessingTask, 
    progress_queue: mp.Queue, 
    timeout: int = 300
) -> ProcessingResult:
    """
    处理单个文件的工作函数（用于多进程执行）
    
    Args:
        task: 处理任务
        progress_queue: 进度更新队列
        timeout: 超时时间（秒）
        
    Returns:
        ProcessingResult: 处理结果
    """
    start_time = time.time()
    
    def timeout_handler(signum, frame):
        raise TaskTimeoutError(f"任务超时: {timeout}秒")
    
    # 设置超时信号处理
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)
    
    # 初始化资源管理器（每个进程独立）
    resource_manager = None
    resource_usage = {}
    
    def progress_callback(processed: int, total: int):
        """解码器调用的回调函数"""
        try:
            progress_queue.put_nowait(
                ProgressUpdate(
                    task_id=task.task_id,
                    file_path=task.file_path,
                    processed=processed,
                    total=total
                )
            )
        except queue.Full:
            # 如果队列已满，可以忽略此次更新
            pass

    try:
        # 创建资源管理器（不启用监控以减少开销）
        resource_manager = ResourceManager(enable_monitoring=False)
        
        # 检查文件是否可以处理
        processability = resource_manager.check_file_processable(task.file_path)
        resource_usage['file_check'] = processability
        
        if not processability['can_process']:
            raise FileError(
                file_path=task.file_path,
                operation="文件处理能力检查",
                original_error=Exception(f"文件无法处理: {processability['recommendations']}")
            )
        
        # 初始化处理组件
        decoder = PacketDecoder(max_packets=task.max_packets)
        extractor = ProtocolExtractor()
        formatter = JSONFormatter(task.output_dir)
        
        # 注册清理回调
        resource_manager.memory_manager.register_cleanup_callback(lambda: decoder.cleanup() if hasattr(decoder, 'cleanup') else None)
        
        # 解码文件
        decode_result = decoder.decode_file(task.file_path, progress_callback=progress_callback)
        
        # 提取协议字段
        for packet in decode_result.packets:
            extractor.extract_fields(packet)
        
        # 检查内存使用情况
        resource_manager.memory_manager.cleanup_if_needed()
        
        # 格式化并保存
        output_file = formatter.format_and_save(decode_result)
        
        processing_time = time.time() - start_time
        
        logger.info(f"完成处理文件: {Path(task.file_path).name} ({processing_time:.3f}s)")
        
        # 发送完成信号
        progress_queue.put_nowait(
            ProgressUpdate(
                task_id=task.task_id, 
                file_path=task.file_path,
                processed=decode_result.packet_count,
                total=decode_result.packet_count if decode_result.packet_count > 0 else 1, # 避免除以0
                done=True
            )
        )
        
        return ProcessingResult(
            task=task,
            success=True,
            decode_result=decode_result,
            output_file=output_file,
            processing_time=processing_time,
            resource_usage=resource_usage
        )
        
    except TaskTimeoutError as e:
        logger.error(f"文件处理超时: {task.file_path} - {e}")
        # 发送错误信号
        progress_queue.put_nowait(
            ProgressUpdate(
                task_id=task.task_id,
                file_path=task.file_path,
                processed=0,
                total=1,
                done=True,
                error=str(e)
            )
        )
        return ProcessingResult(
            task=task,
            success=False,
            error=str(e),
            processing_time=time.time() - start_time,
            resource_usage=resource_usage
        )
        
    except Exception as e:
        logger.error(f"文件处理失败: {task.file_path} - {e}")
        # 发送错误信号
        progress_queue.put_nowait(
            ProgressUpdate(
                task_id=task.task_id,
                file_path=task.file_path,
                processed=0,
                total=1,
                done=True,
                error=str(e)
            )
        )
        return ProcessingResult(
            task=task,
            success=False,
            error=str(e),
            processing_time=time.time() - start_time,
            resource_usage=resource_usage
        )
        
    finally:
        # 清除超时信号
        signal.alarm(0)
        
        # 清理资源
        if resource_manager:
            resource_manager.cleanup_all()


class EnhancedBatchProcessor:
    """增强版批量处理器，支持资源管理和智能调度"""
    
    def __init__(self, 
                 output_dir: Optional[str],
                 max_workers: int = None,
                 task_timeout: int = 300,
                 max_packets: Optional[int] = None,
                 memory_limit_mb: Optional[float] = None,
                 enable_resource_monitoring: bool = True):
        """
        初始化增强版批量处理器
        
        Args:
            output_dir: 输出目录
            max_workers: 最大工作进程数，默认为CPU核心数
            task_timeout: 单个任务超时时间（秒）
            max_packets: 每个文件最大处理包数
            memory_limit_mb: 内存限制（MB）
            enable_resource_monitoring: 是否启用资源监控
        """
        self.output_dir = Path(output_dir) if output_dir else None
        if self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.max_workers = max_workers or mp.cpu_count()
        self.task_timeout = task_timeout
        self.max_packets = max_packets
        
        # 跨进程通信队列
        manager = mp.Manager()
        self.progress_queue = manager.Queue()
        
        # 资源管理配置
        memory_thresholds = MemoryThresholds(
            warning_mb=memory_limit_mb * 0.7 if memory_limit_mb else 1000.0,
            critical_mb=memory_limit_mb * 0.9 if memory_limit_mb else 2000.0
        )
        
        # 初始化资源管理器
        self.resource_manager = ResourceManager(
            memory_thresholds=memory_thresholds,
            enable_monitoring=enable_resource_monitoring
        )
        
        # 错误收集器
        self.error_collector = ErrorCollector()
        
        # 统计信息
        self.stats = {
            'total_files': 0,
            'successful_files': 0,
            'failed_files': 0,
            'skipped_files': 0,
            'total_packets': 0,
            'total_processing_time': 0.0,
            'peak_memory_mb': 0.0,
            'total_memory_cleaned_mb': 0.0,
            'errors': []
        }
        
        logger.info(f"初始化增强版批量处理器: {self.max_workers} 个工作进程，资源监控: {'启用' if enable_resource_monitoring else '禁用'}")
    
    def pre_process_analysis(self, tasks: List[ProcessingTask]) -> Dict[str, Any]:
        """处理前分析，评估资源需求和处理策略"""
        logger.info("执行处理前资源分析...")
        
        total_size_mb = 0.0
        large_files = []
        processable_files = []
        unprocessable_files = []
        recommendations = []
        
        # 模拟资源检查
        if self.resource_manager:
            for task in tasks:
                if self.resource_manager.monitor:
                    file_size_mb = get_file_size_mb(task.file_path)
                    total_size_mb += file_size_mb
                
                    status = self.resource_manager.check_file_processable(task.file_path)
                    if not status['can_process']:
                        unprocessable_files.append((task, status['recommendations']))
                    if status.get('is_large_file', False):
                        large_files.append(task)
                else:
                    # 如果没有监控器，就跳过检查
                    pass
        
        # 估算总处理时间 (简化版)
        estimated_time_per_file = 5  # 假设每个文件平均5秒
        
        analysis = {
            'total_files': len(tasks),
            'processable_files': len(processable_files),
            'unprocessable_files': len(unprocessable_files),
            'large_files': len(large_files),
            'total_size_mb': total_size_mb,
            'estimated_total_memory_mb': total_size_mb * 2.5,
            'recommended_workers': min(self.max_workers, len(processable_files)),
            'processing_strategy': 'sequential' if large_files else 'parallel'
        }
        
        # 记录无法处理的文件
        for task, recommendations in unprocessable_files:
            self.error_collector.add_warning(
                f"文件跳过: {task.file_path}",
                task.file_path,
                {'recommendations': recommendations}
            )
        
        logger.info(f"分析完成: {analysis['processable_files']}/{analysis['total_files']} 个文件可处理")
        if unprocessable_files:
            logger.warning(f"{len(unprocessable_files)} 个文件因资源限制被跳过")
        
        return analysis
    
    def scan_and_prepare_tasks(self, input_dir: str) -> List[ProcessingTask]:
        """扫描目录并准备处理任务"""
        logger.info(f"扫描输入目录: {input_dir}")
        scanner = DirectoryScanner()
        files = scanner.scan_directory(input_dir, max_depth=2)
        
        if not files:
            logger.warning(f"在 {input_dir} 中未找到PCAP/PCAPNG文件")
            return []
            
        tasks = []
        for i, file_path in enumerate(files):
            output_directory = self.output_dir if self.output_dir else Path(file_path).parent
            tasks.append(ProcessingTask(
                file_path=str(file_path),
                output_dir=str(output_directory),
                max_packets=self.max_packets,
                task_id=i
            ))
            
        logger.info(f"准备了 {len(tasks)} 个处理任务")
        return tasks
    
    def process_files(self, 
                     input_dir: str,
                     progress_callback: Optional[Callable[[int, int], None]] = None,
                     save_error_report: bool = True) -> Dict[str, Any]:
        """
        批量处理文件（增强版）
        
        Args:
            input_dir: 输入目录路径
            progress_callback: 进度回调函数 (completed, total)
            save_error_report: 是否保存错误报告
            
        Returns:
            Dict[str, Any]: 处理结果统计
        """
        start_time = time.time()
        
        # 准备任务
        all_tasks = self.scan_and_prepare_tasks(input_dir)
        if not all_tasks:
            logger.warning("没有找到需要处理的文件")
            return self._build_summary()
        
        # 预处理分析
        analysis = self.pre_process_analysis(all_tasks)
        processable_tasks = [task for task in all_tasks 
                           if self.resource_manager.check_file_processable(task.file_path)['can_process']]
        
        self.stats['total_files'] = len(all_tasks)
        self.stats['skipped_files'] = len(all_tasks) - len(processable_tasks)
        
        if not processable_tasks:
            logger.error("没有可处理的文件")
            return self._build_summary()
        
        # 使用 rich 创建进度条
        from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}", justify="right"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            TextColumn("({task.completed}/{task.total} packets)"),
        ) as progress:
            overall_task = progress.add_task("[bold blue]总进度", total=len(processable_tasks))
            task_progress_bars = {}

            with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
                # 提交任务
                future_to_task = {
                    executor.submit(process_single_file, task, self.progress_queue, self.task_timeout): task
                    for task in processable_tasks
                }
                
                # 实时处理进度更新和结果
                completed_count = 0
                while completed_count < len(processable_tasks):
                    try:
                        update: ProgressUpdate = self.progress_queue.get(timeout=1)

                        file_name = Path(update.file_path).name
                        if update.task_id not in task_progress_bars:
                            task_progress_bars[update.task_id] = progress.add_task(f"{file_name}", total=update.total if update.total > 0 else 100)

                        if update.done:
                            completed_count += 1
                            progress.update(overall_task, advance=1)
                            if update.error:
                                progress.update(task_progress_bars[update.task_id], completed=update.total, description=f"[bold red]❌ {file_name} (错误)")
                            else:
                                progress.update(task_progress_bars[update.task_id], completed=update.total, description=f"[bold green]✔️ {file_name}")
                        else:
                            progress.update(task_progress_bars[update.task_id], completed=update.processed, total=update.total if update.total > 0 else None)

                    except queue.Empty:
                        # 检查是否有任务已经完成但没有发送进度
                        done_futures = [f for f in future_to_task if f.done()]
                        if len(done_futures) == len(processable_tasks) and self.progress_queue.empty():
                            break # 所有任务完成

                # 收集最终结果
                for future in as_completed(future_to_task):
                    task = future_to_task[future]
                    try:
                        result = future.result(timeout=1)
                        self._handle_result(result)
                    except Exception as e:
                        logger.error(f"任务 {task.file_path} 产生未捕获异常: {e}", exc_info=True)
                        self.stats['failed_files'] += 1
                        error = FileError(file_path=task.file_path, operation=type(e).__name__, original_error=e)
                        self.error_collector.add_error(error)

        # 最终清理和报告
        end_time = time.time()
        self.stats['total_processing_time'] = end_time - start_time
        
        return self._build_summary()
    
    def _handle_result(self, result: ProcessingResult):
        """处理单个文件的执行结果"""
        if result.success:
            self.stats['successful_files'] += 1
            if result.decode_result:
                self.stats['total_packets'] += result.decode_result.packet_count
            logger.debug(f"成功处理: {result.task.file_path}")
        else:
            self.stats['failed_files'] += 1
            error = FileError(
                file_path=result.task.file_path,
                operation="文件处理",
                original_error=Exception(result.error)
            )
            self.error_collector.add_error(error)
            logger.warning(f"处理失败: {result.task.file_path} - {result.error}")

    def _build_summary(self) -> Dict[str, Any]:
        """构建处理结果摘要（增强版）"""
        total_files = self.stats['total_files']
        successful_files = self.stats['successful_files']
        failed_files = self.stats['failed_files']
        skipped_files = self.stats['skipped_files']
        total_packets = self.stats['total_packets']
        total_time = self.stats['total_processing_time']
        
        # 计算性能指标
        processed_files = successful_files + failed_files
        success_rate = (successful_files / processed_files * 100) if processed_files > 0 else 0
        avg_packets_per_file = (total_packets / successful_files) if successful_files > 0 else 0
        avg_time_per_file = (total_time / processed_files) if processed_files > 0 else 0
        packets_per_second = (total_packets / total_time) if total_time > 0 else 0
        parallelization_efficiency = min(100, round(processed_files / total_time / self.max_workers * 100, 1))
        
        # 性能指标
        performance_metrics = {
            'total_processing_time': total_time,
            'packets_per_second': packets_per_second,
            'average_time_per_file': avg_time_per_file,
            'parallelization_efficiency': parallelization_efficiency
        }
        
        # 资源使用情况
        resource_summary = {}
        if self.resource_manager and self.resource_manager.monitor:
            resource_summary = self.resource_manager.monitor.get_usage_summary()

        # 构建最终报告
        summary = {
            'processing_summary': {
                'total_files': total_files,
                'successful_files': successful_files,
                'failed_files': failed_files,
                'skipped_files': skipped_files,
                'success_rate': round(success_rate, 1),
                'total_packets_processed': total_packets,
                'total_processing_time': round(total_time, 3)
            },
            'performance_metrics': performance_metrics,
            'resource_metrics': resource_summary,
            'configuration': {
                'max_workers': self.max_workers,
                'task_timeout': self.task_timeout,
                'max_packets_per_file': self.max_packets,
                'output_directory': str(self.output_dir)
            },
            'error_summary': self.error_collector.get_error_summary()
        }
        
        return summary
    
    def cleanup(self):
        """清理资源"""
        logger.info("清理批量处理器资源...")
        self.resource_manager.cleanup_all()
        self.error_collector.clear()
    
    def __enter__(self):
        """上下文管理器入口"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器退出"""
        self.cleanup()


# 为了向后兼容，保留原始BatchProcessor
BatchProcessor = EnhancedBatchProcessor 