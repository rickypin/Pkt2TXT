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

from .scanner import DirectoryScanner
from .decoder import PacketDecoder, DecodeResult
from .extractor import ProtocolExtractor
from .formatter import JSONFormatter
from ..utils.resource_manager import ResourceManager, MemoryThresholds, DiskThresholds
from ..utils.errors import ErrorCollector, FileError, DecodeError

logger = logging.getLogger(__name__)


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


def process_single_file(task: ProcessingTask, timeout: int = 300) -> ProcessingResult:
    """
    处理单个文件的工作函数（用于多进程执行）
    
    Args:
        task: 处理任务
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
        initial_usage = resource_manager.monitor.get_current_usage()
        decode_result = decoder.decode_file(task.file_path)
        post_decode_usage = resource_manager.monitor.get_current_usage()
        
        # 提取协议字段
        for packet in decode_result.packets:
            extractor.extract_fields(packet)
        
        # 检查内存使用情况
        resource_manager.memory_manager.cleanup_if_needed()
        
        # 格式化并保存
        output_file = formatter.format_and_save(decode_result)
        final_usage = resource_manager.monitor.get_current_usage()
        
        processing_time = time.time() - start_time
        
        # 记录资源使用情况
        resource_usage.update({
            'initial_memory_mb': initial_usage.memory_mb,
            'post_decode_memory_mb': post_decode_usage.memory_mb,
            'final_memory_mb': final_usage.memory_mb,
            'memory_increase_mb': final_usage.memory_mb - initial_usage.memory_mb,
            'peak_memory_mb': max(initial_usage.memory_mb, post_decode_usage.memory_mb, final_usage.memory_mb)
        })
        
        logger.info(f"完成处理文件: {Path(task.file_path).name} ({processing_time:.3f}s, 内存增长: {resource_usage['memory_increase_mb']:.1f}MB)")
        
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
        return ProcessingResult(
            task=task,
            success=False,
            error=str(e),
            processing_time=time.time() - start_time,
            resource_usage=resource_usage
        )
        
    except Exception as e:
        logger.error(f"文件处理失败: {task.file_path} - {e}")
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
                 output_dir: str,
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
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.max_workers = max_workers or mp.cpu_count()
        self.task_timeout = task_timeout
        self.max_packets = max_packets
        
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
        
        for task in tasks:
            file_size_mb = self.resource_manager.file_handler.get_file_size_mb(task.file_path)
            total_size_mb += file_size_mb
            
            # 检查文件可处理性
            processability = self.resource_manager.check_file_processable(task.file_path)
            
            if processability['can_process']:
                processable_files.append(task)
                if processability['is_large_file']:
                    large_files.append(task)
            else:
                unprocessable_files.append((task, processability['recommendations']))
        
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
        """
        扫描输入目录并准备处理任务
        
        Args:
            input_dir: 输入目录路径
            
        Returns:
            List[ProcessingTask]: 任务列表
        """
        scanner = DirectoryScanner()
        files = scanner.scan_directory(input_dir, max_depth=2)
        
        tasks = []
        for i, file_path in enumerate(files):
            task = ProcessingTask(
                file_path=file_path,
                output_dir=str(self.output_dir),
                max_packets=self.max_packets,
                task_id=i
            )
            tasks.append(task)
        
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
        
        # 存储所有成功的解码结果
        successful_results = []
        
        # 动态调整工作进程数
        effective_workers = min(self.max_workers, analysis['recommended_workers'])
        logger.info(f"使用 {effective_workers} 个工作进程处理 {len(processable_tasks)} 个文件")
        
        # 使用进程池执行任务
        with ProcessPoolExecutor(max_workers=effective_workers) as executor:
            # 提交所有任务
            future_to_task = {
                executor.submit(process_single_file, task, self.task_timeout): task 
                for task in processable_tasks
            }
            
            # 处理完成的任务
            completed = 0
            for future in as_completed(future_to_task):
                task = future_to_task[future]
                completed += 1
                
                try:
                    result = future.result()
                    
                    # 更新资源使用统计
                    if result.resource_usage:
                        self.stats['peak_memory_mb'] = max(
                            self.stats['peak_memory_mb'],
                            result.resource_usage.get('peak_memory_mb', 0)
                        )
                    
                    if result.success:
                        self.stats['successful_files'] += 1
                        self.stats['total_packets'] += result.decode_result.packet_count
                        successful_results.append(result.decode_result)
                        logger.info(f"✅ [{completed}/{len(processable_tasks)}] {Path(task.file_path).name}")
                    else:
                        self.stats['failed_files'] += 1
                        
                        # 使用错误收集器记录错误
                        if "超时" in result.error:
                            error = FileError(task.file_path, "处理超时", Exception(result.error))
                        else:
                            error = DecodeError(task.file_path, original_error=Exception(result.error))
                        
                        self.error_collector.add_error(error, task.file_path)
                        logger.error(f"❌ [{completed}/{len(processable_tasks)}] {Path(task.file_path).name}: {result.error}")
                    
                    self.stats['total_processing_time'] += result.processing_time
                    
                except Exception as e:
                    self.stats['failed_files'] += 1
                    error = DecodeError(task.file_path, original_error=e)
                    self.error_collector.add_error(error, task.file_path)
                    logger.error(f"❌ [{completed}/{len(processable_tasks)}] {Path(task.file_path).name}: {e}")
                
                # 定期清理内存
                if completed % 5 == 0:
                    cleaned = self.resource_manager.memory_manager.cleanup_if_needed()
                    if cleaned:
                        self.stats['total_memory_cleaned_mb'] += 100  # 估算清理量
                
                # 调用进度回调
                if progress_callback:
                    progress_callback(completed, len(processable_tasks))
        
        # 生成汇总报告
        if successful_results:
            formatter = JSONFormatter(str(self.output_dir))
            summary_file = formatter.generate_summary_report(successful_results)
            logger.info(f"生成汇总报告: {summary_file}")
        
        # 保存错误报告
        if save_error_report and (self.error_collector.has_errors() or self.error_collector.has_warnings()):
            error_report_file = self.output_dir / "error_report.json"
            import json
            with open(error_report_file, 'w', encoding='utf-8') as f:
                json.dump(self.error_collector.generate_error_report(), f, indent=2, ensure_ascii=False)
            logger.info(f"生成错误报告: {error_report_file}")
        
        total_time = time.time() - start_time
        self.stats['total_processing_time'] = total_time
        
        return self._build_summary()
    
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
            'performance_metrics': {
                'average_packets_per_file': round(avg_packets_per_file, 1),
                'average_time_per_file': round(avg_time_per_file, 3),
                'packets_per_second': round(packets_per_second, 1),
                'parallelization_efficiency': min(100, round(processed_files / total_time / self.max_workers * 100, 1))
            },
            'resource_metrics': {
                'peak_memory_mb': round(self.stats['peak_memory_mb'], 1),
                'total_memory_cleaned_mb': round(self.stats['total_memory_cleaned_mb'], 1),
                'resource_status': self.resource_manager.get_comprehensive_status()
            },
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