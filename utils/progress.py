"""
进度跟踪器模块
提供文件处理的进度显示功能，支持多进程进度合并和实时状态监控
"""

import logging
from typing import Optional, List, Dict, Any, Callable
from tqdm import tqdm
import time
import threading
import multiprocessing as mp
from collections import deque
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ProgressUpdate:
    """进度更新数据类"""
    file_path: str
    success: bool
    packets: int = 0
    processing_time: float = 0.0
    error_msg: Optional[str] = None
    worker_id: Optional[int] = None


class RealTimeProgressMonitor:
    """实时进度监控器，支持多进程环境"""
    
    def __init__(self, 
                 verbose: bool = False,
                 update_interval: float = 0.5,
                 show_detailed_stats: bool = True):
        """
        初始化实时进度监控器
        
        Args:
            verbose: 是否显示详细信息
            update_interval: 更新间隔（秒）
            show_detailed_stats: 是否显示详细统计
        """
        self.verbose = verbose
        self.update_interval = update_interval
        self.show_detailed_stats = show_detailed_stats
        
        # 进度数据
        self.total_files = 0
        self.processed_files = 0
        self.successful_files = 0
        self.failed_files = 0
        self.total_packets = 0
        self.total_processing_time = 0.0
        
        # 实时统计
        self.start_time = None
        self.recent_updates = deque(maxlen=50)  # 保存最近50个更新
        self.workers_status = {}  # 工作进程状态
        
        # UI组件
        self.progress_bar = None
        self.stats_thread = None
        self.stop_monitoring = False
        
        # 锁
        self._lock = threading.Lock()
    
    def start_monitoring(self, total_files: int, description: str = "处理PCAP文件"):
        """
        开始监控
        
        Args:
            total_files: 总文件数
            description: 任务描述
        """
        with self._lock:
            self.total_files = total_files
            self.processed_files = 0
            self.successful_files = 0
            self.failed_files = 0
            self.total_packets = 0
            self.total_processing_time = 0.0
            self.start_time = time.time()
            self.recent_updates.clear()
            self.workers_status.clear()
            self.stop_monitoring = False
        
        if self.verbose:
            print(f"\n🚀 开始批量处理: {description}")
            print(f"📁 总文件数: {total_files}")
            print(f"⚙️  处理模式: 多进程并行")
            print("-" * 60)
            
            # 创建进度条
            self.progress_bar = tqdm(
                total=total_files,
                desc="📦 处理进度",
                unit="文件",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
            )
            
            # 启动实时统计线程
            if self.show_detailed_stats:
                self.stats_thread = threading.Thread(target=self._stats_monitor, daemon=True)
                self.stats_thread.start()
    
    def update_progress(self, update: ProgressUpdate):
        """
        更新进度
        
        Args:
            update: 进度更新数据
        """
        with self._lock:
            self.processed_files += 1
            self.total_packets += update.packets
            self.total_processing_time += update.processing_time
            
            if update.success:
                self.successful_files += 1
            else:
                self.failed_files += 1
            
            # 记录最近更新
            update_with_timestamp = {
                'timestamp': time.time(),
                'file_path': update.file_path,
                'success': update.success,
                'packets': update.packets,
                'processing_time': update.processing_time,
                'worker_id': update.worker_id
            }
            self.recent_updates.append(update_with_timestamp)
            
            # 更新工作进程状态
            if update.worker_id:
                self.workers_status[update.worker_id] = {
                    'last_file': update.file_path,
                    'last_update': time.time(),
                    'status': 'completed' if update.success else 'failed'
                }
        
        # 更新UI
        if self.progress_bar:
            file_name = update.file_path.split('/')[-1]
            status_icon = "✅" if update.success else "❌"
            
            postfix = {
                '成功': self.successful_files,
                '失败': self.failed_files,
                '包数': self.total_packets
            }
            
            self.progress_bar.set_postfix(postfix)
            self.progress_bar.set_description(f"📦 {status_icon} {file_name[:25]}...")
            self.progress_bar.update(1)
            
            # 错误详情
            if not update.success and update.error_msg and self.verbose:
                tqdm.write(f"❌ 处理失败: {file_name} - {update.error_msg}")
    
    def _stats_monitor(self):
        """实时统计监控线程"""
        while not self.stop_monitoring and self.processed_files < self.total_files:
            time.sleep(self.update_interval)
            
            if self.processed_files == 0:
                continue
                
            # 计算实时统计
            current_time = time.time()
            elapsed_time = current_time - self.start_time
            
            # 计算最近的处理速度
            recent_speed = self._calculate_recent_speed()
            
            # 估算剩余时间
            remaining_files = self.total_files - self.processed_files
            if recent_speed > 0:
                eta = remaining_files / recent_speed
                eta_str = f"{eta:.0f}s"
            else:
                eta_str = "unknown"
            
            # 显示实时统计
            if self.verbose and self.processed_files > 0:
                tqdm.write(
                    f"📊 实时统计: "
                    f"速度 {recent_speed:.1f}文件/s | "
                    f"平均包数 {self.total_packets/self.processed_files:.0f} | "
                    f"ETA {eta_str}"
                )
    
    def _calculate_recent_speed(self) -> float:
        """计算最近的处理速度"""
        if len(self.recent_updates) < 2:
            return 0.0
        
        # 使用最近10个更新计算速度
        recent_count = min(10, len(self.recent_updates))
        recent_items = list(self.recent_updates)[-recent_count:]
        
        if len(recent_items) < 2:
            return 0.0
        
        time_span = recent_items[-1]['timestamp'] - recent_items[0]['timestamp']
        if time_span > 0:
            return (len(recent_items) - 1) / time_span
        return 0.0
    
    def finish_monitoring(self) -> Dict[str, Any]:
        """
        完成监控并返回统计信息
        
        Returns:
            Dict[str, Any]: 详细统计信息
        """
        self.stop_monitoring = True
        
        if self.progress_bar:
            self.progress_bar.close()
        
        if self.stats_thread and self.stats_thread.is_alive():
            self.stats_thread.join(timeout=1.0)
        
        # 计算最终统计
        end_time = time.time()
        total_elapsed = end_time - self.start_time if self.start_time else 0
        
        success_rate = (self.successful_files / self.processed_files * 100) if self.processed_files > 0 else 0
        avg_packets_per_file = self.total_packets / self.successful_files if self.successful_files > 0 else 0
        overall_speed = self.processed_files / total_elapsed if total_elapsed > 0 else 0
        packets_per_second = self.total_packets / self.total_processing_time if self.total_processing_time > 0 else 0
        
        stats = {
            'files': {
                'total': self.total_files,
                'processed': self.processed_files,
                'successful': self.successful_files,
                'failed': self.failed_files,
                'success_rate': round(success_rate, 1)
            },
            'packets': {
                'total_packets': self.total_packets,
                'average_per_file': round(avg_packets_per_file, 1)
            },
            'timing': {
                'total_elapsed_time': round(total_elapsed, 3),
                'total_processing_time': round(self.total_processing_time, 3),
                'average_time_per_file': round(self.total_processing_time / self.processed_files, 3) if self.processed_files > 0 else 0
            },
            'performance': {
                'files_per_second': round(overall_speed, 2),
                'packets_per_second': round(packets_per_second, 1),
                'parallelization_efficiency': round((self.total_processing_time / total_elapsed) * 100, 1) if total_elapsed > 0 else 0
            }
        }
        
        if self.verbose:
            self._print_final_summary(stats)
        
        return stats
    
    def _print_final_summary(self, stats: Dict[str, Any]):
        """打印最终摘要"""
        print("\n" + "=" * 60)
        print("🎉 批量处理完成!")
        print("=" * 60)
        
        # 文件统计
        print(f"📁 文件处理统计:")
        print(f"   总文件数: {stats['files']['total']}")
        print(f"   处理成功: {stats['files']['successful']} ✅")
        print(f"   处理失败: {stats['files']['failed']} ❌")
        print(f"   成功率: {stats['files']['success_rate']}%")
        
        # 数据包统计
        print(f"\n📦 数据包统计:")
        print(f"   总包数: {stats['packets']['total_packets']:,}")
        print(f"   平均包数/文件: {stats['packets']['average_per_file']}")
        
        # 性能统计
        print(f"\n⚡ 性能指标:")
        print(f"   总耗时: {stats['timing']['total_elapsed_time']}s")
        print(f"   处理速度: {stats['performance']['files_per_second']} 文件/s")
        print(f"   包处理速度: {stats['performance']['packets_per_second']} 包/s")
        print(f"   并行效率: {stats['performance']['parallelization_efficiency']}%")
        
        print("=" * 60)


class ProgressTracker:
    """兼容性进度跟踪器（保持向后兼容）"""
    
    def __init__(self, verbose: bool = False):
        """
        初始化进度跟踪器
        
        Args:
            verbose: 是否显示详细信息
        """
        self.monitor = RealTimeProgressMonitor(verbose=verbose, show_detailed_stats=False)
        self.file_list = []
    
    def start_batch(self, file_list: List[str], description: str = "处理PCAP文件"):
        """
        开始批量处理
        
        Args:
            file_list: 文件列表
            description: 任务描述
        """
        self.file_list = file_list
        self.monitor.start_monitoring(len(file_list), description)
    
    def update_progress(self, file_path: str, success: bool = True, error_msg: str = None):
        """
        更新处理进度
        
        Args:
            file_path: 当前处理的文件路径
            success: 是否处理成功
            error_msg: 错误信息（如果有）
        """
        update = ProgressUpdate(
            file_path=file_path,
            success=success,
            error_msg=error_msg
        )
        self.monitor.update_progress(update)
    
    def finish_batch(self):
        """完成批量处理"""
        return self.monitor.finish_monitoring()
    
    def get_statistics(self) -> dict:
        """
        获取处理统计信息
        
        Returns:
            dict: 统计信息字典
        """
        stats = self.monitor.finish_monitoring()
        
        # 转换为旧格式以保持兼容性
        return {
            'total_files': stats['files']['total'],
            'processed_files': stats['files']['processed'],
            'successful_files': stats['files']['successful'],
            'failed_files': stats['files']['failed'],
            'success_rate': stats['files']['success_rate'],
            'total_time': stats['timing']['total_elapsed_time'],
            'average_time_per_file': stats['timing']['average_time_per_file']
        }


class SimpleProgressBar:
    """简单进度条（用于非verbose模式）"""
    
    def __init__(self, total: int, description: str = "Processing"):
        """
        初始化简单进度条
        
        Args:
            total: 总数量
            description: 描述
        """
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = time.time()
    
    def update(self, n: int = 1):
        """更新进度"""
        self.current += n
        
        # 计算进度百分比
        progress = self.current / self.total if self.total > 0 else 0
        bar_length = 30
        filled_length = int(bar_length * progress)
        
        # 创建进度条
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        percent = progress * 100
        
        # 计算剩余时间
        elapsed_time = time.time() - self.start_time
        if self.current > 0:
            eta = elapsed_time * (self.total - self.current) / self.current
            eta_str = f" ETA: {eta:.0f}s"
        else:
            eta_str = ""
        
        # 输出进度条
        print(f'\r{self.description}: |{bar}| {self.current}/{self.total} ({percent:.1f}%){eta_str}', end='')
        
        if self.current >= self.total:
            print()  # 换行


# 工厂函数，用于创建适合的进度监控器
def create_progress_monitor(verbose: bool = False, 
                          multi_process: bool = False,
                          show_detailed_stats: bool = True) -> RealTimeProgressMonitor:
    """
    创建适合的进度监控器
    
    Args:
        verbose: 是否显示详细信息
        multi_process: 是否为多进程环境
        show_detailed_stats: 是否显示详细统计
        
    Returns:
        RealTimeProgressMonitor: 进度监控器实例
    """
    if multi_process:
        return RealTimeProgressMonitor(
            verbose=verbose, 
            show_detailed_stats=show_detailed_stats,
            update_interval=0.3  # 多进程环境下更频繁更新
        )
    else:
        return RealTimeProgressMonitor(
            verbose=verbose,
            show_detailed_stats=show_detailed_stats
        ) 