"""
资源管理模块
实现内存监控、内存清理、磁盘空间检查等资源管理功能
"""

import gc
import logging
import os
import psutil
import shutil
import tempfile
import time
import threading
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass
import weakref

logger = logging.getLogger(__name__)


@dataclass
class ResourceUsage:
    """资源使用情况数据类"""
    memory_mb: float
    memory_percent: float
    cpu_percent: float
    disk_usage_gb: float
    disk_free_gb: float
    timestamp: float


@dataclass
class MemoryThresholds:
    """内存阈值配置"""
    warning_mb: float = 1000.0      # 内存警告阈值（MB）
    critical_mb: float = 2000.0     # 内存临界阈值（MB）
    cleanup_threshold: float = 80.0  # 触发清理的内存使用百分比


@dataclass
class DiskThresholds:
    """磁盘阈值配置"""
    min_free_gb: float = 1.0        # 最小可用磁盘空间（GB）
    warning_free_gb: float = 5.0    # 磁盘空间警告阈值（GB）


class ResourceMonitor:
    """资源监控器"""
    
    def __init__(self, 
                 monitoring_interval: float = 5.0,
                 memory_thresholds: Optional[MemoryThresholds] = None,
                 disk_thresholds: Optional[DiskThresholds] = None):
        """
        初始化资源监控器
        
        Args:
            monitoring_interval: 监控间隔（秒）
            memory_thresholds: 内存阈值配置
            disk_thresholds: 磁盘阈值配置
        """
        self.monitoring_interval = monitoring_interval
        self.memory_thresholds = memory_thresholds or MemoryThresholds()
        self.disk_thresholds = disk_thresholds or DiskThresholds()
        
        self.is_monitoring = False
        self.monitor_thread = None
        self.usage_history: List[ResourceUsage] = []
        self.max_history_size = 100
        
        # 回调函数
        self.warning_callbacks: List[Callable[[str, ResourceUsage], None]] = []
        self.critical_callbacks: List[Callable[[str, ResourceUsage], None]] = []
        
        self.process = psutil.Process()
    
    def get_current_usage(self) -> ResourceUsage:
        """获取当前资源使用情况"""
        memory_info = self.process.memory_info()
        memory_mb = memory_info.rss / 1024 / 1024
        memory_percent = self.process.memory_percent()
        
        try:
            cpu_percent = self.process.cpu_percent()
        except psutil.ZombieProcess:
            cpu_percent = 0.0
        
        disk_usage = shutil.disk_usage('.')
        disk_total_gb = disk_usage.total / 1024**3
        disk_free_gb = disk_usage.free / 1024**3
        disk_used_gb = disk_total_gb - disk_free_gb
        
        return ResourceUsage(
            memory_mb=memory_mb,
            memory_percent=memory_percent,
            cpu_percent=cpu_percent,
            disk_usage_gb=disk_used_gb,
            disk_free_gb=disk_free_gb,
            timestamp=time.time()
        )
    
    def check_thresholds(self, usage: ResourceUsage):
        """检查资源使用阈值"""
        # 检查内存阈值
        if usage.memory_mb >= self.memory_thresholds.critical_mb:
            self._trigger_critical_callbacks("内存使用量超过临界阈值", usage)
        elif usage.memory_mb >= self.memory_thresholds.warning_mb:
            self._trigger_warning_callbacks("内存使用量超过警告阈值", usage)
        
        # 检查磁盘空间
        if usage.disk_free_gb <= self.disk_thresholds.min_free_gb:
            self._trigger_critical_callbacks("磁盘可用空间不足", usage)
        elif usage.disk_free_gb <= self.disk_thresholds.warning_free_gb:
            self._trigger_warning_callbacks("磁盘可用空间较少", usage)
    
    def add_warning_callback(self, callback: Callable[[str, ResourceUsage], None]):
        """添加警告回调函数"""
        self.warning_callbacks.append(callback)
    
    def add_critical_callback(self, callback: Callable[[str, ResourceUsage], None]):
        """添加临界情况回调函数"""
        self.critical_callbacks.append(callback)
    
    def _trigger_warning_callbacks(self, message: str, usage: ResourceUsage):
        """触发警告回调"""
        logger.warning(f"资源警告: {message} - 内存: {usage.memory_mb:.1f}MB, 磁盘剩余: {usage.disk_free_gb:.1f}GB")
        for callback in self.warning_callbacks:
            try:
                callback(message, usage)
            except Exception as e:
                logger.error(f"警告回调执行失败: {e}")
    
    def _trigger_critical_callbacks(self, message: str, usage: ResourceUsage):
        """触发临界情况回调"""
        logger.critical(f"资源临界: {message} - 内存: {usage.memory_mb:.1f}MB, 磁盘剩余: {usage.disk_free_gb:.1f}GB")
        for callback in self.critical_callbacks:
            try:
                callback(message, usage)
            except Exception as e:
                logger.error(f"临界回调执行失败: {e}")
    
    def start_monitoring(self):
        """开始监控"""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("资源监控已启动")
    
    def stop_monitoring(self):
        """停止监控"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=self.monitoring_interval + 1)
        logger.info("资源监控已停止")
    
    def _monitor_loop(self):
        """监控循环"""
        while self.is_monitoring:
            try:
                usage = self.get_current_usage()
                
                # 添加到历史记录
                self.usage_history.append(usage)
                if len(self.usage_history) > self.max_history_size:
                    self.usage_history.pop(0)
                
                # 检查阈值
                self.check_thresholds(usage)
                
                time.sleep(self.monitoring_interval)
                
            except Exception as e:
                logger.error(f"资源监控出错: {e}")
                time.sleep(self.monitoring_interval)
    
    def get_usage_summary(self) -> Dict[str, Any]:
        """获取资源使用汇总"""
        if not self.usage_history:
            current = self.get_current_usage()
            return {
                'current': current,
                'peak_memory_mb': current.memory_mb,
                'avg_memory_mb': current.memory_mb,
                'min_disk_free_gb': current.disk_free_gb,
                'monitoring_duration': 0.0
            }
        
        memory_values = [u.memory_mb for u in self.usage_history]
        disk_values = [u.disk_free_gb for u in self.usage_history]
        
        duration = self.usage_history[-1].timestamp - self.usage_history[0].timestamp
        
        return {
            'current': self.usage_history[-1],
            'peak_memory_mb': max(memory_values),
            'avg_memory_mb': sum(memory_values) / len(memory_values),
            'min_disk_free_gb': min(disk_values),
            'monitoring_duration': duration,
            'sample_count': len(self.usage_history)
        }


class MemoryManager:
    """内存管理器"""
    
    def __init__(self):
        """初始化内存管理器"""
        self.object_pools = {}
        self.cleanup_callbacks: List[Callable[[], None]] = []
        self.weak_references: List[weakref.ref] = []
    
    def register_cleanup_callback(self, callback: Callable[[], None]):
        """注册清理回调函数"""
        self.cleanup_callbacks.append(callback)
    
    def add_weak_reference(self, obj):
        """添加弱引用跟踪"""
        self.weak_references.append(weakref.ref(obj))
    
    def force_garbage_collection(self) -> Dict[str, int]:
        """强制垃圾回收"""
        logger.info("执行强制垃圾回收...")
        
        # 清理已失效的弱引用
        alive_refs = []
        for ref in self.weak_references:
            if ref() is not None:
                alive_refs.append(ref)
        self.weak_references = alive_refs
        
        # 执行清理回调
        for callback in self.cleanup_callbacks:
            try:
                callback()
            except Exception as e:
                logger.error(f"清理回调执行失败: {e}")
        
        # 多轮垃圾回收
        collected = {}
        for generation in range(3):
            count = gc.collect(generation)
            collected[f'generation_{generation}'] = count
        
        total_collected = sum(collected.values())
        logger.info(f"垃圾回收完成: 清理了 {total_collected} 个对象")
        
        return collected
    
    def get_memory_stats(self) -> Dict[str, Any]:
        """获取内存统计信息"""
        import sys
        
        # 获取垃圾回收统计
        gc_stats = gc.get_stats()
        
        # 获取进程内存信息
        process = psutil.Process()
        memory_info = process.memory_info()
        
        return {
            'rss_mb': memory_info.rss / 1024 / 1024,
            'vms_mb': memory_info.vms / 1024 / 1024,
            'memory_percent': process.memory_percent(),
            'gc_stats': gc_stats,
            'ref_count': sys.getrefcount,
            'weak_refs_count': len(self.weak_references),
            'cleanup_callbacks_count': len(self.cleanup_callbacks)
        }
    
    def cleanup_if_needed(self, threshold_mb: float = 1000.0) -> bool:
        """根据需要执行清理"""
        process = psutil.Process()
        current_memory_mb = process.memory_info().rss / 1024 / 1024
        
        if current_memory_mb > threshold_mb:
            logger.info(f"内存使用 {current_memory_mb:.1f}MB 超过阈值 {threshold_mb}MB，开始清理")
            self.force_garbage_collection()
            
            # 检查清理效果
            new_memory_mb = process.memory_info().rss / 1024 / 1024
            freed_mb = current_memory_mb - new_memory_mb
            logger.info(f"内存清理完成: 释放了 {freed_mb:.1f}MB，当前使用 {new_memory_mb:.1f}MB")
            
            return True
        
        return False


class LargeFileHandler:
    """大文件处理器"""
    
    def __init__(self, 
                 chunk_size_mb: float = 100.0,
                 temp_dir: Optional[str] = None,
                 max_file_size_mb: float = 1000.0):
        """
        初始化大文件处理器
        
        Args:
            chunk_size_mb: 分块大小（MB）
            temp_dir: 临时目录
            max_file_size_mb: 最大文件大小（MB）
        """
        self.chunk_size_bytes = int(chunk_size_mb * 1024 * 1024)
        self.temp_dir = Path(temp_dir) if temp_dir else Path(tempfile.gettempdir())
        self.max_file_size_bytes = int(max_file_size_mb * 1024 * 1024)
        self.temp_files: List[Path] = []
    
    def is_large_file(self, file_path: str) -> bool:
        """检查是否为大文件"""
        try:
            file_size = Path(file_path).stat().st_size
            return file_size > self.max_file_size_bytes
        except OSError:
            return False
    
    def get_file_size_mb(self, file_path: str) -> float:
        """获取文件大小（MB）"""
        try:
            return Path(file_path).stat().st_size / 1024 / 1024
        except OSError:
            return 0.0
    
    def create_temp_file(self, suffix: str = '.tmp') -> Path:
        """创建临时文件"""
        temp_file = self.temp_dir / f"pcap_decoder_{int(time.time())}_{len(self.temp_files)}{suffix}"
        self.temp_files.append(temp_file)
        return temp_file
    
    def cleanup_temp_files(self):
        """清理临时文件"""
        cleaned = 0
        for temp_file in self.temp_files:
            try:
                if temp_file.exists():
                    temp_file.unlink()
                    cleaned += 1
            except Exception as e:
                logger.warning(f"清理临时文件失败: {temp_file} - {e}")
        
        self.temp_files.clear()
        if cleaned > 0:
            logger.info(f"清理了 {cleaned} 个临时文件")
    
    def estimate_processing_memory(self, file_path: str) -> float:
        """估算处理文件所需的内存（MB）"""
        file_size_mb = self.get_file_size_mb(file_path)
        # 经验估算：文件大小的2-3倍内存用于解析和处理
        estimated_memory_mb = file_size_mb * 2.5
        return estimated_memory_mb


class ResourceManager:
    """综合资源管理器"""
    
    def __init__(self,
                 memory_thresholds: Optional[MemoryThresholds] = None,
                 disk_thresholds: Optional[DiskThresholds] = None,
                 enable_monitoring: bool = True):
        """
        初始化资源管理器
        
        Args:
            memory_thresholds: 内存阈值配置
            disk_thresholds: 磁盘阈值配置
            enable_monitoring: 是否启用监控
        """
        self.monitor = ResourceMonitor(
            memory_thresholds=memory_thresholds,
            disk_thresholds=disk_thresholds
        )
        self.memory_manager = MemoryManager()
        self.file_handler = LargeFileHandler()
        
        # 注册资源管理回调
        self.monitor.add_warning_callback(self._handle_resource_warning)
        self.monitor.add_critical_callback(self._handle_resource_critical)
        
        if enable_monitoring:
            self.monitor.start_monitoring()
    
    def _handle_resource_warning(self, message: str, usage: ResourceUsage):
        """处理资源警告"""
        logger.warning(f"资源警告: {message}")
        # 尝试清理内存
        if usage.memory_percent > 70:
            self.memory_manager.cleanup_if_needed(usage.memory_mb * 0.8)
    
    def _handle_resource_critical(self, message: str, usage: ResourceUsage):
        """处理资源临界情况"""
        logger.critical(f"资源临界: {message}")
        # 强制清理内存
        self.memory_manager.force_garbage_collection()
        # 清理临时文件
        self.file_handler.cleanup_temp_files()
    
    def check_file_processable(self, file_path: str) -> Dict[str, Any]:
        """检查文件是否可以处理"""
        file_size_mb = self.file_handler.get_file_size_mb(file_path)
        estimated_memory_mb = self.file_handler.estimate_processing_memory(file_path)
        current_usage = self.monitor.get_current_usage()
        
        # 检查可用内存
        available_memory_mb = (100 - current_usage.memory_percent) * current_usage.memory_mb / current_usage.memory_percent
        memory_sufficient = available_memory_mb > estimated_memory_mb
        
        # 检查磁盘空间
        required_disk_gb = file_size_mb / 1024 * 1.5  # 估计需要1.5倍的输出空间
        disk_sufficient = current_usage.disk_free_gb > required_disk_gb
        
        return {
            'file_size_mb': file_size_mb,
            'estimated_memory_mb': estimated_memory_mb,
            'available_memory_mb': available_memory_mb,
            'memory_sufficient': memory_sufficient,
            'disk_sufficient': disk_sufficient,
            'is_large_file': self.file_handler.is_large_file(file_path),
            'can_process': memory_sufficient and disk_sufficient,
            'recommendations': self._get_processing_recommendations(
                file_size_mb, estimated_memory_mb, available_memory_mb, disk_sufficient
            )
        }
    
    def _get_processing_recommendations(self, file_size_mb: float, estimated_memory_mb: float,
                                       available_memory_mb: float, disk_sufficient: bool) -> List[str]:
        """获取处理建议"""
        recommendations = []
        
        if estimated_memory_mb > available_memory_mb:
            recommendations.append("建议先清理内存或等待其他任务完成")
            recommendations.append(f"需要内存: {estimated_memory_mb:.1f}MB, 可用: {available_memory_mb:.1f}MB")
        
        if not disk_sufficient:
            recommendations.append("磁盘空间不足，建议清理临时文件或更换输出目录")
        
        if file_size_mb > 500:
            recommendations.append("文件较大，建议使用流式处理或限制包数量")
        
        return recommendations
    
    def get_comprehensive_status(self) -> Dict[str, Any]:
        """获取综合资源状态"""
        return {
            'monitor_summary': self.monitor.get_usage_summary(),
            'memory_stats': self.memory_manager.get_memory_stats(),
            'temp_files_count': len(self.file_handler.temp_files),
            'thresholds': {
                'memory': {
                    'warning_mb': self.monitor.memory_thresholds.warning_mb,
                    'critical_mb': self.monitor.memory_thresholds.critical_mb
                },
                'disk': {
                    'min_free_gb': self.monitor.disk_thresholds.min_free_gb,
                    'warning_free_gb': self.monitor.disk_thresholds.warning_free_gb
                }
            }
        }
    
    def cleanup_all(self):
        """清理所有资源"""
        logger.info("开始全面资源清理...")
        
        # 停止监控
        self.monitor.stop_monitoring()
        
        # 清理内存
        self.memory_manager.force_garbage_collection()
        
        # 清理临时文件
        self.file_handler.cleanup_temp_files()
        
        logger.info("全面资源清理完成")
    
    def __enter__(self):
        """上下文管理器入口"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器退出"""
        self.cleanup_all() 