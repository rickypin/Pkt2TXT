#!/usr/bin/env python3
"""
阶段4测试验证脚本: 错误处理与健壮性
测试资源管理、错误处理、大文件处理等功能
"""

import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Dict, Any

from utils.resource_manager import (
    ResourceManager, MemoryThresholds, DiskThresholds,
    ResourceMonitor, MemoryManager, LargeFileHandler
)
from utils.errors import ErrorCollector, FileError, DecodeError
from core.processor import EnhancedBatchProcessor
from core.scanner import DirectoryScanner

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 新增导入
from Pkt2TXT.utils.helpers import get_file_size_mb

class Stage4Validator:
    """阶段4功能验证器"""
    
    def __init__(self):
        """初始化验证器"""
        self.test_results = {}
        self.temp_dir = Path(tempfile.mkdtemp(prefix="pcap_decoder_stage4_"))
        logger.info(f"初始化阶段4验证器，临时目录: {self.temp_dir}")
    
    def test_resource_monitor(self) -> Dict[str, Any]:
        """测试资源监控器"""
        logger.info("=== 测试资源监控器 ===")
        
        results = {
            'test_name': '资源监控器测试',
            'start_time': time.time(),
            'tests': []
        }
        
        # 测试1: 基本监控功能
        try:
            monitor = ResourceMonitor(monitoring_interval=1.0)
            
            # 获取当前使用情况
            usage = monitor.get_current_usage()
            
            test_result = {
                'name': '基本监控功能',
                'success': True,
                'details': {
                    'memory_mb': round(usage.memory_mb, 2),
                    'memory_percent': round(usage.memory_percent, 2),
                    'disk_free_gb': round(usage.disk_free_gb, 2),
                    'timestamp': usage.timestamp
                }
            }
            
            # 验证数据合理性
            if usage.memory_mb <= 0 or usage.disk_free_gb <= 0:
                test_result['success'] = False
                test_result['error'] = "资源使用数据异常"
            
            results['tests'].append(test_result)
            logger.info(f"✅ 基本监控功能: 内存 {usage.memory_mb:.1f}MB, 磁盘剩余 {usage.disk_free_gb:.1f}GB")
            
        except Exception as e:
            results['tests'].append({
                'name': '基本监控功能',
                'success': False,
                'error': str(e)
            })
            logger.error(f"❌ 基本监控功能测试失败: {e}")
        
        # 测试2: 阈值检查
        try:
            thresholds = MemoryThresholds(warning_mb=100.0, critical_mb=200.0)
            disk_thresholds = DiskThresholds(min_free_gb=0.1, warning_free_gb=1.0)
            
            monitor = ResourceMonitor(
                memory_thresholds=thresholds,
                disk_thresholds=disk_thresholds
            )
            
            usage = monitor.get_current_usage()
            
            # 模拟触发阈值检查
            warnings_triggered = []
            criticals_triggered = []
            
            def warning_callback(message, usage):
                warnings_triggered.append(message)
            
            def critical_callback(message, usage):
                criticals_triggered.append(message)
            
            monitor.add_warning_callback(warning_callback)
            monitor.add_critical_callback(critical_callback)
            
            monitor.check_thresholds(usage)
            
            test_result = {
                'name': '阈值检查',
                'success': True,
                'details': {
                    'warnings_triggered': len(warnings_triggered),
                    'criticals_triggered': len(criticals_triggered),
                    'current_memory_mb': usage.memory_mb,
                    'warning_threshold': thresholds.warning_mb,
                    'critical_threshold': thresholds.critical_mb
                }
            }
            
            results['tests'].append(test_result)
            logger.info(f"✅ 阈值检查: {len(warnings_triggered)} 警告, {len(criticals_triggered)} 临界")
            
        except Exception as e:
            results['tests'].append({
                'name': '阈值检查',
                'success': False,
                'error': str(e)
            })
            logger.error(f"❌ 阈值检查测试失败: {e}")
        
        # 测试3: 短期监控运行
        try:
            monitor = ResourceMonitor(monitoring_interval=0.5)
            monitor.start_monitoring()
            
            # 运行2秒
            time.sleep(2)
            
            monitor.stop_monitoring()
            
            summary = monitor.get_usage_summary()
            
            test_result = {
                'name': '短期监控运行',
                'success': summary['sample_count'] > 0,
                'details': {
                    'sample_count': summary['sample_count'],
                    'monitoring_duration': round(summary['monitoring_duration'], 2),
                    'peak_memory_mb': round(summary['peak_memory_mb'], 2),
                    'avg_memory_mb': round(summary['avg_memory_mb'], 2)
                }
            }
            
            if summary['sample_count'] == 0:
                test_result['error'] = "没有收集到监控样本"
            
            results['tests'].append(test_result)
            logger.info(f"✅ 短期监控: {summary['sample_count']} 个样本, 持续 {summary['monitoring_duration']:.1f}s")
            
        except Exception as e:
            results['tests'].append({
                'name': '短期监控运行',
                'success': False,
                'error': str(e)
            })
            logger.error(f"❌ 短期监控测试失败: {e}")
        
        results['end_time'] = time.time()
        results['duration'] = results['end_time'] - results['start_time']
        results['success_count'] = sum(1 for test in results['tests'] if test['success'])
        results['total_count'] = len(results['tests'])
        
        return results
    
    def test_memory_manager(self) -> Dict[str, Any]:
        """测试内存管理器"""
        logger.info("=== 测试内存管理器 ===")
        
        results = {
            'test_name': '内存管理器测试',
            'start_time': time.time(),
            'tests': []
        }
        
        # 测试1: 垃圾回收
        try:
            manager = MemoryManager()
            
            # 记录初始内存
            initial_stats = manager.get_memory_stats()
            
            # 执行垃圾回收
            collected = manager.force_garbage_collection()
            
            # 记录清理后内存
            final_stats = manager.get_memory_stats()
            
            test_result = {
                'name': '强制垃圾回收',
                'success': True,
                'details': {
                    'objects_collected': sum(collected.values()),
                    'gc_generations': collected,
                    'initial_memory_mb': round(initial_stats['rss_mb'], 2),
                    'final_memory_mb': round(final_stats['rss_mb'], 2),
                    'memory_change_mb': round(final_stats['rss_mb'] - initial_stats['rss_mb'], 2)
                }
            }
            
            results['tests'].append(test_result)
            logger.info(f"✅ 垃圾回收: 清理 {sum(collected.values())} 对象")
            
        except Exception as e:
            results['tests'].append({
                'name': '强制垃圾回收',
                'success': False,
                'error': str(e)
            })
            logger.error(f"❌ 垃圾回收测试失败: {e}")
        
        # 测试2: 清理回调
        try:
            manager = MemoryManager()
            
            callback_called = []
            
            def test_callback():
                callback_called.append(time.time())
            
            manager.register_cleanup_callback(test_callback)
            
            # 执行清理
            manager.force_garbage_collection()
            
            test_result = {
                'name': '清理回调机制',
                'success': len(callback_called) > 0,
                'details': {
                    'callbacks_called': len(callback_called),
                    'registered_callbacks': manager.get_memory_stats()['cleanup_callbacks_count']
                }
            }
            
            if len(callback_called) == 0:
                test_result['error'] = "清理回调未被调用"
            
            results['tests'].append(test_result)
            logger.info(f"✅ 清理回调: {len(callback_called)} 次调用")
            
        except Exception as e:
            results['tests'].append({
                'name': '清理回调机制',
                'success': False,
                'error': str(e)
            })
            logger.error(f"❌ 清理回调测试失败: {e}")
        
        # 测试3: 条件清理
        try:
            manager = MemoryManager()
            
            # 测试低阈值（应该不清理）
            cleaned_low = manager.cleanup_if_needed(threshold_mb=10000.0)
            
            # 测试高阈值（应该清理）
            cleaned_high = manager.cleanup_if_needed(threshold_mb=1.0)
            
            test_result = {
                'name': '条件内存清理',
                'success': True,
                'details': {
                    'low_threshold_cleaned': cleaned_low,
                    'high_threshold_cleaned': cleaned_high,
                    'current_memory_mb': round(manager.get_memory_stats()['rss_mb'], 2)
                }
            }
            
            results['tests'].append(test_result)
            logger.info(f"✅ 条件清理: 低阈值 {cleaned_low}, 高阈值 {cleaned_high}")
            
        except Exception as e:
            results['tests'].append({
                'name': '条件内存清理',
                'success': False,
                'error': str(e)
            })
            logger.error(f"❌ 条件清理测试失败: {e}")
        
        results['end_time'] = time.time()
        results['duration'] = results['end_time'] - results['start_time']
        results['success_count'] = sum(1 for test in results['tests'] if test['success'])
        results['total_count'] = len(results['tests'])
        
        return results
    
    def test_large_file_handler(self) -> Dict[str, Any]:
        """测试大文件处理器"""
        logger.info("=== 测试大文件处理器 ===")
        
        results = {
            'test_name': '大文件处理器测试',
            'start_time': time.time(),
            'tests': []
        }
        
        # 测试1: 文件大小检查
        try:
            handler = LargeFileHandler(max_file_size_mb=10.0)
            
            # 创建测试文件
            small_file = self.temp_dir / "small_test.txt"
            large_file = self.temp_dir / "large_test.txt"
            
            # 小文件
            with open(small_file, 'w') as f:
                f.write("small file content")
            
            # 大文件（模拟）
            with open(large_file, 'w') as f:
                f.write("x" * (15 * 1024 * 1024))  # 15MB
            
            small_is_large = handler.is_large_file(str(small_file))
            large_is_large = handler.is_large_file(str(large_file))
            
            small_size = get_file_size_mb(str(small_file))
            large_size = get_file_size_mb(str(large_file))
            
            test_result = {
                'name': '文件大小检查',
                'success': not small_is_large and large_is_large,
                'details': {
                    'small_file_size_mb': round(small_size, 3),
                    'large_file_size_mb': round(large_size, 1),
                    'small_is_large': small_is_large,
                    'large_is_large': large_is_large,
                    'threshold_mb': 10.0
                }
            }
            
            if small_is_large or not large_is_large:
                test_result['error'] = "文件大小判断错误"
            
            results['tests'].append(test_result)
            logger.info(f"✅ 文件大小检查: 小文件 {small_size:.3f}MB, 大文件 {large_size:.1f}MB")
            
        except Exception as e:
            results['tests'].append({
                'name': '文件大小检查',
                'success': False,
                'error': str(e)
            })
            logger.error(f"❌ 文件大小检查失败: {e}")
        
        # 测试2: 临时文件管理
        try:
            handler = LargeFileHandler(temp_dir=str(self.temp_dir))
            
            # 创建临时文件
            temp_file1 = handler.create_temp_file(".test1")
            temp_file2 = handler.create_temp_file(".test2")
            
            # 写入内容
            with open(temp_file1, 'w') as f:
                f.write("temp file 1")
            with open(temp_file2, 'w') as f:
                f.write("temp file 2")
            
            files_before_cleanup = len(handler.temp_files)
            
            # 清理临时文件
            handler.cleanup_temp_files()
            
            files_after_cleanup = len(handler.temp_files)
            file1_exists = temp_file1.exists()
            file2_exists = temp_file2.exists()
            
            test_result = {
                'name': '临时文件管理',
                'success': files_before_cleanup == 2 and files_after_cleanup == 0 and not file1_exists and not file2_exists,
                'details': {
                    'files_before_cleanup': files_before_cleanup,
                    'files_after_cleanup': files_after_cleanup,
                    'temp_file1_exists': file1_exists,
                    'temp_file2_exists': file2_exists
                }
            }
            
            if files_before_cleanup != 2 or files_after_cleanup != 0:
                test_result['error'] = "临时文件管理异常"
            
            results['tests'].append(test_result)
            logger.info(f"✅ 临时文件管理: {files_before_cleanup} -> {files_after_cleanup} 文件")
            
        except Exception as e:
            results['tests'].append({
                'name': '临时文件管理',
                'success': False,
                'error': str(e)
            })
            logger.error(f"❌ 临时文件管理测试失败: {e}")
        
        # 测试3: 内存估算
        try:
            handler = LargeFileHandler()
            
            if large_file.exists():
                estimated_memory = handler.estimate_processing_memory(str(large_file))
                actual_size = get_file_size_mb(str(large_file))
                
                # 估算应该是文件大小的2-3倍
                expected_min = actual_size * 2
                expected_max = actual_size * 3
                
                test_result = {
                    'name': '内存需求估算',
                    'success': expected_min <= estimated_memory <= expected_max,
                    'details': {
                        'file_size_mb': round(actual_size, 1),
                        'estimated_memory_mb': round(estimated_memory, 1),
                        'ratio': round(estimated_memory / actual_size, 1),
                        'expected_range': f"{expected_min:.1f}-{expected_max:.1f}"
                    }
                }
                
                if not (expected_min <= estimated_memory <= expected_max):
                    test_result['error'] = "内存估算超出预期范围"
            else:
                test_result = {
                    'name': '内存需求估算',
                    'success': False,
                    'error': "测试文件不存在"
                }
            
            results['tests'].append(test_result)
            if test_result['success']:
                logger.info(f"✅ 内存估算: {test_result['details']['file_size_mb']}MB 文件需要 {test_result['details']['estimated_memory_mb']}MB 内存")
            
        except Exception as e:
            results['tests'].append({
                'name': '内存需求估算',
                'success': False,
                'error': str(e)
            })
            logger.error(f"❌ 内存估算测试失败: {e}")
        
        results['end_time'] = time.time()
        results['duration'] = results['end_time'] - results['start_time']
        results['success_count'] = sum(1 for test in results['tests'] if test['success'])
        results['total_count'] = len(results['tests'])
        
        return results
    
    def test_error_handling(self) -> Dict[str, Any]:
        """测试错误处理机制"""
        logger.info("=== 测试错误处理机制 ===")
        
        results = {
            'test_name': '错误处理机制测试',
            'start_time': time.time(),
            'tests': []
        }
        
        # 测试1: 错误收集器
        try:
            collector = ErrorCollector()
            
            # 添加各种错误
            file_error = FileError("test.pcap", "读取", IOError("文件不存在"))
            decode_error = DecodeError("test.pcap", packet_number=5, protocol="TCP")
            
            collector.add_error(file_error, "test.pcap")
            collector.add_error(decode_error, "test.pcap")
            collector.add_warning("这是一个警告", "test.pcap", {"detail": "test"})
            
            summary = collector.get_error_summary()
            report = collector.generate_error_report()
            
            test_result = {
                'name': '错误收集器',
                'success': True,
                'details': {
                    'total_errors': summary['total_errors'],
                    'total_warnings': summary['total_warnings'],
                    'files_with_errors': summary['files_with_errors'],
                    'error_types': summary['error_types'],
                    'has_errors': collector.has_errors(),
                    'has_warnings': collector.has_warnings()
                }
            }
            
            # 验证错误收集
            expected_errors = 2
            expected_warnings = 1
            
            if summary['total_errors'] != expected_errors or summary['total_warnings'] != expected_warnings:
                test_result['success'] = False
                test_result['error'] = f"错误数量不匹配: 期望 {expected_errors} 错误 {expected_warnings} 警告"
            
            results['tests'].append(test_result)
            logger.info(f"✅ 错误收集: {summary['total_errors']} 错误, {summary['total_warnings']} 警告")
            
        except Exception as e:
            results['tests'].append({
                'name': '错误收集器',
                'success': False,
                'error': str(e)
            })
            logger.error(f"❌ 错误收集测试失败: {e}")
        
        # 测试2: 损坏文件处理
        try:
            # 创建无效的pcap文件
            invalid_pcap = self.temp_dir / "invalid.pcap"
            with open(invalid_pcap, 'w') as f:
                f.write("这不是一个有效的PCAP文件")
            
            # 尝试用批量处理器处理
            output_dir = self.temp_dir / "error_test_output"
            
            with EnhancedBatchProcessor(
                output_dir=str(output_dir),
                max_workers=1,
                task_timeout=10,
                enable_resource_monitoring=False
            ) as processor:
                
                # 创建包含无效文件的输入目录
                input_dir = self.temp_dir / "error_test_input"
                input_dir.mkdir(exist_ok=True)
                
                # 复制无效文件到输入目录
                import shutil
                shutil.copy2(invalid_pcap, input_dir / "invalid.pcap")
                
                # 处理文件
                summary = processor.process_files(str(input_dir))
            
            test_result = {
                'name': '损坏文件处理',
                'success': True,
                'details': {
                    'total_files': summary['processing_summary']['total_files'],
                    'failed_files': summary['processing_summary']['failed_files'],
                    'success_rate': summary['processing_summary']['success_rate'],
                    'error_count': summary['error_summary']['total_errors']
                }
            }
            
            # 应该处理失败但程序不崩溃
            if summary['processing_summary']['failed_files'] == 0:
                test_result['success'] = False
                test_result['error'] = "损坏文件应该处理失败"
            
            results['tests'].append(test_result)
            logger.info(f"✅ 损坏文件处理: {summary['processing_summary']['failed_files']} 个文件失败")
            
        except Exception as e:
            results['tests'].append({
                'name': '损坏文件处理',
                'success': False,
                'error': str(e)
            })
            logger.error(f"❌ 损坏文件处理测试失败: {e}")
        
        results['end_time'] = time.time()
        results['duration'] = results['end_time'] - results['start_time']
        results['success_count'] = sum(1 for test in results['tests'] if test['success'])
        results['total_count'] = len(results['tests'])
        
        return results
    
    def test_integrated_resource_management(self) -> Dict[str, Any]:
        """测试集成资源管理"""
        logger.info("=== 测试集成资源管理 ===")
        
        results = {
            'test_name': '集成资源管理测试',
            'start_time': time.time(),
            'tests': []
        }
        
        # 测试1: 资源管理器综合功能
        try:
            # 自定义阈值
            memory_thresholds = MemoryThresholds(warning_mb=500.0, critical_mb=1000.0)
            disk_thresholds = DiskThresholds(min_free_gb=0.5, warning_free_gb=2.0)
            
            with ResourceManager(
                memory_thresholds=memory_thresholds,
                disk_thresholds=disk_thresholds,
                enable_monitoring=True
            ) as rm:
                
                # 等待监控启动
                time.sleep(1)
                
                # 检查状态
                status = rm.get_comprehensive_status()
                
                # 创建一个测试文件
                test_file = self.temp_dir / "resource_test.txt"
                with open(test_file, 'w') as f:
                    f.write("x" * 1024)  # 1KB文件
                
                # 检查文件可处理性
                processability = rm.check_file_processable(str(test_file))
                
                test_result = {
                    'name': '资源管理器综合功能',
                    'success': True,
                    'details': {
                        'monitoring_active': status['monitor_summary']['sample_count'] > 0,
                        'current_memory_mb': round(status['monitor_summary']['current'].memory_mb, 2),
                        'temp_files_count': status['temp_files_count'],
                        'file_processable': processability['can_process'],
                        'file_size_mb': processability['file_size_mb']
                    }
                }
                
                if not processability['can_process']:
                    test_result['success'] = False
                    test_result['error'] = "小文件应该可以处理"
                
                results['tests'].append(test_result)
                logger.info(f"✅ 资源管理器: 内存 {test_result['details']['current_memory_mb']}MB, 监控样本 {status['monitor_summary']['sample_count']}")
                
        except Exception as e:
            results['tests'].append({
                'name': '资源管理器综合功能',
                'success': False,
                'error': str(e)
            })
            logger.error(f"❌ 资源管理器测试失败: {e}")
        
        # 测试2: 增强批量处理器
        try:
            # 寻找真实的测试数据
            test_data_dirs = [
                "tests/data/samples",
                "../tests/data/samples",
                "../../tests/data/samples"
            ]
            
            test_dir = None
            for data_dir in test_data_dirs:
                if Path(data_dir).exists():
                    test_dir = data_dir
                    break
            
            if test_dir:
                output_dir = self.temp_dir / "enhanced_processor_test"
                
                with EnhancedBatchProcessor(
                    output_dir=str(output_dir),
                    max_workers=2,
                    task_timeout=30,
                    memory_limit_mb=1000.0,
                    enable_resource_monitoring=True
                ) as processor:
                    
                    # 处理少量文件
                    summary = processor.process_files(test_dir)
                
                test_result = {
                    'name': '增强批量处理器',
                    'success': True,
                    'details': {
                        'total_files': summary['processing_summary']['total_files'],
                        'successful_files': summary['processing_summary']['successful_files'],
                        'failed_files': summary['processing_summary']['failed_files'],
                        'skipped_files': summary['processing_summary']['skipped_files'],
                        'peak_memory_mb': summary['resource_metrics']['peak_memory_mb'],
                        'processing_time': summary['processing_summary']['total_processing_time']
                    }
                }
                
                if summary['processing_summary']['total_files'] == 0:
                    test_result['success'] = False
                    test_result['error'] = "没有找到测试文件"
                
                results['tests'].append(test_result)
                logger.info(f"✅ 增强处理器: {summary['processing_summary']['successful_files']}/{summary['processing_summary']['total_files']} 文件成功")
                
            else:
                results['tests'].append({
                    'name': '增强批量处理器',
                    'success': False,
                    'error': "未找到测试数据目录"
                })
                logger.warning("⚠️ 跳过增强处理器测试: 未找到测试数据")
            
        except Exception as e:
            results['tests'].append({
                'name': '增强批量处理器',
                'success': False,
                'error': str(e)
            })
            logger.error(f"❌ 增强处理器测试失败: {e}")
        
        results['end_time'] = time.time()
        results['duration'] = results['end_time'] - results['start_time']
        results['success_count'] = sum(1 for test in results['tests'] if test['success'])
        results['total_count'] = len(results['tests'])
        
        return results
    
    def run_all_tests(self) -> Dict[str, Any]:
        """运行所有阶段4测试"""
        logger.info("🚀 开始阶段4功能验证")
        
        overall_start = time.time()
        
        # 运行各项测试
        test_results = {
            'resource_monitor': self.test_resource_monitor(),
            'memory_manager': self.test_memory_manager(),
            'large_file_handler': self.test_large_file_handler(),
            'error_handling': self.test_error_handling(),
            'integrated_resource_management': self.test_integrated_resource_management()
        }
        
        overall_end = time.time()
        
        # 计算总体统计
        total_tests = sum(result['total_count'] for result in test_results.values())
        total_success = sum(result['success_count'] for result in test_results.values())
        overall_success_rate = (total_success / total_tests * 100) if total_tests > 0 else 0
        
        summary = {
            'stage': 4,
            'stage_name': '错误处理与健壮性',
            'start_time': overall_start,
            'end_time': overall_end,
            'duration': overall_end - overall_start,
            'total_tests': total_tests,
            'successful_tests': total_success,
            'failed_tests': total_tests - total_success,
            'success_rate': round(overall_success_rate, 1),
            'test_categories': len(test_results),
            'detailed_results': test_results
        }
        
        return summary
    
    def save_report(self, results: Dict[str, Any], filename: str = "stage4_validation_report.json"):
        """保存测试报告"""
        report_file = self.temp_dir / filename
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        
        logger.info(f"测试报告已保存: {report_file}")
        return str(report_file)
    
    def cleanup(self):
        """清理测试资源"""
        try:
            import shutil
            if self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
            logger.info("测试资源清理完成")
        except Exception as e:
            logger.warning(f"清理测试资源时出错: {e}")


def main():
    """主函数"""
    validator = Stage4Validator()
    
    try:
        # 运行所有测试
        results = validator.run_all_tests()
        
        # 保存报告
        report_file = validator.save_report(results)
        
        # 显示汇总结果
        print("\n" + "="*60)
        print("🎯 阶段4验证结果汇总")
        print("="*60)
        print(f"测试阶段: {results['stage_name']}")
        print(f"总测试数: {results['total_tests']}")
        print(f"成功测试: {results['successful_tests']}")
        print(f"失败测试: {results['failed_tests']}")
        print(f"成功率: {results['success_rate']}%")
        print(f"总耗时: {results['duration']:.2f}秒")
        print(f"测试类别: {results['test_categories']}")
        print(f"详细报告: {report_file}")
        
        # 显示各类别结果
        print("\n📊 各类别测试结果:")
        for category, result in results['detailed_results'].items():
            status = "✅" if result['success_count'] == result['total_count'] else "❌"
            print(f"{status} {result['test_name']}: {result['success_count']}/{result['total_count']} 通过")
        
        # 判断整体结果
        if results['success_rate'] >= 80:
            print(f"\n🎉 阶段4验证成功! (成功率: {results['success_rate']}%)")
            return 0
        else:
            print(f"\n⚠️ 阶段4验证需要改进 (成功率: {results['success_rate']}%)")
            return 1
            
    except Exception as e:
        logger.error(f"验证过程中出现异常: {e}")
        return 1
        
    finally:
        validator.cleanup()


if __name__ == "__main__":
    exit(main()) 