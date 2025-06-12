#!/usr/bin/env python3
"""
阶段3功能验证脚本
测试JSON格式化器增强、批量处理器和进度监控功能
"""

import os
import sys
import time
import tempfile
import shutil
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from pcap_decoder.core import BatchProcessor, JSONFormatter
from pcap_decoder.core.scanner import DirectoryScanner
from pcap_decoder.core.decoder import PacketDecoder
from pcap_decoder.utils.progress import create_progress_monitor, ProgressUpdate


def test_enhanced_json_formatter():
    """测试增强版JSON格式化器"""
    print("=" * 60)
    print("🧪 测试1: 增强版JSON格式化器")
    print("=" * 60)
    
    # 寻找测试文件
    test_data_dir = project_root / "tests" / "data" / "samples"
    test_files = []
    
    # 扫描测试文件
    if test_data_dir.exists():
        scanner = DirectoryScanner()
        test_files = scanner.scan_directory(str(test_data_dir), max_depth=2)
    
    if not test_files:
        print("⚠️  未找到测试文件，跳过此测试")
        return False
    
    # 选择第一个文件进行测试
    test_file = test_files[0]
    print(f"📁 测试文件: {Path(test_file).name}")
    
    try:
        # 创建临时输出目录
        with tempfile.TemporaryDirectory() as temp_dir:
            # 1. 测试标准模式（小文件）
            print("🔧 测试标准输出模式...")
            formatter = JSONFormatter(temp_dir, streaming_threshold=1000)
            
            # 解码文件
            decoder = PacketDecoder(max_packets=10)
            result = decoder.decode_file(test_file)
            
            # 格式化并保存
            output_file = formatter.format_and_save(result)
            
            if Path(output_file).exists():
                file_size = Path(output_file).stat().st_size
                print(f"✅ 标准模式输出成功: {Path(output_file).name} ({file_size} bytes)")
            else:
                print("❌ 标准模式输出失败")
                return False
            
            # 2. 测试流式输出模式（设置低阈值）
            print("🔧 测试流式输出模式...")
            formatter_streaming = JSONFormatter(temp_dir, streaming_threshold=1)
            
            output_file_streaming = formatter_streaming.format_and_save(result)
            
            if Path(output_file_streaming).exists():
                file_size = Path(output_file_streaming).stat().st_size
                print(f"✅ 流式模式输出成功: {Path(output_file_streaming).name} ({file_size} bytes)")
            else:
                print("❌ 流式模式输出失败")
                return False
            
            # 3. 测试文件命名规则
            print("🔧 测试文件命名规则...")
            names = [Path(output_file).name, Path(output_file_streaming).name]
            unique_names = set(names)
            
            if len(unique_names) == len(names):
                print("✅ 文件命名唯一性正确")
            else:
                print("❌ 文件命名存在冲突")
                return False
            
            print("✅ JSON格式化器增强测试通过")
            return True
            
    except Exception as e:
        print(f"❌ JSON格式化器测试失败: {e}")
        return False


def test_batch_processor():
    """测试批量处理器"""
    print("\n" + "=" * 60)
    print("🧪 测试2: 批量处理器")
    print("=" * 60)
    
    # 寻找测试目录
    test_data_dir = project_root / "tests" / "data" / "samples"
    
    if not test_data_dir.exists():
        print("⚠️  未找到测试数据目录，跳过此测试")
        return False
    
    try:
        # 创建临时输出目录
        with tempfile.TemporaryDirectory() as temp_dir:
            print(f"📂 测试数据目录: {test_data_dir}")
            print(f"📁 临时输出目录: {temp_dir}")
            
            # 1. 测试任务准备
            print("🔧 测试任务准备...")
            processor = BatchProcessor(
                output_dir=temp_dir,
                max_workers=2,  # 使用2个进程测试
                task_timeout=60,  # 60秒超时
                max_packets=5    # 限制包数加快测试
            )
            
            tasks = processor.scan_and_prepare_tasks(str(test_data_dir))
            print(f"✅ 准备了 {len(tasks)} 个任务")
            
            if len(tasks) == 0:
                print("⚠️  未找到可处理的文件")
                return False
            
            # 2. 测试批量处理
            print("🔧 测试批量处理...")
            start_time = time.time()
            
            result_summary = processor.process_files(str(test_data_dir))
            
            processing_time = time.time() - start_time
            print(f"✅ 批量处理完成，耗时: {processing_time:.3f}s")
            
            # 3. 验证结果
            print("🔧 验证处理结果...")
            processing = result_summary.get('processing_summary', {})
            performance = result_summary.get('performance_metrics', {})
            
            total_files = processing.get('total_files', 0)
            successful_files = processing.get('successful_files', 0)
            failed_files = processing.get('failed_files', 0)
            
            print(f"   总文件数: {total_files}")
            print(f"   成功处理: {successful_files}")
            print(f"   处理失败: {failed_files}")
            print(f"   成功率: {processing.get('success_rate', 0):.1f}%")
            
            # 检查输出文件
            output_files = list(Path(temp_dir).glob("*.json"))
            summary_files = [f for f in output_files if "summary" in f.name]
            data_files = [f for f in output_files if "summary" not in f.name]
            
            print(f"   生成JSON文件: {len(data_files)}")
            print(f"   生成汇总报告: {len(summary_files)}")
            
            # 验证条件
            if successful_files > 0 and len(data_files) >= successful_files:
                print("✅ 批量处理器测试通过")
                return True
            else:
                print("❌ 批量处理器测试失败：输出文件数量不匹配")
                return False
                
    except Exception as e:
        print(f"❌ 批量处理器测试失败: {e}")
        return False


def test_progress_monitor():
    """测试进度监控器"""
    print("\n" + "=" * 60)
    print("🧪 测试3: 进度监控器")
    print("=" * 60)
    
    try:
        # 创建进度监控器
        print("🔧 测试实时进度监控器...")
        progress_monitor = create_progress_monitor(
            verbose=True,
            multi_process=True,
            show_detailed_stats=True
        )
        
        # 模拟处理任务
        total_files = 5
        progress_monitor.start_monitoring(total_files, "测试进度监控")
        
        # 模拟处理进度更新
        for i in range(total_files):
            time.sleep(0.1)  # 模拟处理时间
            
            update = ProgressUpdate(
                file_path=f"test_file_{i+1}.pcap",
                success=True,
                packets=10 + i * 5,
                processing_time=0.1 + i * 0.05,
                worker_id=i % 2
            )
            
            progress_monitor.update_progress(update)
        
        # 完成监控
        final_stats = progress_monitor.finish_monitoring()
        
        # 验证统计结果
        files_stats = final_stats.get('files', {})
        packets_stats = final_stats.get('packets', {})
        
        print("🔧 验证统计结果...")
        print(f"   处理文件数: {files_stats.get('processed', 0)}")
        print(f"   成功文件数: {files_stats.get('successful', 0)}")
        print(f"   总包数: {packets_stats.get('total_packets', 0)}")
        
        if (files_stats.get('processed', 0) == total_files and 
            files_stats.get('successful', 0) == total_files and
            packets_stats.get('total_packets', 0) > 0):
            print("✅ 进度监控器测试通过")
            return True
        else:
            print("❌ 进度监控器测试失败：统计数据不正确")
            return False
            
    except Exception as e:
        print(f"❌ 进度监控器测试失败: {e}")
        return False


def test_cli_integration():
    """测试CLI集成"""
    print("\n" + "=" * 60)
    print("🧪 测试4: CLI集成测试")
    print("=" * 60)
    
    test_data_dir = project_root / "tests" / "data" / "samples"
    
    if not test_data_dir.exists():
        print("⚠️  未找到测试数据目录，跳过此测试")
        return False
    
    try:
        # 创建临时输出目录
        with tempfile.TemporaryDirectory() as temp_dir:
            # 测试试运行模式
            print("🔧 测试试运行模式...")
            from pcap_decoder.cli import _run_dry_mode
            
            # 重定向输出测试
            import io
            import contextlib
            
            f = io.StringIO()
            with contextlib.redirect_stdout(f):
                _run_dry_mode(str(test_data_dir), verbose=True)
            
            output = f.getvalue()
            if "发现" in output and "文件" in output:
                print("✅ 试运行模式测试通过")
                
                # 测试处理模式（限制文件数量和包数）
                print("🔧 测试处理模式...")
                from pcap_decoder.cli import _run_processing_mode
                
                _run_processing_mode(
                    input_dir=str(test_data_dir),
                    output_dir=temp_dir,
                    jobs=1,  # 单进程测试
                    max_packets=3,  # 限制包数
                    timeout=30,  # 30秒超时
                    verbose=False,  # 避免过多输出
                    error_report=True,
                    streaming_threshold=1000
                )
                
                # 检查输出
                output_files = list(Path(temp_dir).glob("*.json"))
                if len(output_files) > 0:
                    print("✅ 处理模式测试通过")
                    return True
                else:
                    print("❌ 处理模式测试失败：未生成输出文件")
                    return False
            else:
                print("❌ 试运行模式测试失败")
                return False
                
    except Exception as e:
        print(f"❌ CLI集成测试失败: {e}")
        return False


def main():
    """主测试函数"""
    print("🚀 开始阶段3功能验证")
    print("测试内容：JSON格式化器增强、批量处理器、进度监控器、CLI集成")
    
    tests = [
        ("JSON格式化器增强", test_enhanced_json_formatter),
        ("批量处理器", test_batch_processor),
        ("进度监控器", test_progress_monitor),
        ("CLI集成", test_cli_integration),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n⏳ 开始测试: {test_name}")
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} 测试通过")
            else:
                print(f"❌ {test_name} 测试失败")
        except Exception as e:
            print(f"❌ {test_name} 测试异常: {e}")
    
    # 最终结果
    print("\n" + "=" * 60)
    print("🎯 阶段3功能验证结果")
    print("=" * 60)
    print(f"📊 测试结果: {passed}/{total} 通过")
    print(f"📈 通过率: {passed/total*100:.1f}%")
    
    if passed == total:
        print("🎉 阶段3功能验证完全通过！")
        print("✅ JSON格式化器增强功能正常")
        print("✅ 批量处理器并发功能正常")
        print("✅ 进度监控器实时显示正常")
        print("✅ CLI集成功能完整")
        
        print("\n🚀 阶段3开发成功完成！")
        print("📝 新增功能:")
        print("   • 流式JSON输出支持大文件")
        print("   • 多进程并发批量处理")
        print("   • 实时进度监控和统计")
        print("   • 完整的CLI用户界面")
        print("   • 详细的错误处理和报告")
        
        return True
    else:
        print(f"⚠️  阶段3功能验证存在问题 ({total-passed} 个测试失败)")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 