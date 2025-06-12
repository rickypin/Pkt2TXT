#!/usr/bin/env python3
"""
阶段4快速验证脚本
验证错误处理与资源管理的核心功能
"""

import os
import sys
import time
import tempfile
from pathlib import Path

# 添加当前目录到Python路径
sys.path.insert(0, str(Path(__file__).parent))

def test_resource_management():
    """测试资源管理功能"""
    print("=== 测试资源管理功能 ===")
    
    try:
        from utils.resource_manager import ResourceManager, MemoryThresholds
        
        # 测试1: 创建资源管理器
        print("1. 创建资源管理器...")
        with ResourceManager(enable_monitoring=False) as rm:
            
            # 测试2: 获取当前使用情况
            print("2. 获取资源使用情况...")
            usage = rm.monitor.get_current_usage()
            print(f"   内存: {usage.memory_mb:.1f}MB ({usage.memory_percent:.1f}%)")
            print(f"   磁盘剩余: {usage.disk_free_gb:.1f}GB")
            
            # 测试3: 检查文件处理能力
            print("3. 测试文件处理能力检查...")
            
            # 创建临时测试文件
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
                tmp.write(b"test data" * 1000)  # 约9KB
                tmp_path = tmp.name
            
            try:
                processability = rm.check_file_processable(tmp_path)
                print(f"   文件大小: {processability['file_size_mb']:.3f}MB")
                print(f"   可处理: {processability['can_process']}")
                print(f"   预估内存: {processability['estimated_memory_mb']:.1f}MB")
                
                # 测试4: 内存管理
                print("4. 测试内存管理...")
                collected = rm.memory_manager.force_garbage_collection()
                print(f"   垃圾回收: {sum(collected.values())} 对象")
                
                print("✅ 资源管理功能测试通过")
                return True
                
            finally:
                # 清理临时文件
                try:
                    os.unlink(tmp_path)
                except:
                    pass
            
    except Exception as e:
        print(f"❌ 资源管理功能测试失败: {e}")
        return False

def test_error_handling():
    """测试错误处理功能"""
    print("\n=== 测试错误处理功能 ===")
    
    try:
        from utils.errors import ErrorCollector, FileError, DecodeError
        
        # 测试1: 创建错误收集器
        print("1. 创建错误收集器...")
        collector = ErrorCollector()
        
        # 测试2: 添加不同类型的错误
        print("2. 添加测试错误...")
        
        file_error = FileError("test.pcap", "读取", Exception("文件不存在"))
        decode_error = DecodeError("test.pcap", packet_number=1, protocol="TCP")
        
        collector.add_error(file_error, "test.pcap")
        collector.add_error(decode_error, "test.pcap")
        collector.add_warning("测试警告", "test.pcap")
        
        # 测试3: 检查错误统计
        print("3. 检查错误统计...")
        summary = collector.get_error_summary()
        print(f"   总错误数: {summary['total_errors']}")
        print(f"   总警告数: {summary['total_warnings']}")
        print(f"   错误文件数: {summary['files_with_errors']}")
        
        # 测试4: 生成错误报告
        print("4. 生成错误报告...")
        report = collector.generate_error_report()
        
        if (summary['total_errors'] == 2 and 
            summary['total_warnings'] == 1 and 
            'report_generated' in report):
            print("✅ 错误处理功能测试通过")
            return True
        else:
            print("❌ 错误处理功能测试结果不符合预期")
            return False
            
    except Exception as e:
        print(f"❌ 错误处理功能测试失败: {e}")
        return False

def test_enhanced_processor():
    """测试增强版处理器"""
    print("\n=== 测试增强版处理器 ===")
    
    try:
        from core.processor import EnhancedBatchProcessor
        import tempfile
        
        # 测试1: 创建增强处理器
        print("1. 创建增强版处理器...")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "output"
            
            processor = EnhancedBatchProcessor(
                output_dir=str(output_dir),
                max_workers=1,
                enable_resource_monitoring=False
            )
            
            print("2. 检查处理器配置...")
            print(f"   输出目录: {processor.output_dir}")
            print(f"   工作进程数: {processor.max_workers}")
            print(f"   资源管理器: {'已启用' if processor.resource_manager else '未启用'}")
            
            # 测试3: 检查空目录处理
            print("3. 测试空目录处理...")
            empty_input = Path(temp_dir) / "empty_input"
            empty_input.mkdir()
            
            summary = processor.process_files(str(empty_input))
            
            if summary['processing_summary']['total_files'] == 0:
                print("   ✅ 空目录处理正常")
            else:
                print("   ❌ 空目录处理异常")
                return False
            
            processor.cleanup()
            
        print("✅ 增强版处理器测试通过")
        return True
        
    except Exception as e:
        print(f"❌ 增强版处理器测试失败: {e}")
        return False

def test_integration():
    """集成测试"""
    print("\n=== 集成测试 ===")
    
    try:
        # 测试所有模块是否能正常导入
        print("1. 测试模块导入...")
        
        from utils.resource_manager import ResourceManager
        from utils.errors import ErrorCollector
        from core.processor import EnhancedBatchProcessor
        
        print("   ✅ 所有模块导入成功")
        
        # 测试基本集成
        print("2. 测试基本集成...")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "integration_output"
            
            # 创建处理器（集成了资源管理）
            with EnhancedBatchProcessor(
                output_dir=str(output_dir),
                max_workers=1,
                enable_resource_monitoring=False
            ) as processor:
                
                # 检查资源管理器是否正常工作
                status = processor.resource_manager.get_comprehensive_status()
                
                if 'monitor_summary' in status and 'memory_stats' in status:
                    print("   ✅ 资源管理器集成正常")
                else:
                    print("   ❌ 资源管理器集成异常")
                    return False
        
        print("✅ 集成测试通过")
        return True
        
    except Exception as e:
        print(f"❌ 集成测试失败: {e}")
        return False

def main():
    """主函数"""
    print("🚀 阶段4功能快速验证")
    print("="*50)
    
    start_time = time.time()
    
    # 运行各项测试
    tests = [
        ("资源管理", test_resource_management),
        ("错误处理", test_error_handling),
        ("增强处理器", test_enhanced_processor),
        ("集成测试", test_integration)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"❌ {test_name}测试异常: {e}")
    
    end_time = time.time()
    duration = end_time - start_time
    
    # 显示结果
    print("\n" + "="*50)
    print("📊 验证结果汇总")
    print("="*50)
    print(f"总测试数: {total}")
    print(f"通过测试: {passed}")
    print(f"失败测试: {total - passed}")
    print(f"成功率: {passed/total*100:.1f}%")
    print(f"耗时: {duration:.2f}秒")
    
    if passed == total:
        print("\n🎉 阶段4验证全部通过!")
        print("✨ 错误处理与资源管理功能正常")
        return 0
    else:
        print(f"\n⚠️ 阶段4验证部分失败 ({passed}/{total})")
        print("🔧 需要检查失败的功能模块")
        return 1

if __name__ == "__main__":
    exit(main()) 