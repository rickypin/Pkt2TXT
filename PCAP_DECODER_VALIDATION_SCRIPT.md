# PCAP解码器快速验证脚本与测试清单

## 快速验证脚本

### 1. 环境检查脚本
```bash
#!/bin/bash
# check_environment.sh - 验证开发环境

echo "=== PCAP解码器环境检查 ==="

# 检查Python版本
echo "1. Python版本检查:"
python --version

# 检查依赖包
echo "2. 依赖包检查:"
required_packages=("pyshark" "tqdm" "click" "pytest")
for package in "${required_packages[@]}"; do
    if pip show $package > /dev/null 2>&1; then
        echo "✅ $package: 已安装"
    else
        echo "❌ $package: 未安装"
    fi
done

# 检查tshark可用性
echo "3. Tshark可用性检查:"
if command -v tshark &> /dev/null; then
    echo "✅ Tshark: 可用 ($(tshark --version | head -1))"
else
    echo "❌ Tshark: 不可用，需要安装Wireshark"
fi

# 检查测试数据
echo "4. 测试数据检查:"
test_dir="tests/data/samples"
if [ -d "$test_dir" ]; then
    dir_count=$(find "$test_dir" -mindepth 1 -maxdepth 1 -type d | wc -l)
    file_count=$(find "$test_dir" -name "*.pcap" -o -name "*.pcapng" | wc -l)
    echo "✅ 测试数据目录: 存在 ($dir_count 个子目录, $file_count 个文件)"
else
    echo "❌ 测试数据目录: 不存在"
fi

echo "=== 环境检查完成 ==="
```

### 2. 阶段性功能验证脚本
```bash
#!/bin/bash
# validate_stage.sh - 阶段性功能验证

STAGE=$1
TEST_DIR="tests/data/samples"
OUTPUT_DIR="/tmp/pcap_decoder_test"

if [ -z "$STAGE" ]; then
    echo "用法: $0 <stage_number>"
    echo "阶段: 1=基础架构, 2=解码引擎, 3=输出格式, 4=错误处理, 5=综合测试"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

case $STAGE in
    1)
        echo "=== 阶段1: 基础架构验证 ==="
        echo "1.1 模块导入测试:"
        python -c "
try:
    from core.scanner import DirectoryScanner
    from utils.errors import ErrorCollector
    import cli
    print('✅ 模块导入成功')
except ImportError as e:
    print(f'❌ 模块导入失败: {e}')
"
        
        echo "1.2 CLI帮助信息测试:"
        if python3 cli.py --help > /dev/null 2>&1; then
            echo "✅ CLI帮助信息正常"
        else
            echo "❌ CLI帮助信息异常"
        fi
        ;;
        
    2)
        echo "=== 阶段2: 解码引擎验证 ==="
        echo "2.1 目录遍历测试:"
        python -c "
from core.scanner import DirectoryScanner
scanner = DirectoryScanner()
try:
    files = scanner.scan_directory('$TEST_DIR', max_depth=2)
    print(f'✅ 发现文件数: {len(files)}')
    # 显示前5个文件
    for i, f in enumerate(files[:5]):
        print(f'  {i+1}. {f}')
    if len(files) > 5:
        print(f'  ... 还有 {len(files)-5} 个文件')
except Exception as e:
    print(f'❌ 目录遍历失败: {e}')
"
        
        echo "2.2 单文件解码测试:"
        test_file=$(find "$TEST_DIR" -name "*.pcap" -o -name "*.pcapng" | head -1)
        if [ -n "$test_file" ]; then
            python -c "
from core.decoder import PacketDecoder
decoder = PacketDecoder()
try:
    result = decoder.decode_file('$test_file')
    print(f'✅ 文件解码成功: {len(result.packets)} 个包')
    if result.packets:
        print(f'✅ 协议层数: {len(result.packets[0].layers)}')
except Exception as e:
    print(f'❌ 文件解码失败: {e}')
"
        else
            echo "❌ 未找到测试文件"
        fi
        ;;
        
    3)
        echo "=== 阶段3: 输出格式验证 ==="
        echo "3.1 JSON格式化测试:"
        python3 cli.py -i "$TEST_DIR/IPTCP-200ips" -o "$OUTPUT_DIR/stage3_test" --dry-run
        if [ $? -eq 0 ]; then
            echo "✅ 输出格式化正常"
        else
            echo "❌ 输出格式化异常"
        fi
        
        echo "3.2 并发处理测试:"
        timeout 30 python3 cli.py -i "$TEST_DIR" -o "$OUTPUT_DIR/concurrent_test" -j 2 --max-packets 10
        if [ $? -eq 0 ]; then
            json_count=$(find "$OUTPUT_DIR/concurrent_test" -name "*.json" | wc -l)
            echo "✅ 并发处理完成，生成 $json_count 个JSON文件"
        else
            echo "❌ 并发处理超时或失败"
        fi
        ;;
        
    4)
        echo "=== 阶段4: 错误处理验证 ==="
        echo "4.1 创建损坏文件测试:"
        mkdir -p "$OUTPUT_DIR/error_test"
        echo "invalid pcap data" > "$OUTPUT_DIR/error_test/invalid.pcap"
        
        python3 cli.py -i "$OUTPUT_DIR/error_test" -o "$OUTPUT_DIR/error_output" --error-report
        if [ -f "$OUTPUT_DIR/error_output/error_report.json" ]; then
            echo "✅ 错误处理正常，生成错误报告"
        else
            echo "❌ 错误处理异常"
        fi
        
        echo "4.2 空目录容错测试:"
        python3 cli.py -i "$TEST_DIR/empty" -o "$OUTPUT_DIR/empty_test"
        if [ $? -eq 0 ]; then
            echo "✅ 空目录容错正常"
        else
            echo "❌ 空目录容错失败"
        fi
        ;;
        
    5)
        echo "=== 阶段5: 综合测试验证 ==="
        echo "5.1 完整流程测试:"
        start_time=$(date +%s)
        python3 cli.py -i "$TEST_DIR" -o "$OUTPUT_DIR/integration_test" -v --max-packets 50
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        
        json_count=$(find "$OUTPUT_DIR/integration_test" -name "*.json" | wc -l)
        error_count=$(find "$OUTPUT_DIR/integration_test" -name "error_*.log" | wc -l)
        
        echo "✅ 完整流程测试完成:"
        echo "   - 处理时间: ${duration}秒"
        echo "   - 成功文件: $json_count 个"
        echo "   - 错误文件: $error_count 个"
        
        echo "5.2 性能基准测试:"
        if [ $json_count -gt 0 ]; then
            first_json=$(find "$OUTPUT_DIR/integration_test" -name "*.json" | head -1)
            packet_count=$(jq '.file_info.packet_count' "$first_json" 2>/dev/null || echo "0")
            if [ "$packet_count" != "null" ] && [ "$packet_count" -gt 0 ]; then
                echo "✅ 性能基准: $(echo "scale=2; $packet_count / $duration" | bc) 包/秒"
            fi
        fi
        ;;
        
    *)
        echo "❌ 未知阶段: $STAGE"
        exit 1
        ;;
esac

echo "=== 阶段$STAGE 验证完成 ==="
```

### 3. 协议覆盖测试脚本
```bash
#!/bin/bash
# test_protocol_coverage.sh - 协议覆盖测试

TEST_DIR="tests/data/samples"
OUTPUT_DIR="/tmp/protocol_coverage_test"
REPORT_FILE="$OUTPUT_DIR/protocol_coverage_report.txt"

mkdir -p "$OUTPUT_DIR"

echo "=== 协议覆盖测试 ===" > "$REPORT_FILE"
echo "测试时间: $(date)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# 定义协议测试矩阵
declare -A protocol_dirs=(
    ["IPTCP-200ips"]="Plain IP/TCP"
    ["singlevlan"]="Single VLAN"
    ["doublevlan"]="Double VLAN"
    ["TLS"]="TLS/SSL"
    ["TLS70"]="TLS v1.3"
    ["mpls"]="MPLS"
    ["vxlan"]="VXLAN"
    ["gre"]="GRE"
    ["vlan_gre"]="VLAN+GRE"
    ["vxlan_vlan"]="VXLAN+VLAN"
    ["vxlan4787"]="VXLAN非标准端口"
    ["doublevlan_tls"]="Double VLAN+TLS"
    ["IPTCP-TC-001-1-20160407"]="历史数据"
    ["IPTCP-TC-002-5-20220215"]="现代数据"
    ["IPTCP-TC-002-8-20210817"]="中期数据"
)

total_tests=${#protocol_dirs[@]}
passed_tests=0
failed_tests=0

echo "协议测试矩阵 ($total_tests 项):" >> "$REPORT_FILE"
echo "----------------------------------------" >> "$REPORT_FILE"

for dir in "${!protocol_dirs[@]}"; do
    protocol="${protocol_dirs[$dir]}"
    test_path="$TEST_DIR/$dir"
    output_path="$OUTPUT_DIR/$dir"
    
    echo -n "测试 $dir ($protocol)... "
    
    if [ -d "$test_path" ]; then
        # 执行测试，限制时间和包数
        timeout 60 python3 cli.py -i "$test_path" -o "$output_path" --max-packets 20 > /dev/null 2>&1
        status=$?
        
        if [ $status -eq 0 ]; then
            json_count=$(find "$output_path" -name "*.json" | wc -l)
            if [ $json_count -gt 0 ]; then
                echo "✅ 通过 ($json_count 文件)"
                echo "✅ $dir ($protocol): 通过 - $json_count 文件" >> "$REPORT_FILE"
                ((passed_tests++))
            else
                echo "❌ 失败 (无输出文件)"
                echo "❌ $dir ($protocol): 失败 - 无输出文件" >> "$REPORT_FILE"
                ((failed_tests++))
            fi
        else
            echo "❌ 失败 (退出码: $status)"
            echo "❌ $dir ($protocol): 失败 - 退出码 $status" >> "$REPORT_FILE"
            ((failed_tests++))
        fi
    else
        echo "⚠️  跳过 (目录不存在)"
        echo "⚠️  $dir ($protocol): 跳过 - 目录不存在" >> "$REPORT_FILE"
    fi
done

echo "" >> "$REPORT_FILE"
echo "测试汇总:" >> "$REPORT_FILE"
echo "----------------------------------------" >> "$REPORT_FILE"
echo "总测试数: $total_tests" >> "$REPORT_FILE"
echo "通过测试: $passed_tests" >> "$REPORT_FILE"
echo "失败测试: $failed_tests" >> "$REPORT_FILE"
echo "成功率: $(echo "scale=1; $passed_tests * 100 / $total_tests" | bc)%" >> "$REPORT_FILE"

echo ""
echo "=== 协议覆盖测试完成 ==="
echo "详细报告: $REPORT_FILE"

# 显示汇总
cat "$REPORT_FILE" | tail -8
```

### 4. 性能基准测试脚本
```python
#!/usr/bin/env python3
# performance_benchmark.py - 性能基准测试

import time
import psutil
import subprocess
import json
import os
from pathlib import Path

def run_performance_test():
    """运行性能基准测试"""
    test_configs = [
        {
            "name": "小文件测试",
            "input_dir": "tests/data/samples/IPTCP-200ips",
            "max_packets": 50,
            "expected_time": 10,  # 秒
        },
        {
            "name": "中等文件测试", 
            "input_dir": "tests/data/samples/singlevlan",
            "max_packets": 200,
            "expected_time": 30,  # 秒
        },
        {
            "name": "并发处理测试",
            "input_dir": "tests/data/samples",
            "max_packets": 30,
            "jobs": 4,
            "expected_time": 60,  # 秒
        }
    ]
    
    results = []
    
    for config in test_configs:
        print(f"\n=== {config['name']} ===")
        
        # 准备输出目录
        output_dir = f"/tmp/perf_test_{config['name'].replace(' ', '_')}"
        os.makedirs(output_dir, exist_ok=True)
        
        # 构建命令
        cmd = [
            "python", "-m", "pcap_decoder",
            "-i", config["input_dir"],
            "-o", output_dir,
            "--max-packets", str(config["max_packets"])
        ]
        
        if "jobs" in config:
            cmd.extend(["-j", str(config["jobs"])])
        
        # 执行测试
        start_time = time.time()
        start_memory = psutil.virtual_memory().used / 1024 / 1024  # MB
        
        try:
            process = subprocess.run(
                cmd,
                timeout=config["expected_time"] + 30,
                capture_output=True,
                text=True
            )
            
            end_time = time.time()
            end_memory = psutil.virtual_memory().used / 1024 / 1024  # MB
            
            # 分析结果
            duration = end_time - start_time
            memory_delta = end_memory - start_memory
            
            # 统计输出文件
            json_files = list(Path(output_dir).glob("*.json"))
            total_packets = 0
            
            for json_file in json_files:
                try:
                    with open(json_file) as f:
                        data = json.load(f)
                        total_packets += data.get("file_info", {}).get("packet_count", 0)
                except:
                    pass
            
            # 计算性能指标
            packets_per_second = total_packets / duration if duration > 0 else 0
            
            result = {
                "test": config["name"],
                "duration": round(duration, 2),
                "expected_time": config["expected_time"],
                "memory_delta": round(memory_delta, 1),
                "total_packets": total_packets,
                "packets_per_second": round(packets_per_second, 1),
                "json_files": len(json_files),
                "success": process.returncode == 0,
                "within_time_limit": duration <= config["expected_time"]
            }
            
            results.append(result)
            
            # 输出结果
            print(f"✅ 执行时间: {duration:.2f}s (限制: {config['expected_time']}s)")
            print(f"✅ 内存变化: {memory_delta:+.1f}MB")
            print(f"✅ 处理包数: {total_packets}")
            print(f"✅ 处理速度: {packets_per_second:.1f} 包/秒")
            print(f"✅ 输出文件: {len(json_files)}")
            
            if not result["within_time_limit"]:
                print(f"⚠️  超出时间限制")
            
        except subprocess.TimeoutExpired:
            print(f"❌ 测试超时 (>{config['expected_time'] + 30}s)")
            results.append({
                "test": config["name"],
                "success": False,
                "error": "timeout"
            })
        except Exception as e:
            print(f"❌ 测试失败: {e}")
            results.append({
                "test": config["name"],
                "success": False,
                "error": str(e)
            })
    
    # 保存性能报告
    report_file = "/tmp/performance_benchmark_report.json"
    with open(report_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n=== 性能测试完成 ===")
    print(f"详细报告: {report_file}")
    
    # 显示汇总
    successful_tests = [r for r in results if r.get("success", False)]
    print(f"成功测试: {len(successful_tests)}/{len(results)}")
    
    if successful_tests:
        avg_speed = sum(r.get("packets_per_second", 0) for r in successful_tests) / len(successful_tests)
        print(f"平均处理速度: {avg_speed:.1f} 包/秒")

if __name__ == "__main__":
    run_performance_test()
```

## 测试检查清单

### 阶段1检查清单 ✅
- [ ] 项目目录结构正确创建
- [ ] 所有必需的依赖包安装完成
- [ ] 模块可以正常导入
- [ ] CLI帮助信息正常显示
- [ ] pytest可以发现测试模块

### 阶段2检查清单 ✅
- [ ] 目录遍历器正确遍历两层深度
- [ ] 正确识别pcap/pcapng文件
- [ ] PyShark正常解析文件
- [ ] 协议字段提取正常工作
- [ ] 错误文件不导致程序崩溃

### 阶段3检查清单 ✅
- [ ] JSON输出格式正确
- [ ] 文件命名规则正确
- [ ] 并发处理正常工作
- [ ] 进度条显示正确
- [ ] 大文件不导致内存溢出

### 阶段4检查清单 ✅
- [ ] 损坏文件错误处理正确
- [ ] 空目录容错处理正确
- [ ] 错误报告生成正确
- [ ] 内存使用稳定
- [ ] 资源清理正确

### 阶段5检查清单 ✅
- [ ] 15个有效数据目录全部测试通过
- [ ] 单元测试覆盖率>80%
- [ ] 集成测试全部通过
- [ ] 性能指标达到目标
- [ ] 错误处理覆盖完整

### 协议支持检查清单 ✅
- [ ] Plain IP/TCP ✅
- [ ] Single VLAN ✅  
- [ ] Double VLAN ✅
- [ ] TLS/SSL ✅
- [ ] TLS v1.3 ✅
- [ ] MPLS ✅
- [ ] VXLAN ✅
- [ ] GRE ✅
- [ ] 复合封装(VLAN+GRE等) ✅
- [ ] 历史数据兼容性 ✅

## 使用方法

```bash
# 1. 环境检查
bash check_environment.sh

# 2. 阶段性验证 (1-5)
bash validate_stage.sh 1
bash validate_stage.sh 2
# ... 继续到阶段5

# 3. 协议覆盖测试
bash test_protocol_coverage.sh

# 4. 性能基准测试
python performance_benchmark.py
```

这些验证脚本可以在开发过程中随时使用，确保每个阶段的功能正确实现。 