# PCAP批量解码器 - 用户使用手册

## 目录

1. [快速入门](#快速入门)
2. [安装指南](#安装指南)
3. [基本使用](#基本使用)
4. [高级功能](#高级功能)
5. [输出格式详解](#输出格式详解)
6. [性能优化](#性能优化)
7. [常见问题](#常见问题)
8. [故障排除](#故障排除)

---

## 快速入门

PCAP批量解码器是一个基于PyShark的高性能工具，用于批量处理PCAP/PCAPNG网络抓包文件。

### 3分钟上手

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 基本使用
python -m pcap_decoder -i /path/to/pcap/files -o /path/to/output

# 3. 查看结果
ls /path/to/output/*.json
```

### 主要特性

- 🔍 **批量处理**: 自动遍历目录，批量处理所有PCAP文件
- 🚀 **高性能**: 多进程并发，显著提升处理速度
- 📊 **协议丰富**: 支持15种常见网络协议解析
- 📁 **结构化输出**: JSON格式，包含详细协议信息
- 🛡️ **错误容错**: 单文件错误不影响整体处理
- 📈 **实时监控**: 进度条显示，性能统计

---

## 安装指南

### 系统要求

- **Python版本**: Python 3.7 或更高版本
- **操作系统**: Windows, macOS, Linux
- **内存**: 推荐 4GB 或更多
- **存储**: 根据PCAP文件大小预留充足空间

### 依赖安装

#### 步骤1: 安装Wireshark

PCAP解码器依赖于tshark（Wireshark的命令行版本）：

**Windows:**
```bash
# 下载并安装Wireshark
# https://www.wireshark.org/download.html
# 安装时确保包含tshark命令行工具
```

**macOS:**
```bash
# 使用Homebrew安装
brew install wireshark

# 或下载官方安装包
# https://www.wireshark.org/download.html
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install tshark
```

**CentOS/RHEL:**
```bash
sudo yum install wireshark-cli
# 或
sudo dnf install wireshark-cli
```

#### 步骤2: 安装Python依赖

```bash
# 方法1: 使用requirements.txt
pip install -r requirements.txt

# 方法2: 手动安装核心依赖
pip install pyshark>=0.6.0 click>=8.0.0 tqdm>=4.60.0 psutil>=5.8.0
```

#### 步骤3: 验证安装

```bash
# 验证tshark可用
tshark --version

# 验证Python模块
python -c "import pyshark; print('PyShark可用')"

# 验证PCAP解码器
python -m pcap_decoder --version
```

---

## 基本使用

### 命令行参数

```bash
python -m pcap_decoder [选项] -i <输入目录> -o <输出目录>
```

#### 必需参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `-i, --input` | 输入目录路径 | `-i ./pcap_files` |
| `-o, --output` | 输出目录路径 | `-o ./results` |

#### 可选参数

| 参数 | 说明 | 默认值 | 示例 |
|------|------|--------|------|
| `-j, --jobs` | 并发进程数 | 1 | `-j 4` |
| `--max-packets` | 每文件最大处理包数 | 无限制 | `--max-packets 1000` |
| `--dry-run` | 试运行模式（仅扫描） | False | `--dry-run` |
| `-v, --verbose` | 详细输出模式 | False | `-v` |
| `--error-report` | 生成错误报告 | False | `--error-report` |
| `--version` | 显示版本信息 | - | `--version` |

### 基本使用示例

#### 示例1: 单目录处理

```bash
# 处理单个目录下的所有PCAP文件
python -m pcap_decoder -i ./samples -o ./output
```

#### 示例2: 并发处理

```bash
# 使用4个进程并发处理
python -m pcap_decoder -i ./samples -o ./output -j 4
```

#### 示例3: 限制包数量

```bash
# 每个文件最多处理100个包
python -m pcap_decoder -i ./samples -o ./output --max-packets 100
```

#### 示例4: 详细输出

```bash
# 显示详细的处理信息
python -m pcap_decoder -i ./samples -o ./output -v
```

#### 示例5: 试运行

```bash
# 只扫描文件，不实际处理
python -m pcap_decoder -i ./samples -o ./output --dry-run
```

### 目录结构示例

```
输入目录结构:
samples/
├── tcp_traffic/
│   ├── file1.pcap
│   └── file2.pcapng
├── udp_traffic/
│   └── file3.pcap
└── file4.pcap

输出目录结构:
output/
├── tcp_traffic/
│   ├── file1.json
│   └── file2.json
├── udp_traffic/
│   └── file3.json
├── file4.json
└── error_report.json (如果启用错误报告)
```

---

## 高级功能

### 并发处理优化

#### 确定最佳并发数

```bash
# 查看CPU核心数
python -c "import psutil; print(f'CPU核心数: {psutil.cpu_count()}')"

# 推荐并发数 = CPU核心数 * 0.8
# 例如8核CPU，推荐使用6个进程
python -m pcap_decoder -i ./samples -o ./output -j 6
```

#### 内存使用优化

```bash
# 大文件处理时限制并发数和包数
python -m pcap_decoder -i ./large_files -o ./output -j 2 --max-packets 500
```

### 错误处理和调试

#### 启用错误报告

```bash
# 生成详细的错误报告
python -m pcap_decoder -i ./samples -o ./output --error-report -v
```

#### 错误报告结构

```json
{
  "summary": {
    "total_files": 10,
    "successful_files": 8,
    "failed_files": 2,
    "error_rate": 20.0
  },
  "errors": [
    {
      "file": "/path/to/problematic.pcap",
      "error_type": "DecodeError",
      "message": "Invalid packet format",
      "timestamp": "2024-06-12T10:30:00"
    }
  ]
}
```

### 性能监控

#### 实时性能统计

```bash
# 详细模式显示实时性能数据
python -m pcap_decoder -i ./samples -o ./output -v
```

输出示例：
```
🔍 扫描目录: ./samples
📁 发现文件: 15 个 (扫描耗时: 0.01s)
📊 开始处理...

处理进度: 100%|████████████| 15/15 [00:45<00:00, 3.33files/s]

📈 处理统计:
  - 总文件数: 15
  - 成功处理: 14
  - 处理失败: 1
  - 总包数: 1,234
  - 处理速度: 27.4 包/秒
  - 总耗时: 45.2秒
```

---

## 输出格式详解

### JSON文件结构

每个PCAP文件生成对应的JSON文件，包含以下结构：

```json
{
  "metadata": {
    "decoder_version": "1.0.0",
    "generated_by": "PCAP批量解码器",
    "generation_time": "2024-06-12T10:30:00Z",
    "input_file": "/path/to/input.pcap"
  },
  "file_info": {
    "file_name": "input.pcap",
    "file_size": 1048576,
    "packet_count": 100,
    "decode_time": 2.5,
    "file_format": "pcap"
  },
  "protocol_statistics": {
    "total_packets": 100,
    "protocol_distribution": {
      "TCP": 80,
      "UDP": 15,
      "ICMP": 5
    },
    "unique_protocols": ["ETH", "IP", "TCP", "UDP", "ICMP"],
    "protocol_layers": {
      "max_layers": 4,
      "avg_layers": 3.2
    }
  },
  "packets": [
    {
      "packet_id": 1,
      "timestamp": "2024-06-12T10:30:01.123456",
      "size": 74,
      "layers": {
        "ETH": {
          "src": "00:11:22:33:44:55",
          "dst": "aa:bb:cc:dd:ee:ff",
          "type": "0x0800"
        },
        "IP": {
          "src": "192.168.1.100",
          "dst": "192.168.1.1",
          "protocol": "TCP",
          "ttl": 64
        },
        "TCP": {
          "srcport": 12345,
          "dstport": 80,
          "flags": "0x02",
          "seq": 1000,
          "ack": 2000
        }
      },
      "summary": "192.168.1.100:12345 -> 192.168.1.1:80 [SYN]"
    }
  ]
}
```

### 字段说明

#### metadata - 元数据
- `decoder_version`: 解码器版本
- `generated_by`: 生成工具名称
- `generation_time`: 生成时间（ISO格式）
- `input_file`: 原始PCAP文件路径

#### file_info - 文件信息
- `file_name`: 文件名
- `file_size`: 文件大小（字节）
- `packet_count`: 包总数
- `decode_time`: 解码耗时（秒）
- `file_format`: 文件格式（pcap/pcapng）

#### protocol_statistics - 协议统计
- `total_packets`: 总包数
- `protocol_distribution`: 协议分布统计
- `unique_protocols`: 唯一协议列表
- `protocol_layers`: 协议层次统计

#### packets - 包详情
每个包包含：
- `packet_id`: 包序号
- `timestamp`: 时间戳
- `size`: 包大小
- `layers`: 各层协议详情
- `summary`: 包摘要

---

## 性能优化

### 硬件优化建议

#### CPU优化
```bash
# 根据CPU核心数调整并发
cores=$(python -c "import psutil; print(psutil.cpu_count())")
jobs=$((cores * 4 / 5))  # 使用80%的核心
python -m pcap_decoder -i ./samples -o ./output -j $jobs
```

#### 内存优化
```bash
# 大文件处理时的内存友好配置
python -m pcap_decoder -i ./large_files -o ./output -j 2 --max-packets 1000
```

#### 磁盘优化
```bash
# 使用SSD存储输出文件
python -m pcap_decoder -i ./samples -o /ssd/output -j 4
```

### 软件优化配置

#### 批量处理策略

```bash
# 小文件批量处理（高并发）
python -m pcap_decoder -i ./small_files -o ./output -j 8

# 大文件处理（低并发，限制包数）
python -m pcap_decoder -i ./large_files -o ./output -j 2 --max-packets 5000

# 混合文件处理（平衡配置）
python -m pcap_decoder -i ./mixed_files -o ./output -j 4 --max-packets 2000
```

#### 实时监控脚本

创建性能监控脚本 `monitor.py`：

```python
#!/usr/bin/env python3
import psutil
import time
import subprocess
import sys

def monitor_process():
    """监控PCAP解码器进程性能"""
    # 启动解码器进程
    cmd = sys.argv[1:] if len(sys.argv) > 1 else [
        "python", "-m", "pcap_decoder", 
        "-i", "./samples", "-o", "./output", "-v"
    ]
    
    process = subprocess.Popen(cmd)
    
    print("🔍 监控PCAP解码器性能...")
    print("进程ID:", process.pid)
    
    while process.poll() is None:
        try:
            proc = psutil.Process(process.pid)
            cpu_percent = proc.cpu_percent()
            memory_mb = proc.memory_info().rss / 1024 / 1024
            
            print(f"CPU: {cpu_percent:5.1f}% | 内存: {memory_mb:6.1f}MB", end="\r")
            time.sleep(1)
        except psutil.NoSuchProcess:
            break
    
    print("\n✅ 处理完成")

if __name__ == "__main__":
    monitor_process()
```

使用方法：
```bash
# 监控默认命令
python monitor.py

# 监控自定义命令
python monitor.py python -m pcap_decoder -i ./data -o ./results -j 4
```

---

## 常见问题

### Q1: 解码器无法启动

**问题**: 运行时提示模块不存在
```
ModuleNotFoundError: No module named 'pyshark'
```

**解决方案**:
```bash
# 检查依赖安装
pip list | grep pyshark

# 重新安装依赖
pip install -r requirements.txt

# 验证安装
python -c "import pyshark; print('OK')"
```

### Q2: tshark未找到

**问题**: 提示tshark命令不存在
```
FileNotFoundError: tshark not found
```

**解决方案**:
```bash
# 检查tshark安装
which tshark
tshark --version

# 如果未安装，按照安装指南安装Wireshark
```

### Q3: 处理速度慢

**问题**: 处理大文件时速度很慢

**解决方案**:
```bash
# 1. 增加并发数
python -m pcap_decoder -i ./files -o ./output -j 8

# 2. 限制包数量
python -m pcap_decoder -i ./files -o ./output --max-packets 1000

# 3. 使用SSD存储
python -m pcap_decoder -i ./files -o /ssd/output
```

### Q4: 内存不足

**问题**: 处理时内存不足

**解决方案**:
```bash
# 降低并发数
python -m pcap_decoder -i ./files -o ./output -j 1

# 限制处理包数
python -m pcap_decoder -i ./files -o ./output --max-packets 500

# 分批处理大文件
find ./large_files -name "*.pcap" | head -5 | while read file; do
    python -m pcap_decoder -i "$(dirname "$file")" -o ./output
done
```

### Q5: 输出JSON格式错误

**问题**: 生成的JSON文件无法解析

**解决方案**:
```bash
# 检查JSON格式
python -c "import json; json.load(open('output.json'))"

# 重新生成，启用详细模式查看错误
python -m pcap_decoder -i ./files -o ./output -v --error-report
```

### Q6: 某些协议无法识别

**问题**: 特定协议的包没有被正确解析

**解决方案**:
- 检查PyShark版本：`pip show pyshark`
- 升级PyShark：`pip install --upgrade pyshark`
- 查看支持的协议列表（见协议支持章节）
- 提交Issue报告未支持的协议

---

## 故障排除

### 调试模式

#### 启用详细日志

```bash
# 启用最详细的输出
python -m pcap_decoder -i ./samples -o ./output -v --error-report
```

#### 手动调试

```python
# debug.py - 手动调试脚本
from pcap_decoder.core.scanner import DirectoryScanner
from pcap_decoder.core.decoder import PacketDecoder

# 测试目录扫描
scanner = DirectoryScanner()
files = scanner.scan_directory("./samples")
print(f"发现文件: {len(files)}")

# 测试单文件解码
if files:
    decoder = PacketDecoder()
    result = decoder.decode_file(files[0])
    print(f"解码包数: {len(result.packets)}")
```

### 常见错误代码

| 错误代码 | 含义 | 解决方案 |
|----------|------|----------|
| Exit 1 | 输入目录不存在 | 检查路径是否正确 |
| Exit 2 | 输出目录创建失败 | 检查写入权限 |
| Exit 3 | tshark未找到 | 安装Wireshark |
| Exit 4 | 依赖包缺失 | 安装requirements.txt |
| Exit 5 | 内存不足 | 降低并发数或限制包数 |

### 日志文件分析

#### 错误日志格式

```
2024-06-12 10:30:00 ERROR [scanner.py:45] 无法读取文件: /path/to/file.pcap
2024-06-12 10:30:01 WARNING [decoder.py:78] 包解码失败: packet #123
2024-06-12 10:30:02 INFO [processor.py:156] 处理完成: 100/120 包成功
```

#### 日志级别说明

- `ERROR`: 严重错误，影响处理
- `WARNING`: 警告信息，不影响整体处理
- `INFO`: 一般信息，处理状态
- `DEBUG`: 详细调试信息

### 性能分析工具

#### 内建性能统计

```bash
# 使用详细模式查看性能统计
python -m pcap_decoder -i ./samples -o ./output -v
```

#### 外部性能监控

```bash
# 使用系统监控工具
top -p $(pgrep -f pcap_decoder)

# 使用htop监控（如果已安装）
htop -p $(pgrep -f pcap_decoder)
```

---

## 技术支持

### 获取帮助

1. **查看帮助信息**:
   ```bash
   python -m pcap_decoder --help
   ```

2. **查看版本信息**:
   ```bash
   python -m pcap_decoder --version
   ```

3. **生成调试报告**:
   ```bash
   python -m pcap_decoder -i ./samples -o ./output -v --error-report > debug.log 2>&1
   ```

### 报告问题

提交Issue时请包含：
- 操作系统和版本
- Python版本
- PyShark版本
- 错误日志
- 最小复现示例
- PCAP文件特征（如果可能）

### 贡献代码

欢迎贡献代码改进！详见 `DEVELOPER_GUIDE.md`

---

*用户手册版本: 1.0.0*  
*最后更新: 2024-06-12* 