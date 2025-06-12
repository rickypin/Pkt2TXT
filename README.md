# PCAP/PCAPNG 批量解码器

一个基于PyShark的高性能PCAP/PCAPNG文件批量解码工具，能够批量处理网络抓包文件并输出详细的协议字段信息。

## 功能特性

- 🔍 **批量处理**: 支持目录级别的批量PCAP/PCAPNG文件处理
- 🚀 **高性能**: 多进程并发处理，显著提升处理速度
- 📊 **协议支持**: 支持常见网络协议（Ethernet、IP、TCP、UDP、TLS、VLAN、MPLS等）
- 📁 **灵活输出**: JSON格式输出，包含详细的协议字段和统计信息
- 🛡️ **错误处理**: 完善的错误处理机制，单个文件错误不影响整体处理
- 📈 **进度显示**: 实时进度条显示处理状态

## 快速开始

### 安装依赖

```bash
pip install -r requirements.txt
```

### 基本使用

```bash
# 基本用法
python3 cli.py -i /path/to/pcap/files -o /path/to/output

# 并发处理
python3 cli.py -i ./samples -o ./results -j 4

# 详细输出模式
python3 cli.py -i ./samples -o ./results -v

# 限制处理包数
python3 cli.py -i ./samples -o ./results --max-packets 100

# 试运行模式（只扫描，不处理）
python3 cli.py -i ./samples -o ./results --dry-run
```

### 参数说明

- `-i, --input`: 输入目录路径，包含PCAP/PCAPNG文件
- `-o, --output`: 输出目录路径，用于保存JSON结果
- `-j, --jobs`: 并发处理进程数（默认：1）
- `--max-packets`: 每个文件最大处理包数（默认：无限制）
- `--dry-run`: 试运行模式，只扫描文件不实际处理
- `-v, --verbose`: 详细输出模式
- `--error-report`: 生成错误报告
- `--version`: 显示版本信息

## 支持的文件格式

- `.pcap` - 标准PCAP格式
- `.pcapng` - 新一代PCAP格式
- `.cap` - 网络捕获文件

## 支持的协议

- **链路层**: Ethernet (ETH)
- **网络层**: IPv4 (IP), IPv6 (IPV6)
- **传输层**: TCP, UDP
- **应用层**: TLS/SSL, HTTP, DNS
- **封装协议**: VLAN, MPLS, GRE, VXLAN

## 输出格式

解码器为每个PCAP文件生成对应的JSON文件，包含：

```json
{
  "metadata": {
    "decoder_version": "1.0.0",
    "generated_by": "PCAP批量解码器",
    "generation_time": "2024-01-01T12:00:00"
  },
  "file_info": {
    "input_file": "/path/to/file.pcap",
    "file_name": "file.pcap", 
    "file_size": 1024,
    "packet_count": 100,
    "decode_time": 2.5
  },
  "protocol_statistics": {
    "total_packets": 100,
    "protocol_distribution": {"TCP": 80, "UDP": 20},
    "unique_protocols": ["ETH", "IP", "TCP", "UDP"]
  },
  "packets": [...]
}
```

## 开发状态

项目已完成所有阶段开发，正式发布！

- ✅ **阶段1**: 基础架构搭建（已完成）
- ✅ **阶段2**: 核心解码引擎开发（已完成）
- ✅ **阶段3**: 输出格式化与并发处理（已完成）
- ✅ **阶段4**: 错误处理与健壮性（已完成）
- ✅ **阶段5**: 综合测试与优化（已完成）
- ✅ **阶段6**: 文档与部署（已完成）

**🎉 项目状态**: 生产就绪，版本 1.0.0

## 依赖要求

- Python 3.7+
- PyShark 0.6.0+
- Click 8.0.0+
- tqdm 4.60.0+
- Wireshark/tshark（PyShark依赖）

## 许可证

MIT License

## 贡献

欢迎提交Issue和Pull Request！ 