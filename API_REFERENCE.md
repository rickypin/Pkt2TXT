# PCAP批量解码器 - API参考文档

## 目录

1. [核心模块](#核心模块)
2. [工具模块](#工具模块)
3. [数据结构](#数据结构)
4. [异常类](#异常类)
5. [配置选项](#配置选项)
6. [使用示例](#使用示例)

---

## 核心模块

### pcap_decoder.core.scanner

目录扫描和文件发现模块。

#### DirectoryScanner

负责扫描目录并发现PCAP文件的核心类。

```python
class DirectoryScanner:
    """目录扫描器，用于发现PCAP文件"""
```

##### 构造函数

```python
def __init__(self, supported_extensions: Optional[List[str]] = None):
    """
    初始化目录扫描器
    
    Args:
        supported_extensions: 支持的文件扩展名列表，默认为['.pcap', '.pcapng', '.cap']
    """
```

##### 方法

###### scan_directory

```python
def scan_directory(self, path: str, max_depth: int = 2) -> List[str]:
    """
    扫描目录并返回发现的PCAP文件列表
    
    Args:
        path: 要扫描的目录路径
        max_depth: 最大扫描深度，默认为2
        
    Returns:
        List[str]: 发现的PCAP文件路径列表
        
    Raises:
        DirectoryNotFoundError: 目录不存在
        PermissionError: 没有读取权限
        
    Example:
        >>> scanner = DirectoryScanner()
        >>> files = scanner.scan_directory('/path/to/pcaps')
        >>> print(f"发现 {len(files)} 个文件")
    """
```

###### is_pcap_file

```python
def is_pcap_file(self, filepath: str) -> bool:
    """
    检查文件是否为支持的PCAP格式
    
    Args:
        filepath: 文件路径
        
    Returns:
        bool: 如果是PCAP文件返回True，否则返回False
        
    Example:
        >>> scanner = DirectoryScanner()
        >>> is_pcap = scanner.is_pcap_file('test.pcap')
    """
```

###### get_scan_statistics

```python
def get_scan_statistics(self) -> Dict[str, Any]:
    """
    获取最后一次扫描的统计信息
    
    Returns:
        Dict[str, Any]: 包含以下键的字典：
            - found_files: 发现的文件数量
            - ignored_files: 忽略的文件数量
            - error_paths: 错误路径数量
            - total_processed: 总处理路径数量
            - scan_time: 扫描耗时（秒）
            
    Example:
        >>> stats = scanner.get_scan_statistics()
        >>> print(f"扫描耗时: {stats['scan_time']:.3f}秒")
    """
```

---

### pcap_decoder.core.decoder

PCAP文件解码模块。

#### PacketDecoder

负责解码PCAP文件的核心类。

```python
class PacketDecoder:
    """PCAP文件解码器"""
```

##### 构造函数

```python
def __init__(self, max_packets: Optional[int] = None, 
             decode_full_packets: bool = True,
             include_raw: bool = False):
    """
    初始化包解码器
    
    Args:
        max_packets: 每个文件最大解码包数，None表示无限制
        decode_full_packets: 是否解码完整的包信息
        include_raw: 是否包含原始包数据
    """
```

##### 方法

###### decode_file

```python
def decode_file(self, filepath: str) -> DecodedFile:
    """
    解码单个PCAP文件
    
    Args:
        filepath: PCAP文件路径
        
    Returns:
        DecodedFile: 解码结果对象
        
    Raises:
        FileNotFoundError: 文件不存在
        DecodeError: 解码失败
        InvalidFileFormatError: 文件格式无效
        
    Example:
        >>> decoder = PacketDecoder(max_packets=100)
        >>> result = decoder.decode_file('sample.pcap')
        >>> print(f"解码了 {len(result.packets)} 个包")
    """
```

###### decode_packet

```python
def decode_packet(self, packet) -> DecodedPacket:
    """
    解码单个数据包
    
    Args:
        packet: PyShark包对象
        
    Returns:
        DecodedPacket: 解码后的包对象
        
    Raises:
        PacketDecodeError: 包解码失败
    """
```

###### get_file_info

```python
def get_file_info(self, filepath: str) -> FileInfo:
    """
    获取PCAP文件基本信息
    
    Args:
        filepath: 文件路径
        
    Returns:
        FileInfo: 文件信息对象
        
    Example:
        >>> info = decoder.get_file_info('test.pcap')
        >>> print(f"文件大小: {info.file_size} 字节")
    """
```

---

### pcap_decoder.core.extractor

协议字段提取模块。

#### FieldExtractor

负责从包中提取协议字段的类。

```python
class FieldExtractor:
    """协议字段提取器"""
```

##### 构造函数

```python
def __init__(self, protocols: Optional[List[str]] = None,
             extract_summary: bool = True,
             extract_timestamps: bool = True):
    """
    初始化字段提取器
    
    Args:
        protocols: 要提取的协议列表，None表示所有支持的协议
        extract_summary: 是否生成包摘要
        extract_timestamps: 是否提取时间戳
    """
```

##### 方法

###### extract_fields

```python
def extract_fields(self, packet) -> Dict[str, Any]:
    """
    提取包的所有协议字段
    
    Args:
        packet: PyShark包对象
        
    Returns:
        Dict[str, Any]: 协议字段字典，键为协议名，值为字段字典
        
    Example:
        >>> extractor = FieldExtractor()
        >>> fields = extractor.extract_fields(packet)
        >>> ip_fields = fields.get('IP', {})
    """
```

###### extract_layer_fields

```python
def extract_layer_fields(self, layer) -> Dict[str, Any]:
    """
    提取单层协议字段
    
    Args:
        layer: PyShark协议层对象
        
    Returns:
        Dict[str, Any]: 该层的字段字典
    """
```

###### generate_summary

```python
def generate_summary(self, packet) -> str:
    """
    生成包摘要字符串
    
    Args:
        packet: PyShark包对象
        
    Returns:
        str: 包摘要字符串
        
    Example:
        >>> summary = extractor.generate_summary(packet)
        >>> print(summary)  # "192.168.1.1:80 -> 192.168.1.100:12345 [TCP SYN]"
    """
```

###### get_supported_protocols

```python
def get_supported_protocols(self) -> List[str]:
    """
    获取支持的协议列表
    
    Returns:
        List[str]: 支持的协议名称列表
    """
```

---

### pcap_decoder.core.formatter

输出格式化模块。

#### JSONFormatter

JSON格式输出格式化器。

```python
class JSONFormatter:
    """JSON格式化器"""
```

##### 构造函数

```python
def __init__(self, indent: int = 2, 
             ensure_ascii: bool = False,
             sort_keys: bool = True):
    """
    初始化JSON格式化器
    
    Args:
        indent: JSON缩进空格数
        ensure_ascii: 是否确保ASCII编码
        sort_keys: 是否排序键
    """
```

##### 方法

###### format_file

```python
def format_file(self, decoded_file: DecodedFile) -> str:
    """
    将解码文件格式化为JSON字符串
    
    Args:
        decoded_file: 解码后的文件对象
        
    Returns:
        str: JSON格式的字符串
        
    Example:
        >>> formatter = JSONFormatter()
        >>> json_str = formatter.format_file(decoded_file)
    """
```

###### save_to_file

```python
def save_to_file(self, decoded_file: DecodedFile, output_path: str) -> None:
    """
    将解码文件保存为JSON文件
    
    Args:
        decoded_file: 解码后的文件对象
        output_path: 输出文件路径
        
    Raises:
        PermissionError: 没有写入权限
        IOError: 写入失败
    """
```

---

### pcap_decoder.core.processor

批量处理模块。

#### BatchProcessor

批量处理PCAP文件的核心类。

```python
class BatchProcessor:
    """批量处理器"""
```

##### 构造函数

```python
def __init__(self, input_dir: str, 
             output_dir: str,
             max_workers: int = 1,
             max_packets_per_file: Optional[int] = None,
             enable_progress: bool = True,
             error_handling: str = 'continue'):
    """
    初始化批量处理器
    
    Args:
        input_dir: 输入目录路径
        output_dir: 输出目录路径
        max_workers: 最大工作进程数
        max_packets_per_file: 每文件最大处理包数
        enable_progress: 是否启用进度条
        error_handling: 错误处理策略 ('continue', 'stop', 'collect')
    """
```

##### 方法

###### process_all

```python
def process_all(self) -> List[ProcessingResult]:
    """
    处理所有发现的PCAP文件
    
    Returns:
        List[ProcessingResult]: 处理结果列表
        
    Example:
        >>> processor = BatchProcessor('./input', './output', max_workers=4)
        >>> results = processor.process_all()
        >>> successful = [r for r in results if r.success]
    """
```

###### process_file

```python
def process_file(self, filepath: str) -> ProcessingResult:
    """
    处理单个PCAP文件
    
    Args:
        filepath: 文件路径
        
    Returns:
        ProcessingResult: 处理结果
    """
```

###### get_processing_statistics

```python
def get_processing_statistics(self) -> Dict[str, Any]:
    """
    获取处理统计信息
    
    Returns:
        Dict[str, Any]: 统计信息字典
    """
```

---

## 工具模块

### pcap_decoder.utils.progress

进度跟踪模块。

#### ProgressTracker

```python
class ProgressTracker:
    """进度跟踪器"""
    
    def __init__(self, total_files: int, 
                 description: str = "处理文件",
                 unit: str = "files"):
        """
        初始化进度跟踪器
        
        Args:
            total_files: 总文件数
            description: 进度描述
            unit: 进度单位
        """
    
    def update(self, n: int = 1, current_file: Optional[str] = None) -> None:
        """
        更新进度
        
        Args:
            n: 增加的进度数量
            current_file: 当前处理的文件名
        """
    
    def close(self) -> None:
        """关闭进度条"""
```

---

### pcap_decoder.utils.errors

错误处理模块。

#### ErrorCollector

```python
class ErrorCollector:
    """错误收集器"""
    
    def __init__(self):
        """初始化错误收集器"""
    
    def add_error(self, error_type: str, message: str, 
                  filepath: Optional[str] = None,
                  details: Optional[Dict[str, Any]] = None) -> None:
        """
        添加错误记录
        
        Args:
            error_type: 错误类型
            message: 错误消息
            filepath: 相关文件路径
            details: 额外详情
        """
    
    def get_errors(self) -> List[Dict[str, Any]]:
        """获取所有错误记录"""
    
    def get_error_summary(self) -> Dict[str, Any]:
        """获取错误摘要"""
    
    def generate_report(self) -> Dict[str, Any]:
        """生成错误报告"""
```

---

### pcap_decoder.utils.resource_manager

资源管理模块。

#### ResourceManager

```python
class ResourceManager:
    """资源管理器"""
    
    def __init__(self, max_memory_mb: Optional[int] = None,
                 max_disk_usage_percent: float = 90.0):
        """
        初始化资源管理器
        
        Args:
            max_memory_mb: 最大内存使用量(MB)
            max_disk_usage_percent: 最大磁盘使用百分比
        """
    
    def check_memory(self) -> bool:
        """检查内存是否充足"""
    
    def check_disk_space(self, required_mb: float) -> bool:
        """检查磁盘空间是否充足"""
    
    def cleanup(self) -> None:
        """清理资源"""
    
    def get_memory_usage(self) -> Dict[str, float]:
        """获取内存使用情况"""
```

---

## 数据结构

### DecodedFile

```python
@dataclass
class DecodedFile:
    """解码后的文件对象"""
    file_path: str                      # 文件路径
    file_info: FileInfo                 # 文件信息
    packets: List[DecodedPacket]        # 解码的包列表
    statistics: ProtocolStatistics      # 协议统计
    decode_time: float                  # 解码耗时
    errors: List[DecodeError]           # 解码错误列表
    metadata: Dict[str, Any]            # 元数据
```

### DecodedPacket

```python
@dataclass
class DecodedPacket:
    """解码后的包对象"""
    packet_id: int                      # 包ID
    timestamp: datetime                 # 时间戳
    size: int                          # 包大小
    layers: Dict[str, Dict[str, Any]]  # 协议层字段
    summary: str                       # 包摘要
    raw_data: Optional[bytes] = None   # 原始数据
```

### FileInfo

```python
@dataclass
class FileInfo:
    """文件信息"""
    file_name: str                     # 文件名
    file_size: int                     # 文件大小(字节)
    packet_count: int                  # 包总数
    file_format: str                   # 文件格式
    creation_time: Optional[datetime] = None  # 创建时间
    modification_time: Optional[datetime] = None  # 修改时间
```

### ProtocolStatistics

```python
@dataclass
class ProtocolStatistics:
    """协议统计信息"""
    total_packets: int                          # 总包数
    protocol_distribution: Dict[str, int]      # 协议分布
    unique_protocols: List[str]                # 唯一协议列表
    protocol_layers: Dict[str, Any]           # 协议层统计
    size_distribution: Dict[str, int]         # 大小分布
    timestamp_range: Tuple[datetime, datetime] # 时间范围
```

### ProcessingResult

```python
@dataclass
class ProcessingResult:
    """处理结果"""
    file_path: str                    # 文件路径
    success: bool                     # 是否成功
    output_path: Optional[str] = None # 输出文件路径
    packet_count: int = 0            # 处理的包数
    processing_time: float = 0.0     # 处理时间
    error: Optional[str] = None      # 错误信息
    warnings: List[str] = field(default_factory=list)  # 警告列表
```

---

## 异常类

### PCAPDecoderError

```python
class PCAPDecoderError(Exception):
    """PCAP解码器基础异常类"""
    pass
```

### FileError

```python
class FileError(PCAPDecoderError):
    """文件相关错误"""
    pass

class DirectoryNotFoundError(FileError):
    """目录不存在错误"""
    pass

class InvalidFileFormatError(FileError):
    """文件格式无效错误"""
    pass
```

### DecodeError

```python
class DecodeError(PCAPDecoderError):
    """解码错误"""
    pass

class PacketDecodeError(DecodeError):
    """包解码错误"""
    pass

class ProtocolNotSupportedError(DecodeError):
    """协议不支持错误"""
    pass
```

### ResourceError

```python
class ResourceError(PCAPDecoderError):
    """资源相关错误"""
    pass

class MemoryError(ResourceError):
    """内存不足错误"""
    pass

class DiskSpaceError(ResourceError):
    """磁盘空间不足错误"""
    pass
```

---

## 配置选项

### 全局配置

```python
# pcap_decoder/utils/config.py

class Config:
    """全局配置类"""
    
    # 扫描配置
    DEFAULT_MAX_DEPTH = 2
    SUPPORTED_EXTENSIONS = ['.pcap', '.pcapng', '.cap']
    
    # 解码配置
    DEFAULT_MAX_PACKETS = None
    DECODE_TIMEOUT = 300  # 秒
    
    # 处理配置
    DEFAULT_MAX_WORKERS = 1
    MAX_MEMORY_MB = 1000
    MAX_DISK_USAGE_PERCENT = 90.0
    
    # 输出配置
    JSON_INDENT = 2
    JSON_ENSURE_ASCII = False
    JSON_SORT_KEYS = True
    
    # 进度配置
    PROGRESS_UPDATE_INTERVAL = 0.1  # 秒
    PROGRESS_DESCRIPTION = "处理文件"
```

### 环境变量

```bash
# 设置最大工作进程数
export PCAP_DECODER_MAX_WORKERS=4

# 设置最大内存使用量(MB)
export PCAP_DECODER_MAX_MEMORY=2000

# 启用详细日志
export PCAP_DECODER_VERBOSE=1

# 设置日志级别
export PCAP_DECODER_LOG_LEVEL=INFO
```

---

## 使用示例

### 基本使用

```python
from pcap_decoder.core.scanner import DirectoryScanner
from pcap_decoder.core.decoder import PacketDecoder
from pcap_decoder.core.formatter import JSONFormatter

# 1. 扫描目录
scanner = DirectoryScanner()
files = scanner.scan_directory('/path/to/pcaps')
print(f"发现 {len(files)} 个PCAP文件")

# 2. 解码文件
decoder = PacketDecoder(max_packets=100)
decoded_file = decoder.decode_file(files[0])
print(f"解码了 {len(decoded_file.packets)} 个包")

# 3. 格式化输出
formatter = JSONFormatter()
json_output = formatter.format_file(decoded_file)
print(json_output[:200] + "...")
```

### 批量处理

```python
from pcap_decoder.core.processor import BatchProcessor

# 创建批量处理器
processor = BatchProcessor(
    input_dir='/path/to/pcaps',
    output_dir='/path/to/output',
    max_workers=4,
    max_packets_per_file=1000
)

# 处理所有文件
results = processor.process_all()

# 统计结果
successful = [r for r in results if r.success]
failed = [r for r in results if not r.success]

print(f"成功: {len(successful)}, 失败: {len(failed)}")
```

### 错误处理

```python
from pcap_decoder.utils.errors import ErrorCollector
from pcap_decoder.core.decoder import PacketDecoder

collector = ErrorCollector()
decoder = PacketDecoder()

for filepath in pcap_files:
    try:
        result = decoder.decode_file(filepath)
        print(f"✅ {filepath}")
    except Exception as e:
        collector.add_error(
            error_type=type(e).__name__,
            message=str(e),
            filepath=filepath
        )
        print(f"❌ {filepath}: {e}")

# 生成错误报告
report = collector.generate_report()
print(f"错误率: {report['summary']['error_rate']:.1f}%")
```

### 自定义协议提取

```python
from pcap_decoder.core.extractor import FieldExtractor

class CustomFieldExtractor(FieldExtractor):
    def extract_layer_fields(self, layer):
        """扩展字段提取逻辑"""
        fields = super().extract_layer_fields(layer)
        
        # 添加自定义字段处理
        if layer.layer_name.upper() == 'CUSTOM':
            fields['custom_field'] = self._extract_custom_field(layer)
        
        return fields
    
    def _extract_custom_field(self, layer):
        """自定义字段提取"""
        # 实现自定义逻辑
        return "custom_value"

# 使用自定义提取器
extractor = CustomFieldExtractor()
```

### 性能监控

```python
import time
from pcap_decoder.utils.resource_manager import ResourceManager
from pcap_decoder.utils.progress import ProgressTracker

# 创建资源管理器
rm = ResourceManager(max_memory_mb=1000)

# 创建进度跟踪器
progress = ProgressTracker(total_files=len(files))

for i, filepath in enumerate(files):
    # 检查资源
    if not rm.check_memory():
        print("内存不足，暂停处理")
        time.sleep(5)
        continue
    
    # 处理文件
    try:
        result = process_file(filepath)
        progress.update(1, current_file=filepath)
    except Exception as e:
        print(f"处理失败: {e}")

progress.close()
rm.cleanup()
```

---

*API参考文档版本: 1.0.0*  
*最后更新: 2024-06-12* 