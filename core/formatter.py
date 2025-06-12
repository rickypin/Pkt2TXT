"""
JSON输出格式化器模块
负责将解码结果格式化为JSON并输出到文件
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Iterator
from datetime import datetime
import hashlib
import time
from core.decoder import DecodeResult

logger = logging.getLogger(__name__)


class JSONFormatter:
    """增强版JSON格式化器，支持流式输出和大文件处理"""
    
    def __init__(self, output_dir: str, streaming_threshold: int = 1000):
        """
        初始化格式化器
        
        Args:
            output_dir: 输出目录路径
            streaming_threshold: 包数量阈值，超过此值使用流式输出
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.streaming_threshold = streaming_threshold
    
    def format_and_save(self, result: DecodeResult) -> str:
        """
        格式化并保存解码结果
        
        Args:
            result: 解码结果
            
        Returns:
            str: 输出文件路径
        """
        # 生成标准化的输出文件名
        output_filename = self._generate_output_filename(result)
        output_path = self.output_dir / output_filename
        
        try:
            # 根据包数量选择输出方式
            if result.packet_count > self.streaming_threshold:
                self._save_streaming(result, output_path)
            else:
                self._save_standard(result, output_path)
            
            logger.info(f"保存JSON文件: {output_path} ({result.packet_count} 包)")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"保存JSON文件失败 {output_path}: {e}")
            raise
    
    def _generate_output_filename(self, result: DecodeResult) -> str:
        """
        生成标准化的输出文件名
        
        Args:
            result: 解码结果
            
        Returns:
            str: 文件名
        """
        input_file = Path(result.file_path)
        base_name = input_file.stem
        
        return f"{base_name}.json"
    
    def _save_standard(self, result: DecodeResult, output_path: Path):
        """
        标准方式保存（一次性加载到内存）
        
        Args:
            result: 解码结果
            output_path: 输出文件路径
        """
        json_data = self._build_json_structure(result)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False, default=str)
    
    def _save_streaming(self, result: DecodeResult, output_path: Path):
        """
        流式保存（逐块写入，节省内存）
        
        Args:
            result: 解码结果
            output_path: 输出文件路径
        """
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('{\n')
            
            # 写入元数据
            metadata = self._build_metadata()
            f.write(f'  "metadata": {json.dumps(metadata, indent=2, default=str)},\n')
            
            # 写入文件信息
            file_info = self._build_file_info(result)
            f.write(f'  "file_info": {json.dumps(file_info, indent=2, default=str)},\n')
            
            # 写入协议统计
            protocol_stats = self._calculate_protocol_statistics(result)
            f.write(f'  "protocol_statistics": {json.dumps(protocol_stats, indent=2, default=str)},\n')
            
            # 写入错误信息（如果有）
            if result.errors:
                error_info = {
                    'error_count': len(result.errors),
                    'errors': result.errors
                }
                f.write(f'  "errors": {json.dumps(error_info, indent=2, default=str)},\n')
            
            # 流式写入数据包信息
            f.write('  "packets": [\n')
            for i, packet in enumerate(result.packets):
                packet_data = self._build_packet_data(packet)
                packet_json = json.dumps(packet_data, indent=4, default=str)
                
                # 添加适当的缩进
                indented_packet = '\n'.join('    ' + line for line in packet_json.split('\n'))
                f.write(indented_packet)
                
                if i < len(result.packets) - 1:
                    f.write(',')
                f.write('\n')
            
            f.write('  ]\n')
            f.write('}\n')
    
    def _build_json_structure(self, result: DecodeResult) -> Dict[str, Any]:
        """
        构建完整的JSON数据结构
        
        Args:
            result: 解码结果
            
        Returns:
            Dict[str, Any]: JSON数据字典
        """
        # 构建完整的JSON结构
        json_structure = {
            'metadata': self._build_metadata(),
            'file_info': self._build_file_info(result),
            'protocol_statistics': self._calculate_protocol_statistics(result),
            'packets': [self._build_packet_data(packet) for packet in result.packets]
        }
        
        # 添加错误信息（如果有）
        if result.errors:
            json_structure['errors'] = {
                'error_count': len(result.errors),
                'errors': result.errors
            }
        
        return json_structure
    
    def _build_metadata(self) -> Dict[str, Any]:
        """构建元数据"""
        return {
            'decoder_version': '1.0.0',
            'generated_by': 'PCAP批量解码器',
            'generation_time': datetime.now().isoformat(),
            'format_version': '1.1.0'
        }
    
    def _build_file_info(self, result: DecodeResult) -> Dict[str, Any]:
        """构建文件信息"""
        return {
            'input_file': result.file_path,
            'file_name': Path(result.file_path).name,
            'file_size': result.file_size,
            'packet_count': result.packet_count,
            'decode_time': round(result.decode_time, 3),
            'processing_timestamp': datetime.now().isoformat()
        }
    
    def _build_packet_data(self, packet) -> Dict[str, Any]:
        """
        构建单个数据包的详细信息
        
        Args:
            packet: 数据包对象
            
        Returns:
            Dict[str, Any]: 数据包数据字典
        """
        packet_data = {
            'number': packet.number,
            'timestamp': packet.timestamp,
            'length': packet.length,
            'layers': packet.layers,
            'protocols': {}
        }
        
        # 详细的协议字段信息
        for protocol_name, protocol_data in packet.protocols.items():
            packet_data['protocols'][protocol_name] = {
                'fields': protocol_data.get('fields', {}),
                'summary': protocol_data.get('summary', ''),
                'layer_index': protocol_data.get('layer_index', 0)
            }
        
        return packet_data
    
    def _calculate_protocol_statistics(self, result: DecodeResult) -> Dict[str, Any]:
        """
        计算协议统计信息
        
        Args:
            result: 解码结果
            
        Returns:
            Dict[str, Any]: 协议统计信息
        """
        stats = {}
        
        # 统计每种协议的出现次数
        protocol_counts = {}
        layer_counts = {}
        protocol_combinations = {}
        
        for packet in result.packets:
            # 统计协议类型
            for protocol in packet.protocols.keys():
                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
            
            # 统计协议层数
            layer_count = len(packet.layers)
            layer_counts[layer_count] = layer_counts.get(layer_count, 0) + 1
            
            # 统计协议组合
            protocol_combo = '+'.join(sorted(packet.protocols.keys()))
            protocol_combinations[protocol_combo] = protocol_combinations.get(protocol_combo, 0) + 1
        
        stats = {
            'total_packets': len(result.packets),
            'protocol_distribution': protocol_counts,
            'layer_distribution': layer_counts,
            'protocol_combinations': protocol_combinations,
            'unique_protocols': sorted(list(protocol_counts.keys())),
            'protocol_count': len(protocol_counts),
            'average_layers_per_packet': round(sum(layer_counts.keys()) / len(result.packets), 2) if result.packets else 0
        }
        
        return stats
    
    def generate_summary_report(self, results: List[DecodeResult]) -> str:
        """
        生成批量处理的汇总报告
        
        Args:
            results: 解码结果列表
            
        Returns:
            str: 汇总报告文件路径
        """
        summary_path = self.output_dir / 'batch_summary_report.json'
        
        # 计算汇总统计
        total_files = len(results)
        total_packets = sum(r.packet_count for r in results)
        total_time = sum(r.decode_time for r in results)
        total_errors = sum(len(r.errors) for r in results)
        total_size = sum(r.file_size for r in results)
        
        # 协议汇总统计
        all_protocols = set()
        protocol_file_count = {}
        
        for result in results:
            file_protocols = set()
            for packet in result.packets:
                file_protocols.update(packet.protocols.keys())
                all_protocols.update(packet.protocols.keys())
            
            # 统计每种协议出现在多少个文件中
            for protocol in file_protocols:
                protocol_file_count[protocol] = protocol_file_count.get(protocol, 0) + 1
        
        # 性能统计
        avg_packets_per_second = total_packets / total_time if total_time > 0 else 0
        avg_mb_per_second = (total_size / 1024 / 1024) / total_time if total_time > 0 else 0
        
        summary_data = {
            'summary': {
                'total_files_processed': total_files,
                'total_packets_decoded': total_packets,
                'total_processing_time': round(total_time, 3),
                'total_errors': total_errors,
                'total_file_size': total_size,
                'average_packets_per_file': round(total_packets / total_files, 1) if total_files > 0 else 0,
                'average_processing_time': round(total_time / total_files, 3) if total_files > 0 else 0,
                'processing_speed': {
                    'packets_per_second': round(avg_packets_per_second, 1),
                    'mb_per_second': round(avg_mb_per_second, 2)
                }
            },
            'protocol_overview': {
                'unique_protocols_found': sorted(list(all_protocols)),
                'protocol_count': len(all_protocols),
                'protocol_file_distribution': protocol_file_count
            },
            'file_details': [
                {
                    'file': Path(r.file_path).name,
                    'packets': r.packet_count,
                    'size': r.file_size,
                    'time': round(r.decode_time, 3),
                    'errors': len(r.errors),
                    'speed_pps': round(r.packet_count / r.decode_time, 1) if r.decode_time > 0 else 0
                }
                for r in results
            ],
            'generation_info': {
                'generated_at': datetime.now().isoformat(),
                'generator': 'PCAP批量解码器 v1.0.0',
                'format_version': '1.1.0'
            }
        }
        
        # 保存汇总报告
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(summary_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"生成汇总报告: {summary_path}")
        return str(summary_path) 