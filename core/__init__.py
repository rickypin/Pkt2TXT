"""
Pkt2TXT Core Library
====================

This package contains the core functionalities of the PCAP Decoder project.

Modules:
- **decoder**:         Decodes PCAP files into packet data.
- **extractor**:       Extracts specific protocol fields from packets.
- **formatter**:       Formats decoded data into JSON.
- **processor**:       Manages batch processing of files.
- **scanner**:         Scans directories for PCAP files.
- **models**:          Defines the core data structures.

Key Classes:
- `BatchProcessor`:  High-level class for batch processing.
- `PacketDecoder`:   Low-level class for decoding individual files.
- `DecodeResult`:    Dataclass for storing decoding results.
"""

from core.scanner import DirectoryScanner
from .decoder import PacketDecoder
from .models import DecodeResult
from core.extractor import ProtocolExtractor
from core.formatter import JSONFormatter
from .processor import EnhancedBatchProcessor as BatchProcessor

__all__ = [
    'DirectoryScanner',
    'PacketDecoder',
    'DecodeResult',
    'ProtocolExtractor',
    'JSONFormatter',
    'BatchProcessor'
] 