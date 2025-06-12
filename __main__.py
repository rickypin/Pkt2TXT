"""
PCAP解码器主入口文件
支持 python -m pcap_decoder 调用
"""

if __name__ == '__main__':
    from .cli import main
    main() 