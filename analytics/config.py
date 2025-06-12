"""
Analytics模块配置

定义统计模块的配置选项和默认设置
"""

from typing import Dict, List, Any
from pathlib import Path


class AnalyticsConfig:
    """统计分析配置类"""
    
    def __init__(self):
        self.default_config = {
            # 基础设置
            'version': '1.0.0',
            'max_workers': 4,
            'enable_parallel': True,
            'output_formats': ['json'],
            
            # 统计项配置
            'statistics': {
                'traffic': {
                    'basic_traffic': {
                        'enabled': True,
                        'description': '基础流量统计'
                    },
                    'packet_size_distribution': {
                        'enabled': True,
                        'parameters': {
                            'bin_size': 64
                        }
                    },
                    'time_based_traffic': {
                        'enabled': True,
                        'parameters': {
                            'interval_seconds': 60
                        }
                    }
                },
                'protocol': {
                    'enabled': False  # 未来扩展
                },
                'security': {
                    'enabled': False  # 未来扩展
                }
            },
            
            # 输出设置
            'output': {
                'directory': './analytics_results',
                'filename_template': '{input_name}_analytics.json',
                'include_metadata': True,
                'compress_output': False
            }
        }
    
    def get_config(self) -> Dict[str, Any]:
        """获取配置字典"""
        return self.default_config.copy()
    
    def load_from_file(self, config_path: str) -> Dict[str, Any]:
        """从文件加载配置"""
        config_file = Path(config_path)
        
        if config_file.exists():
            import json
            with open(config_file, 'r', encoding='utf-8') as f:
                file_config = json.load(f)
            
            # 合并配置
            merged_config = self.default_config.copy()
            merged_config.update(file_config)
            return merged_config
        
        return self.default_config.copy()
    
    def save_to_file(self, config: Dict[str, Any], config_path: str):
        """保存配置到文件"""
        import json
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)


# 默认配置实例
default_analytics_config = AnalyticsConfig() 