"""
报告生成器

负责将分析结果格式化为各种输出格式
支持JSON、HTML、CSV等多种报告格式
"""

import json
import csv
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from datetime import datetime

logger = logging.getLogger(__name__)


class ReportGenerator:
    """报告生成器"""
    
    def __init__(self):
        """初始化报告生成器"""
        self.supported_formats = ['json', 'html', 'csv', 'txt']
    
    def generate_report(self, analysis_results: Dict[str, Any], 
                       output_path: Union[str, Path],
                       format_type: str = 'json',
                       template_options: Optional[Dict[str, Any]] = None) -> Path:
        """
        生成分析报告
        
        Args:
            analysis_results: 分析结果数据
            output_path: 输出路径
            format_type: 报告格式类型
            template_options: 模板选项
            
        Returns:
            Path: 生成的报告文件路径
        """
        output_path = Path(output_path)
        
        if format_type not in self.supported_formats:
            raise ValueError(f"不支持的报告格式: {format_type}")
        
        # 确保输出目录存在
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 根据格式类型生成报告
        if format_type == 'json':
            return self._generate_json_report(analysis_results, output_path)
        elif format_type == 'html':
            return self._generate_html_report(analysis_results, output_path, template_options)
        elif format_type == 'csv':
            return self._generate_csv_report(analysis_results, output_path)
        elif format_type == 'txt':
            return self._generate_text_report(analysis_results, output_path)
        else:
            raise ValueError(f"未实现的报告格式: {format_type}")
    
    def _generate_json_report(self, analysis_results: Dict[str, Any], 
                             output_path: Path) -> Path:
        """生成JSON格式报告"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(analysis_results, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"JSON报告已生成: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"生成JSON报告失败: {e}")
            raise
    
    def _generate_html_report(self, analysis_results: Dict[str, Any], 
                             output_path: Path,
                             template_options: Optional[Dict[str, Any]] = None) -> Path:
        """生成HTML格式报告"""
        try:
            html_content = self._create_html_content(analysis_results, template_options)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML报告已生成: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"生成HTML报告失败: {e}")
            raise
    
    def _generate_csv_report(self, analysis_results: Dict[str, Any], 
                            output_path: Path) -> Path:
        """生成CSV格式报告"""
        try:
            csv_data = self._extract_csv_data(analysis_results)
            
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                if csv_data:
                    writer = csv.DictWriter(f, fieldnames=csv_data[0].keys())
                    writer.writeheader()
                    writer.writerows(csv_data)
            
            logger.info(f"CSV报告已生成: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"生成CSV报告失败: {e}")
            raise
    
    def _generate_text_report(self, analysis_results: Dict[str, Any], 
                             output_path: Path) -> Path:
        """生成纯文本格式报告"""
        try:
            text_content = self._create_text_content(analysis_results)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(text_content)
            
            logger.info(f"文本报告已生成: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"生成文本报告失败: {e}")
            raise
    
    def _create_html_content(self, analysis_results: Dict[str, Any], 
                            template_options: Optional[Dict[str, Any]] = None) -> str:
        """创建HTML报告内容"""
        template_options = template_options or {}
        
        # 获取基本信息
        file_info = analysis_results.get('file_info', {})
        statistics = analysis_results.get('statistics', {})
        metadata = analysis_results.get('metadata', {})
        
        # 生成HTML内容
        html_content = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCAP数据分析报告</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
        }}
        .content {{
            padding: 30px;
        }}
        .section {{
            margin-bottom: 30px;
            padding: 20px;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            background-color: #fafafa;
        }}
        .section h2 {{
            margin-top: 0;
            color: #333;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }}
        .info-item {{
            background: white;
            padding: 15px;
            border-radius: 4px;
            border-left: 4px solid #667eea;
        }}
        .info-label {{
            font-weight: bold;
            color: #666;
            margin-bottom: 5px;
        }}
        .info-value {{
            font-size: 1.2em;
            color: #333;
        }}
        .stats-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        .stats-table th, .stats-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        .stats-table th {{
            background-color: #667eea;
            color: white;
        }}
        .stats-table tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .json-view {{
            background: #f8f8f8;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            overflow-x: auto;
            max-height: 400px;
            overflow-y: auto;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>PCAP数据分析报告</h1>
            <p>生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="content">
            <!-- 文件信息 -->
            <div class="section">
                <h2>📄 文件信息</h2>
                <div class="info-grid">
"""
        
        # 添加文件信息
        if 'file_path' in file_info:
            html_content += f"""
                    <div class="info-item">
                        <div class="info-label">文件路径</div>
                        <div class="info-value">{file_info['file_path']}</div>
                    </div>
"""
        
        if 'packet_count' in file_info:
            html_content += f"""
                    <div class="info-item">
                        <div class="info-label">数据包数量</div>
                        <div class="info-value">{file_info['packet_count']:,}</div>
                    </div>
"""
        
        if 'analysis_time' in file_info:
            html_content += f"""
                    <div class="info-item">
                        <div class="info-label">分析耗时</div>
                        <div class="info-value">{file_info['analysis_time']:.2f} 秒</div>
                    </div>
"""
        
        html_content += """
                </div>
            </div>
            
            <!-- 统计结果 -->
            <div class="section">
                <h2>📊 统计结果</h2>
"""
        
        # 添加统计项
        for stat_name, stat_data in statistics.items():
            if 'error' not in stat_data:
                html_content += f"""
                <h3>{stat_data.get('name', stat_name)}</h3>
                <p>{stat_data.get('description', '')}</p>
                <div class="json-view">
                    <pre>{json.dumps(stat_data.get('results', {}), indent=2, ensure_ascii=False)}</pre>
                </div>
"""
        
        html_content += """
            </div>
            
            <!-- 元数据 -->
            <div class="section">
                <h2>ℹ️ 元数据</h2>
                <div class="json-view">
                    <pre>""" + json.dumps(metadata, indent=2, ensure_ascii=False) + """</pre>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""
        
        return html_content
    
    def _extract_csv_data(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """提取CSV数据"""
        csv_data = []
        
        file_info = analysis_results.get('file_info', {})
        statistics = analysis_results.get('statistics', {})
        
        # 基本信息行
        base_row = {
            'file_path': file_info.get('file_path', ''),
            'packet_count': file_info.get('packet_count', 0),
            'analysis_time': file_info.get('analysis_time', 0)
        }
        
        # 为每个统计项创建行
        for stat_name, stat_data in statistics.items():
            if 'error' not in stat_data:
                row = base_row.copy()
                row['statistic_name'] = stat_name
                row['statistic_description'] = stat_data.get('description', '')
                
                # 展平统计结果
                results = stat_data.get('results', {})
                for key, value in results.items():
                    if isinstance(value, (int, float, str)):
                        row[f'result_{key}'] = value
                    else:
                        row[f'result_{key}'] = str(value)
                
                csv_data.append(row)
        
        return csv_data
    
    def _create_text_content(self, analysis_results: Dict[str, Any]) -> str:
        """创建纯文本报告内容"""
        content = []
        content.append("=" * 60)
        content.append("PCAP数据分析报告")
        content.append("=" * 60)
        content.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        content.append("")
        
        # 文件信息
        file_info = analysis_results.get('file_info', {})
        if file_info:
            content.append("文件信息:")
            content.append("-" * 20)
            for key, value in file_info.items():
                content.append(f"  {key}: {value}")
            content.append("")
        
        # 统计结果
        statistics = analysis_results.get('statistics', {})
        if statistics:
            content.append("统计结果:")
            content.append("-" * 20)
            
            for stat_name, stat_data in statistics.items():
                if 'error' not in stat_data:
                    content.append(f"\n【{stat_data.get('name', stat_name)}】")
                    content.append(f"描述: {stat_data.get('description', '')}")
                    content.append("结果:")
                    
                    results = stat_data.get('results', {})
                    for key, value in results.items():
                        content.append(f"  {key}: {value}")
                    
                    calculation_time = stat_data.get('calculation_time', 0)
                    content.append(f"计算耗时: {calculation_time:.3f}秒")
                else:
                    content.append(f"\n【{stat_name}】")
                    content.append(f"错误: {stat_data['error']}")
            
            content.append("")
        
        # 元数据
        metadata = analysis_results.get('metadata', {})
        if metadata:
            content.append("元数据:")
            content.append("-" * 20)
            for key, value in metadata.items():
                content.append(f"  {key}: {value}")
        
        return "\n".join(content)
    
    def generate_summary_report(self, batch_results: Dict[str, Any], 
                               output_path: Union[str, Path]) -> Path:
        """
        生成批量分析的摘要报告
        
        Args:
            batch_results: 批量分析结果
            output_path: 输出路径
            
        Returns:
            Path: 生成的摘要报告路径
        """
        summary_data = {
            'report_type': 'batch_summary',
            'generation_time': datetime.now().isoformat(),
            'summary': batch_results.get('summary', {}),
            'aggregated_results': batch_results.get('aggregated_results', {}),
            'error_summary': self._create_error_summary(batch_results.get('errors', []))
        }
        
        return self._generate_json_report(summary_data, Path(output_path))
    
    def _create_error_summary(self, errors: List[Dict[str, Any]]) -> Dict[str, Any]:
        """创建错误摘要"""
        if not errors:
            return {'total_errors': 0, 'error_types': {}}
        
        error_types = {}
        for error in errors:
            error_msg = error.get('error', 'Unknown error')
            error_type = error_msg.split(':')[0] if ':' in error_msg else 'General'
            
            if error_type not in error_types:
                error_types[error_type] = {
                    'count': 0,
                    'files': []
                }
            
            error_types[error_type]['count'] += 1
            if 'file_info' in error and 'file_path' in error['file_info']:
                error_types[error_type]['files'].append(error['file_info']['file_path'])
        
        return {
            'total_errors': len(errors),
            'error_types': error_types
        } 