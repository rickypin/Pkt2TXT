#!/usr/bin/env python3
"""
PCAP批量解码器部署脚本

用于自动化构建、测试和发布流程
"""

import os
import sys
import subprocess
import shutil
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any

class DeploymentManager:
    """部署管理器"""
    
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root).resolve()
        self.dist_dir = self.project_root / "dist"
        self.build_dir = self.project_root / "build"
        
    def clean_build(self) -> bool:
        """清理构建目录"""
        print("🧹 清理构建目录...")
        
        try:
            if self.dist_dir.exists():
                shutil.rmtree(self.dist_dir)
                print(f"  ✅ 清理 {self.dist_dir}")
            
            if self.build_dir.exists():
                shutil.rmtree(self.build_dir)
                print(f"  ✅ 清理 {self.build_dir}")
            
            # 清理缓存目录
            cache_dirs = [
                self.project_root / "__pycache__",
                self.project_root / "pcap_decoder" / "__pycache__",
                self.project_root / ".pytest_cache",
                self.project_root / ".coverage",
            ]
            
            for cache_dir in cache_dirs:
                if cache_dir.exists():
                    if cache_dir.is_file():
                        cache_dir.unlink()
                    else:
                        shutil.rmtree(cache_dir)
                    print(f"  ✅ 清理 {cache_dir}")
            
            return True
        except Exception as e:
            print(f"  ❌ 清理失败: {e}")
            return False
    
    def run_tests(self) -> bool:
        """运行测试套件"""
        print("🧪 运行测试套件...")
        
        try:
            # 运行pytest
            cmd = ["python", "-m", "pytest", "tests/", "-v", "--tb=short"]
            result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("  ✅ 所有测试通过")
                return True
            else:
                print("  ❌ 测试失败:")
                print(result.stdout)
                print(result.stderr)
                return False
        except Exception as e:
            print(f"  ❌ 测试执行失败: {e}")
            return False
    
    def run_linting(self) -> bool:
        """运行代码质量检查"""
        print("🔍 运行代码质量检查...")
        
        checks = [
            {
                "name": "Black格式检查",
                "cmd": ["python", "-m", "black", "--check", "pcap_decoder/"],
                "fix_cmd": ["python", "-m", "black", "pcap_decoder/"]
            },
            {
                "name": "Flake8风格检查", 
                "cmd": ["python", "-m", "flake8", "pcap_decoder/"],
                "fix_cmd": None
            },
            {
                "name": "MyPy类型检查",
                "cmd": ["python", "-m", "mypy", "pcap_decoder/"],
                "fix_cmd": None
            }
        ]
        
        all_passed = True
        for check in checks:
            try:
                result = subprocess.run(
                    check["cmd"], 
                    cwd=self.project_root, 
                    capture_output=True, 
                    text=True
                )
                
                if result.returncode == 0:
                    print(f"  ✅ {check['name']}")
                else:
                    print(f"  ❌ {check['name']} 失败")
                    if check.get("fix_cmd") and input("是否自动修复? (y/N): ").lower() == 'y':
                        subprocess.run(check["fix_cmd"], cwd=self.project_root)
                        print(f"  🔧 已尝试自动修复 {check['name']}")
                    all_passed = False
            except Exception as e:
                print(f"  ❌ {check['name']} 执行失败: {e}")
                all_passed = False
        
        return all_passed
    
    def build_package(self) -> bool:
        """构建分发包"""
        print("📦 构建分发包...")
        
        try:
            # 确保有构建工具
            subprocess.run([sys.executable, "-m", "pip", "install", "build", "twine"], 
                         check=True, capture_output=True)
            
            # 构建包
            cmd = [sys.executable, "-m", "build"]
            result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("  ✅ 包构建成功")
                
                # 列出生成的文件
                if self.dist_dir.exists():
                    dist_files = list(self.dist_dir.glob("*"))
                    print("  📁 生成的文件:")
                    for file in dist_files:
                        print(f"    - {file.name} ({file.stat().st_size / 1024:.1f} KB)")
                
                return True
            else:
                print("  ❌ 包构建失败:")
                print(result.stdout)
                print(result.stderr)
                return False
        except Exception as e:
            print(f"  ❌ 构建失败: {e}")
            return False
    
    def check_package(self) -> bool:
        """检查分发包"""
        print("🔍 检查分发包...")
        
        try:
            if not self.dist_dir.exists():
                print("  ❌ 分发目录不存在")
                return False
            
            dist_files = list(self.dist_dir.glob("*"))
            if not dist_files:
                print("  ❌ 没有找到分发文件")
                return False
            
            # 使用twine检查
            cmd = ["python", "-m", "twine", "check", str(self.dist_dir / "*")]
            result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("  ✅ 包检查通过")
                return True
            else:
                print("  ❌ 包检查失败:")
                print(result.stdout)
                print(result.stderr)
                return False
        except Exception as e:
            print(f"  ❌ 检查失败: {e}")
            return False
    
    def test_installation(self) -> bool:
        """测试包安装"""
        print("🧪 测试包安装...")
        
        try:
            # 创建临时虚拟环境进行测试
            temp_venv = self.project_root / ".temp_venv"
            if temp_venv.exists():
                shutil.rmtree(temp_venv)
            
            # 创建虚拟环境
            subprocess.run([sys.executable, "-m", "venv", str(temp_venv)], check=True)
            
            # 确定pip路径
            if sys.platform == "win32":
                pip_path = temp_venv / "Scripts" / "pip.exe"
                python_path = temp_venv / "Scripts" / "python.exe"
            else:
                pip_path = temp_venv / "bin" / "pip"
                python_path = temp_venv / "bin" / "python"
            
            # 安装包
            whl_files = list(self.dist_dir.glob("*.whl"))
            if not whl_files:
                print("  ❌ 没有找到wheel文件")
                return False
            
            whl_file = whl_files[0]
            subprocess.run([str(pip_path), "install", str(whl_file)], check=True)
            print(f"  ✅ 包安装成功: {whl_file.name}")
            
            # 测试导入
            test_script = """
import pcap_decoder
from pcap_decoder.core.scanner import DirectoryScanner
from pcap_decoder.core.decoder import PacketDecoder
print("导入测试成功")
print(f"版本: {pcap_decoder.__version__}")
"""
            
            result = subprocess.run(
                [str(python_path), "-c", test_script],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print("  ✅ 导入测试通过")
                print(f"  📋 输出: {result.stdout.strip()}")
            else:
                print("  ❌ 导入测试失败:")
                print(result.stderr)
                return False
            
            # 清理临时环境
            shutil.rmtree(temp_venv)
            
            return True
        except Exception as e:
            print(f"  ❌ 安装测试失败: {e}")
            return False
    
    def upload_to_pypi(self, test: bool = True) -> bool:
        """上传到PyPI"""
        repo_name = "testpypi" if test else "pypi"
        print(f"🚀 上传到 {'Test PyPI' if test else 'PyPI'}...")
        
        try:
            # 检查是否有分发文件
            if not self.dist_dir.exists() or not list(self.dist_dir.glob("*")):
                print("  ❌ 没有找到分发文件，请先构建包")
                return False
            
            # 上传命令
            cmd = ["python", "-m", "twine", "upload"]
            if test:
                cmd.extend(["--repository", "testpypi"])
            cmd.append(str(self.dist_dir / "*"))
            
            print(f"  执行命令: {' '.join(cmd)}")
            result = subprocess.run(cmd, cwd=self.project_root)
            
            if result.returncode == 0:
                print(f"  ✅ 上传到 {repo_name} 成功")
                return True
            else:
                print(f"  ❌ 上传到 {repo_name} 失败")
                return False
        except Exception as e:
            print(f"  ❌ 上传失败: {e}")
            return False
    
    def generate_deployment_report(self) -> Dict[str, Any]:
        """生成部署报告"""
        import datetime
        
        report = {
            "deployment_time": datetime.datetime.now().isoformat(),
            "project_root": str(self.project_root),
            "dist_files": [],
            "package_info": {}
        }
        
        # 收集分发文件信息
        if self.dist_dir.exists():
            for file in self.dist_dir.glob("*"):
                report["dist_files"].append({
                    "name": file.name,
                    "size": file.stat().st_size,
                    "path": str(file)
                })
        
        # 收集包信息
        pyproject_file = self.project_root / "pyproject.toml"
        if pyproject_file.exists():
            import toml
            try:
                pyproject = toml.load(pyproject_file)
                project_info = pyproject.get("project", {})
                report["package_info"] = {
                    "name": project_info.get("name"),
                    "version": project_info.get("version"),
                    "description": project_info.get("description")
                }
            except Exception:
                pass
        
        return report

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="PCAP批量解码器部署脚本")
    parser.add_argument("--clean", action="store_true", help="清理构建目录")
    parser.add_argument("--test", action="store_true", help="运行测试")
    parser.add_argument("--lint", action="store_true", help="运行代码质量检查")
    parser.add_argument("--build", action="store_true", help="构建分发包")
    parser.add_argument("--check", action="store_true", help="检查分发包")
    parser.add_argument("--test-install", action="store_true", help="测试安装")
    parser.add_argument("--upload-test", action="store_true", help="上传到Test PyPI")
    parser.add_argument("--upload", action="store_true", help="上传到PyPI")
    parser.add_argument("--all", action="store_true", help="执行完整的部署流程")
    parser.add_argument("--project-root", default=".", help="项目根目录")
    
    args = parser.parse_args()
    
    # 创建部署管理器
    dm = DeploymentManager(args.project_root)
    
    # 如果没有指定任何操作，显示帮助
    if not any(vars(args).values()):
        parser.print_help()
        return
    
    success = True
    
    # 执行操作
    if args.all or args.clean:
        success &= dm.clean_build()
    
    if args.all or args.lint:
        success &= dm.run_linting()
    
    if args.all or args.test:
        success &= dm.run_tests()
    
    if args.all or args.build:
        success &= dm.build_package()
    
    if args.all or args.check:
        success &= dm.check_package()
    
    if args.all or args.test_install:
        success &= dm.test_installation()
    
    if args.upload_test:
        success &= dm.upload_to_pypi(test=True)
    
    if args.upload:
        if input("确认上传到正式PyPI? (yes/no): ").lower() == "yes":
            success &= dm.upload_to_pypi(test=False)
        else:
            print("❌ 用户取消上传")
            success = False
    
    # 生成报告
    report = dm.generate_deployment_report()
    report_file = dm.project_root / "deployment_report.json"
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"\n📊 部署报告已保存到: {report_file}")
    
    if success:
        print("\n🎉 部署完成!")
        exit_code = 0
    else:
        print("\n❌ 部署过程中出现错误")
        exit_code = 1
    
    sys.exit(exit_code)

if __name__ == "__main__":
    main() 