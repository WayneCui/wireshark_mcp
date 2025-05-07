#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Wireshark MCP服务器
提供连接Wireshark工具的MCP实现
"""

import os
import sys
import subprocess
import json
import pyshark
import time
from typing import Dict, List, Optional, Any
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse, HTMLResponse

# 修改导入语句，使用新版本MCP
from mcp.server.fastmcp import FastMCP

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("WiresharkMCPServer")

class WiresharkPromptStore:
    """Wireshark相关提示的存储类"""
    
    def __init__(self):
        """初始化提示存储"""
        self._prompts = {
            "wireshark_filters": {
                "id": "wireshark_filters",
                "text": (
                    "常用Wireshark过滤器:\n"
                    "- IP地址过滤: ip.addr == 192.168.1.1\n"
                    "- 端口过滤: tcp.port == 80 或 udp.port == 53\n"
                    "- 协议过滤: http 或 dns 或 tcp\n"
                    "- HTTP请求过滤: http.request.method == \"GET\"\n"
                    "- DNS过滤: dns.qry.name contains \"example.com\"\n"
                    "- 数据包大小过滤: frame.len > 1000\n"
                    "- 多条件组合: (ip.src == 192.168.1.1) && (tcp.port == 80)\n"
                )
            },
            "wireshark_analysis": {
                "id": "wireshark_analysis",
                "text": (
                    "网络分析基本步骤:\n"
                    "1. 应用适当的过滤器缩小分析范围\n"
                    "2. 查找关键连接 (SYN, SYN-ACK等TCP握手)\n"
                    "3. 分析响应时间和延迟情况\n"
                    "4. 检查错误包和重传包\n"
                    "5. 对特定协议深入分析其字段\n"
                    "6. 导出重要会话为单独文件\n"
                )
            },
            "wireshark_commands": {
                "id": "wireshark_commands",
                "text": (
                    "有用的Wireshark命令行命令:\n"
                    "- 捕获数据包: tshark -i <interface> -w <output.pcap>\n"
                    "- 读取捕获文件: tshark -r <input.pcap>\n"
                    "- 应用过滤器: tshark -r <input.pcap> -Y \"<display filter>\"\n"
                    "- 提取特定字段: tshark -r <input.pcap> -T fields -e <field>\n"
                    "- 统计信息: tshark -r <input.pcap> -q -z <statistics>\n"
                )
            }
        }

    def get(self, prompt_id: str) -> Optional[Dict[str, str]]:
        """获取特定ID的提示"""
        return self._prompts.get(prompt_id)
    
    def list(self) -> List[Dict[str, str]]:
        """列出所有提示"""
        return list(self._prompts.values())

class WiresharkTools:
    """Wireshark工具类"""
    
    @staticmethod
    def check_wireshark_installed() -> bool:
        """检查Wireshark是否已安装"""
        try:
            # 检查tshark是否可用
            subprocess.run(
                ["tshark", "--version"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                check=True
            )
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    @staticmethod
    def get_available_interfaces() -> List[Dict[str, str]]:
        """获取可用的网络接口列表"""
        try:
            result = subprocess.run(
                ["tshark", "-D"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                check=True
            )
            
            interfaces = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    # 格式通常为: "1. en0 (Wi-Fi)"
                    parts = line.split(' ', 1)
                    if len(parts) > 1:
                        index = parts[0].rstrip('.')
                        description = parts[1]
                        interfaces.append({
                            "index": index,
                            "interface": description
                        })
            
            return interfaces
        except subprocess.SubprocessError:
            return []
    
    @staticmethod
    def capture_packets(interface: str, duration: int = 10, filter_str: str = None, output_file: str = None) -> Dict[str, Any]:
        """捕获网络数据包"""
        try:
            cmd = ["tshark", "-i", interface, "-a", f"duration:{duration}"]
            
            if filter_str:
                cmd.extend(["-f", filter_str])
            
            if output_file:
                cmd.extend(["-w", output_file])
            
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "output_file": output_file if output_file else None
            }
        except subprocess.SubprocessError as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    @staticmethod
    def read_capture_file(file_path: str, filter_str: str = None, limit: int = 100) -> Dict[str, Any]:
        """读取捕获的数据包文件"""
        try:
            cmd = ["tshark", "-r", file_path]
            
            if filter_str:
                cmd.extend(["-Y", filter_str])
            
            if limit:
                cmd.extend(["-c", str(limit)])
            
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
        except subprocess.SubprocessError as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    @staticmethod
    def analyze_capture(file_path: str, analysis_type: str) -> Dict[str, Any]:
        """分析捕获文件并提供统计数据"""
        supported_types = {
            "conversations": "conv,ip",
            "endpoints": "endpoints,ip",
            "protocols": "io,phs",
            "http": "http,tree",
            "dns": "dns,tree"
        }
        
        if analysis_type not in supported_types:
            return {
                "success": False,
                "error": f"不支持的分析类型: {analysis_type}. 支持的类型: {list(supported_types.keys())}"
            }
        
        try:
            cmd = ["tshark", "-r", file_path, "-q", "-z", supported_types[analysis_type]]
            
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
        except subprocess.SubprocessError as e:
            return {
                "success": False,
                "error": str(e)
            }

@asynccontextmanager
async def server_lifespan(server: FastMCP) -> AsyncIterator[Dict[str, Any]]:
    """管理服务器启动和关闭生命周期"""
    try:
        logger.info("Wireshark MCP服务器启动中...")
        # 验证Wireshark可用性
        if not WiresharkTools.check_wireshark_installed():
            logger.error("Wireshark未安装或tshark命令不可用")
            raise Exception("Wireshark未安装或tshark命令不可用")
            
        logger.info("成功连接到Wireshark")
        yield {}
    finally:
        logger.info("Wireshark MCP服务器关闭")

# 创建MCP服务器
app = FastMCP(
    "wireshark", 
    description="通过Model Context Protocol连接Wireshark",
    lifespan=server_lifespan
)
prompt_store = WiresharkPromptStore()

# 注册工具
@app.tool()
def wireshark_check_installation() -> Dict[str, bool]:
    """检查Wireshark是否已安装"""
    is_installed = WiresharkTools.check_wireshark_installed()
    return {"installed": is_installed}

@app.tool()
def wireshark_get_interfaces() -> Dict[str, List[Dict[str, str]]]:
    """获取可用的网络接口列表"""
    interfaces = WiresharkTools.get_available_interfaces()
    return {"interfaces": interfaces}

@app.tool()
def wireshark_capture_packets(
    interface: str,
    duration: int = 10,
    filter_str: str = None,
    output_file: str = None
) -> Dict[str, Any]:
    """
    捕获网络数据包
    
    参数:
    - interface: 要捕获的网络接口
    - duration: 捕获持续时间（秒）
    - filter_str: 可选的捕获过滤器
    - output_file: 可选的输出文件路径
    """
    try:
        logger.info(f"开始在接口 {interface} 上捕获数据包 (持续 {duration} 秒)")
        
        if not output_file:
            output_file = f"capture_{int(time.time())}.pcap"
        
        result = WiresharkTools.capture_packets(
            interface=interface,
            duration=duration,
            filter_str=filter_str,
            output_file=output_file
        )
        
        if result["success"]:
            logger.info(f"成功捕获数据包，保存到 {output_file}")
        else:
            logger.error(f"捕获数据包失败: {result.get('error', '未知错误')}")
            
        return result
    except Exception as e:
        logger.error(f"捕获数据包时发生错误: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@app.tool()
def wireshark_read_capture(
    file_path: str,
    filter_str: str = None,
    limit: int = 100
) -> Dict[str, Any]:
    """
    读取捕获的数据包文件
    
    参数:
    - file_path: 捕获文件路径
    - filter_str: 可选的显示过滤器
    - limit: 最大读取的数据包数量
    """
    result = WiresharkTools.read_capture_file(
        file_path=file_path,
        filter_str=filter_str,
        limit=limit
    )
    
    return result

@app.tool()
def wireshark_analyze(
    file_path: str,
    analysis_type: str
) -> Dict[str, Any]:
    """
    分析捕获文件并提供统计数据
    
    参数:
    - file_path: 捕获文件路径
    - analysis_type: 分析类型 (conversations, endpoints, protocols, http, dns)
    """
    result = WiresharkTools.analyze_capture(
        file_path=file_path,
        analysis_type=analysis_type
    )
    
    return result

@app.tool()
def wireshark_get_prompts() -> Dict[str, List[Dict[str, str]]]:
    """获取所有Wireshark相关提示"""
    prompts = prompt_store.list()
    return {
        "prompts": prompts
    }

@app.tool()
def wireshark_get_prompt(
    prompt_id: str
) -> Dict[str, Any]:
    """
    获取特定的Wireshark提示
    
    参数:
    - prompt_id: 提示ID
    """
    prompt = prompt_store.get(prompt_id)
    if prompt:
        return {
            "success": True,
            "prompt": prompt
        }
    else:
        return {
            "success": False,
            "error": f"未找到ID为'{prompt_id}'的提示"
        }

@app.tool()
def wireshark_health_check() -> Dict[str, Any]:
    """
    检查Wireshark服务状态
    
    返回Wireshark安装状态和可用网络接口数量
    """
    try:
        is_installed = WiresharkTools.check_wireshark_installed()
        interfaces = WiresharkTools.get_available_interfaces() if is_installed else []
        
        return {
            "status": "ok" if is_installed else "error",
            "wireshark_installed": is_installed,
            "interface_count": len(interfaces),
            "timestamp": time.time()
        }
    except Exception as e:
        logger.error(f"健康检查失败: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "timestamp": time.time()
        }

@app.prompt()
def wireshark_filter_guide() -> str:
    """提供Wireshark过滤器使用指南"""
    return """常用Wireshark过滤器:
- IP地址过滤: ip.addr == 192.168.1.1
- 端口过滤: tcp.port == 80 或 udp.port == 53
- 协议过滤: http 或 dns 或 tcp
- HTTP请求过滤: http.request.method == "GET"
- DNS过滤: dns.qry.name contains "example.com"
- 数据包大小过滤: frame.len > 1000
- 多条件组合: (ip.src == 192.168.1.1) && (tcp.port == 80)

过滤器示例用例:
1. 查找特定主机通信: ip.addr == 10.0.0.1
2. 查找HTTP GET请求: http.request.method == "GET"
3. 查找DNS查询: dns && dns.flags.response == 0
4. 查找TCP重传: tcp.analysis.retransmission
5. 通过端口过滤特定服务: tcp.port == 443 或 udp.port == 53
"""

@app.prompt()
def wireshark_analysis_guide() -> str:
    """提供Wireshark网络分析方法指南"""
    return """网络分析基本步骤:
1. 应用适当的过滤器缩小分析范围
2. 查找关键连接 (SYN, SYN-ACK等TCP握手)
3. 分析响应时间和延迟情况
4. 检查错误包和重传包
5. 对特定协议深入分析其字段
6. 导出重要会话为单独文件

分析方法:
- 查看统计信息: Statistics > Protocol Hierarchy / Endpoints / Conversations
- 跟踪TCP流: 右键点击包 > Follow > TCP Stream
- 查看协议分布: 使用wireshark_analyze工具的"protocols"分析类型
- 识别异常延迟: 使用"tcp.time_delta > 1"过滤器查找响应慢的包
- 识别错误包: 使用"http.response.code >= 400"查找HTTP错误
"""

# 修改SSE服务器创建代码
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.responses import JSONResponse, HTMLResponse
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

def create_sse_server(mcp_server):
    """创建处理SSE连接和消息的Starlette应用"""
    transport = SseServerTransport("/messages/")

    # 定义处理函数
    async def handle_sse(request):
        async with transport.connect_sse(
            request.scope, request.receive, request._send
        ) as streams:
            await mcp_server.run(
                streams[0], streams[1], mcp_server.create_initialization_options()
            )
    
    async def index(request):
        """提供简单的索引页面"""
        return HTMLResponse("""
        <html>
            <head><title>Wireshark MCP服务器</title></head>
            <body>
                <h1>Wireshark MCP服务器</h1>
                <p>Wireshark MCP服务器已成功启动。</p>
                <p>连接端点: <code>/sse/</code></p>
            </body>
        </html>
        """)
    
    async def health(request):
        """提供简单的健康检查端点"""
        is_installed = WiresharkTools.check_wireshark_installed()
        return JSONResponse({
            "status": "healthy" if is_installed else "unhealthy",
            "wireshark_installed": is_installed,
            "server_time": time.time()
        })

    # 创建Starlette路由
    routes = [
        Route("/", endpoint=index),
        Route("/health", endpoint=health),
        Route("/sse/", endpoint=handle_sse),
        Mount("/messages/", app=transport.handle_post_message),
    ]

    # 添加CORS中间件
    middleware = [
        Middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
        )
    ]

    # 创建Starlette应用
    return Starlette(routes=routes, middleware=middleware)

if __name__ == "__main__":
    try:
        # 启动MCP服务器
        port = int(os.environ.get("MCP_PORT", 3001))
        host = os.environ.get("MCP_HOST", "127.0.0.1")
        
        # 显示基本信息
        logger.info(f"启动Wireshark MCP服务器在 {host}:{port}")
        if WiresharkTools.check_wireshark_installed():
            logger.info("Wireshark已安装并可用")
            interfaces = WiresharkTools.get_available_interfaces()
            logger.info(f"检测到 {len(interfaces)} 个网络接口:")
            for interface in interfaces:
                logger.info(f"  {interface['index']}. {interface['interface']}")
        else:
            logger.error("Wireshark未安装或tshark命令不可用")
            logger.error("请安装Wireshark并确保tshark命令可用")
            sys.exit(1)
        
        # 使用自定义函数创建SSE服务器应用
        sse_app = create_sse_server(app._mcp_server)
        
        # 启动服务器
        import uvicorn
        logger.info(f"服务器已就绪，可通过 http://{host}:{port}/sse/ 访问")
        uvicorn.run(sse_app, host=host, port=port)
    except Exception as e:
        logger.error(f"启动服务器时发生错误: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1) 