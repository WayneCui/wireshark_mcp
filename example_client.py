#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Wireshark MCP客户端示例
展示如何使用Wireshark MCP服务器
"""

import asyncio
import json
import time
import sys
from typing import Dict, Any

from mcp.client.client import Client
from mcp.client.transport import ClientTransport
from mcp.client.sse import SseClientTransport

# MCP服务器地址
MCP_SERVER_URL = "http://127.0.0.1:3001/sse/"

async def print_response(result: Any) -> None:
    """格式化并打印响应"""
    if not result:
        return
    
    print(json.dumps(result, indent=2, ensure_ascii=False))

async def main() -> None:
    """主函数"""
    try:
        print(f"正在连接到MCP服务器: {MCP_SERVER_URL}")
        
        # 创建SSE客户端传输
        transport = SseClientTransport(MCP_SERVER_URL)
        
        # 创建客户端
        client = Client()
        
        # 连接到服务器
        await client.connect(transport)
        print("已连接到MCP服务器")
        
        # 列出可用工具
        print("\n获取可用工具...")
        tools = await client.list_tools()
        print(f"发现 {len(tools)} 个工具")
        
        # 检查Wireshark是否已安装
        print("\n检查Wireshark安装...")
        result = await client.call_tool("wireshark_check_installation")
        await print_response(result)
        
        if not result or not result.get("installed", False):
            print("Wireshark未安装或不可用。请安装Wireshark并确保tshark命令可用。")
            return
        
        # 获取可用接口
        print("\n获取网络接口...")
        result = await client.call_tool("wireshark_get_interfaces")
        await print_response(result)
        
        interfaces = result.get("interfaces", [])
        if not interfaces:
            print("未找到可用的网络接口。")
            return
        
        # 选择第一个接口进行捕获
        selected_interface = interfaces[0]["index"]
        
        # 获取过滤器提示
        print("\n获取过滤器提示...")
        result = await client.call_tool(
            "wireshark_get_prompt",
            {"prompt_id": "wireshark_filters"}
        )
        await print_response(result)
        
        # 捕获数据包
        print(f"\n在接口 {selected_interface} 上捕获数据包 (5秒)...")
        output_file = f"capture_{int(time.time())}.pcap"
        result = await client.call_tool(
            "wireshark_capture_packets", 
            {
                "interface": selected_interface,
                "duration": 5,
                "output_file": output_file
            }
        )
        await print_response(result)
        
        if not result or not result.get("success", False):
            print("捕获失败。")
            return
        
        # 读取捕获文件
        print(f"\n读取捕获文件 {output_file}...")
        result = await client.call_tool(
            "wireshark_read_capture",
            {
                "file_path": output_file,
                "limit": 10
            }
        )
        await print_response(result)
        
        # 分析捕获文件
        print(f"\n分析捕获文件 {output_file}...")
        result = await client.call_tool(
            "wireshark_analyze",
            {
                "file_path": output_file,
                "analysis_type": "protocols"
            }
        )
        await print_response(result)
        
        print("\n示例完成。")
    
    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main()) 