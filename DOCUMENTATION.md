# Wireshark MCP服务器文档

## 概述

Wireshark MCP服务器是一个基于Model Context Protocol (MCP)的服务，允许大型语言模型(LLM)直接与Wireshark交互。该服务器提供了一系列工具，使LLM能够执行Wireshark相关任务，如捕获网络数据包、读取捕获文件、分析网络数据等。

## 架构设计

该服务器基于Python实现，使用以下主要组件：

1. **MCP服务器框架**：使用`mcp>=1.4.1`实现MCP协议，通过FastMCP实现服务器功能
2. **Wireshark接口**：通过`pyshark`库和命令行工具`tshark`与Wireshark交互
3. **提示存储**：提供常用Wireshark过滤器和命令的提示

## 功能列表

### 1. 系统功能

- 检查Wireshark安装状态
- 获取可用网络接口列表

### 2. 数据捕获功能

- 捕获网络数据包
- 读取已捕获的数据包文件
- 应用过滤器分析数据包

### 3. 分析功能

- 分析会话和端点
- 协议分布统计
- HTTP/DNS等特定协议分析

### 4. 提示功能

- 获取常用Wireshark过滤器提示
- 获取网络分析方法提示
- 获取常用Wireshark命令提示

## API参考

### 1. `wireshark_check_installation`

检查Wireshark是否已安装。

**参数**：无

**返回值**：
```json
{
  "installed": true|false
}
```

### 2. `wireshark_get_interfaces`

获取可用的网络接口列表。

**参数**：无

**返回值**：
```json
{
  "interfaces": [
    {
      "index": "1",
      "interface": "en0 (Wi-Fi)"
    },
    ...
  ]
}
```

### 3. `wireshark_capture_packets`

捕获网络数据包。

**参数**：
- `interface`: 要捕获的网络接口
- `duration`: 捕获持续时间（秒），默认10秒
- `filter_str`: 可选的捕获过滤器
- `output_file`: 可选的输出文件路径

**返回值**：
```json
{
  "success": true|false,
  "stdout": "输出内容",
  "stderr": "错误内容",
  "output_file": "捕获文件路径"
}
```

### 4. `wireshark_read_capture`

读取捕获的数据包文件。

**参数**：
- `file_path`: 捕获文件路径
- `filter_str`: 可选的显示过滤器
- `limit`: 最大读取的数据包数量，默认100

**返回值**：
```json
{
  "success": true|false,
  "stdout": "输出内容",
  "stderr": "错误内容"
}
```

### 5. `wireshark_analyze`

分析捕获文件并提供统计数据。

**参数**：
- `file_path`: 捕获文件路径
- `analysis_type`: 分析类型，可选值包括：
  - `conversations`: 会话统计
  - `endpoints`: 端点统计
  - `protocols`: 协议统计
  - `http`: HTTP分析
  - `dns`: DNS分析

**返回值**：
```json
{
  "success": true|false,
  "stdout": "输出内容",
  "stderr": "错误内容"
}
```

### 6. `wireshark_get_prompts`

获取所有Wireshark相关提示。

**参数**：无

**返回值**：
```json
{
  "prompts": [
    {
      "id": "提示ID",
      "text": "提示内容"
    },
    ...
  ]
}
```

### 7. `wireshark_get_prompt`

获取特定的Wireshark提示。

**参数**：
- `prompt_id`: 提示ID

**返回值**：
```json
{
  "success": true|false,
  "prompt": {
    "id": "提示ID",
    "text": "提示内容"
  }
}
```

## 使用方式

### 启动服务器

```bash
python wireshark_mcp_server.py
```

服务器默认在 http://127.0.0.1:3001 启动，使用SSE传输协议。

### MCP客户端集成

在MCP客户端中，可以通过以下方式连接服务器：

```python
from mcp.client import ClientSession
from mcp.client.sse import sse_client

async with sse_client("http://127.0.0.1:3001") as (read, write):
    async with ClientSession(read, write) as session:
        # 初始化连接
        await session.initialize()
        
        # 列出可用工具
        tools = await session.list_tools()
        
        # 调用工具
        result = await session.call_tool(
            "wireshark_capture_packets", 
            {
                "interface": "1",
                "duration": 5,
                "output_file": "capture.pcap"
            }
        )
```

### 示例客户端

项目包含一个示例客户端，展示如何使用该MCP服务器：

```bash
python example_client.py
```

## 常见问题

### 1. 找不到tshark命令

确保已安装Wireshark，并且tshark命令在系统PATH中。

### 2. 没有足够权限捕获数据包

在Linux/macOS上，可能需要使用sudo运行或给予适当的权限：

```bash
sudo python wireshark_mcp_server.py
```

或

```bash
sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/dumpcap
```

### 3. 过滤器语法错误

Wireshark过滤器需要遵循特定语法。请参考"wireshark_filters"提示获取正确的语法示例。

### 4. MCP连接失败

确保MCP服务器正在运行，并且客户端使用了正确的URL：http://127.0.0.1:3001 