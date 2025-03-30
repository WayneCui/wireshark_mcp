# Wireshark MCP服务器

这是一个连接Wireshark的MCP (Model Context Protocol) 服务器，提供以下功能：

- 连接本地Wireshark实例
- 提供运行Wireshark命令的工具
- 包含常见数据过滤任务的提示

## 安装

1. 创建并激活Python虚拟环境（推荐）：
```bash
python -m venv venv
source venv/bin/activate  # 在Windows上使用: venv\Scripts\activate
```

2. 安装依赖：
```bash
pip install -r requirements.txt
```

3. 确保安装了Wireshark并且tshark命令可用：
```bash
tshark --version
```

## 使用方法

### 启动服务器

```bash
python wireshark_mcp_server.py
```

服务器将启动一个SSE应用，监听在`http://127.0.0.1:3001`，可以通过支持MCP的LLM客户端连接。

### 测试客户端

提供了一个简单的测试客户端，可以用来验证服务器功能：

```bash
python example_client.py
```

### 可用工具

服务器提供以下工具：

1. `wireshark_check_installation` - 检查Wireshark是否已安装
2. `wireshark_get_interfaces` - 获取可用网络接口列表
3. `wireshark_capture_packets` - 捕获网络数据包
4. `wireshark_read_capture` - 读取捕获文件
5. `wireshark_analyze` - 分析捕获文件并提供统计数据
6. `wireshark_get_prompts` - 获取所有提示
7. `wireshark_get_prompt` - 获取特定提示

详细的API文档请参考`DOCUMENTATION.md`文件。

## 所需依赖

- Wireshark必须已安装在系统上
- Python 3.10+

## 常见问题

### 缺少权限

在Linux/macOS上，可能需要以root权限运行才能捕获数据包：

```bash
sudo python wireshark_mcp_server.py
```

或者给予dumpcap命令适当的权限：

```bash
sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/dumpcap
```

### tshark命令未找到

确保Wireshark已正确安装，并且tshark命令在系统PATH中。

### 服务器启动错误

如果看到错误信息提示找不到某些模块，可能是依赖安装不完整，请确保正确安装了所有依赖：

```bash
pip install -r requirements.txt
``` 