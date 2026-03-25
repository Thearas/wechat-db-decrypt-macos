# macOS 微信数据库解密

提取微信 (WeChat) 数据库密钥，解密 SQLCipher 加密的本地数据库，导出聊天记录。支持 MCP Server，让 AI 直接查询微信数据。

## 快速开始

### 1. 前置条件

- macOS arm64，微信 4.x
- 禁用 SIP：`csrutil disable`
- 安装依赖：`brew install llvm sqlcipher`

### 2. 提取密钥

确保微信已登录并正在运行：

```bash
PYTHONPATH=$(lldb -P) python3 find_key_memscan.py
```

密钥保存到 `wechat_keys.json`。

### 3. 解密数据库

```bash
python3 decrypt_db.py
```

### 4. 导出聊天记录

```bash
# 列出所有会话
python3 export_messages.py

# 导出指定会话（支持模糊匹配联系人名）
python3 export_messages.py -c "卡比"
python3 export_messages.py -c wxid_xxx
python3 export_messages.py -c 12345@chatroom

# 导出最近 N 条
python3 export_messages.py -c "卡比" -n 50

# 搜索关键词
python3 export_messages.py -s "关键词"

# 导出所有会话
python3 export_messages.py --all

# 按日期范围导出（支持个人聊天 + 群聊，可组合使用）
python3 export_messages.py --all --since 2026-03-02
python3 export_messages.py --all --since 2026-03-01 --until 2026-03-31

# 只导出个人聊天和群聊（过滤公众号）
python3 export_messages.py --all --personal

# 组合：导出 3 月 2 日至今的个人聊天，仅保留有消息的会话
python3 export_messages.py --all --personal --since 2026-03-02 -o exported_personal
```

> **注意**：微信将个人消息存储在 `message_N.db`，公众号消息存储在 `biz_message_N.db`。首次运行 `find_key_memscan.py` 时，只有已在微信中打开过的对话对应的数据库密钥会被提取到内存中。若发现导出的个人聊天记录不完整，请在微信中打开更多历史对话后重新运行密钥提取脚本，再重新解密。

### 5. 合并并清理聊天记录

将导出目录中的所有 txt 文件合并为单个文件，同时自动清理图片、语音、视频等消息后附带的二进制乱码：

```bash
# 合并到默认输出文件（<目录名>_merged.txt）
python3 merge_and_clean.py exported_personal

# 指定输出文件名
python3 merge_and_clean.py exported_personal output.txt

# 合并后自动删除原导出目录
python3 merge_and_clean.py exported_personal --clean
python3 merge_and_clean.py exported_personal output.txt --clean
```

### 6. MCP Server（让 AI 直接查询）

安装依赖并注册到 Claude Code：

```bash
pip3 install fastmcp
claude mcp add wechat -- python3 $(pwd)/mcp_server.py
```

注册后 AI 可以直接调用以下能力：

| Tool | 功能 |
|------|------|
| `get_recent_sessions` | 获取最近会话列表 |
| `get_chat_history` | 查看聊天记录（支持模糊匹配） |
| `search_messages` | 跨会话搜索关键词 |
| `get_contacts` | 搜索联系人 |

## Thanks

- [ylytdeng/wechat-decrypt](https://github.com/ylytdeng/wechat-decrypt) — 内存搜索方案参考
