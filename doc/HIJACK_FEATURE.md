# DNS IP 劫持功能说明

## 功能概述

DNS IP 劫持功能允许你为特定域名指定优选的 IPv4 地址。这在使用 Cloudflare 等服务时特别有用，可以将解析结果替换为访问速度更快的 IP 地址。

### 特性
- ✅ 只修改 A 记录的 IP 地址
- ✅ 保留所有其他 DNS 记录（包括 HTTPS/ECH 记录）
- ✅ 持久化存储劫持规则（自动保存到 `data/hijack_rules.json`）
- ✅ 支持动态添加、删除和查询规则
- ✅ 域名自动规范化（不区分大小写，自动处理尾部点号）

## API 接口

### 1. 添加/更新劫持规则

**端点:** `POST /api/hijack`

**请求体:**
```json
{
  "domain": "cloudflare.com",
  "ipv4": "1.1.1.1"
}
```

**示例:**
```bash
curl -X POST http://127.0.0.1:8854/api/hijack \
  -H "Content-Type: application/json" \
  -d '{"domain":"cloudflare.com","ipv4":"1.1.1.1"}'
```

**响应:**
```json
{
  "success": true,
  "message": "Hijack rule added successfully"
}
```

### 2. 删除劫持规则

**端点:** `DELETE /api/hijack?domain={domain}`

**示例:**
```bash
curl -X DELETE "http://127.0.0.1:8854/api/hijack?domain=cloudflare.com"
```

**响应:**
```json
{
  "success": true,
  "message": "Hijack rule removed successfully"
}
```

### 3. 查询所有劫持规则

**端点:** `GET /api/hijack/list`

**示例:**
```bash
curl http://127.0.0.1:8854/api/hijack/list
```

**响应:**
```json
[
  {
    "domain": "cloudflare.com",
    "ipv4": "1.1.1.1"
  },
  {
    "domain": "www.cloudflare.com",
    "ipv4": "1.0.0.1"
  }
]
```

## 使用场景

### 场景 1: Cloudflare CDN 优选 IP

当你发现 Cloudflare 解析的 IP 访问速度较慢时，可以使用 IP 测速工具找到最优 IP，然后添加劫持规则：

```bash
# 添加优选 IP
curl -X POST http://127.0.0.1:8854/api/hijack \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","ipv4":"104.16.1.2"}'
```

### 场景 2: 自定义域名解析

为特定域名指定固定 IP 地址：

```bash
# 将域名指向特定服务器
curl -X POST http://127.0.0.1:8854/api/hijack \
  -H "Content-Type: application/json" \
  -d '{"domain":"myapp.local","ipv4":"192.168.1.100"}'
```

## 测试脚本

项目提供了一个完整的测试脚本 `script/test_hijack.sh`，可以测试所有功能：

```bash
# 运行测试
./script/test_hijack.sh
```

测试脚本会执行以下操作：
1. 查看当前所有劫持规则
2. 添加劫持规则
3. 测试 DNS 查询是否返回劫持的 IP
4. 验证 HTTPS/ECH 记录不受影响
5. 删除劫持规则
6. 验证恢复正常解析

## 技术实现

### 劫持流程

```
DNS 查询请求
    ↓
从上游 DNS 获取响应
    ↓
检查是否有劫持规则
    ↓
[如果有] 只替换 A 记录的 IP
    ↓
保留其他所有记录 (AAAA, HTTPS, CNAME 等)
    ↓
返回修改后的响应
```

### 核心特性

1. **只修改 A 记录**: 只替换 IPv4 地址记录，其他记录类型完全不受影响
2. **ECH 保护**: HTTPS 记录（包含 ECH 配置）保持不变
3. **域名规范化**: 自动转换为小写并去除尾部点号，确保匹配准确
4. **持久化存储**: 规则自动保存到 `data/hijack_rules.json`
5. **线程安全**: 使用读写锁保护并发访问

### 文件结构

```
internal/model/hijack.go          # 劫持管理器核心实现
internal/handler/handler.go       # DNS 响应处理集成
internal/web/handler.go           # Web API 端点
data/hijack_rules.json            # 持久化存储文件
```

## 注意事项

1. **IP 格式验证**: 添加规则时会验证 IPv4 地址格式，无效地址会被拒绝
2. **域名格式**: 支持任何合法的域名格式，会自动规范化
3. **缓存影响**: 劫持发生在缓存之后，因此缓存的响应也会被劫持
4. **只支持 IPv4**: 当前版本只支持劫持 A 记录，不支持 AAAA (IPv6) 记录

## 故障排除

### 规则不生效？

1. 检查规则是否已添加：
   ```bash
   curl http://127.0.0.1:8854/api/hijack/list
   ```

2. 检查日志输出：
   ```
   [日志] Hijacked DNS response for example.com: 1.2.3.4 -> 1.1.1.1
   ```

3. 清除 DNS 缓存后重试

### 规则丢失？

- 规则会自动持久化到 `data/hijack_rules.json`
- 检查文件权限确保可以写入
- 查看日志是否有保存失败的错误

## 示例集成

### 在脚本中使用

```bash
#!/bin/bash

# 定义 API 地址
API_BASE="http://127.0.0.1:8854"

# 添加多个优选 IP
declare -A OPTIMIZED_IPS=(
    ["cdn1.example.com"]="104.16.1.1"
    ["cdn2.example.com"]="104.16.1.2"
    ["api.example.com"]="172.67.1.1"
)

for domain in "${!OPTIMIZED_IPS[@]}"; do
    ipv4="${OPTIMIZED_IPS[$domain]}"
    echo "Adding hijack rule: $domain -> $ipv4"
    curl -s -X POST "$API_BASE/api/hijack" \
        -H "Content-Type: application/json" \
        -d "{\"domain\":\"$domain\",\"ipv4\":\"$ipv4\"}" | jq '.'
done
```

### 配合 IP 测速工具

1. 使用 CloudflareSpeedTest 等工具找到最优 IP
2. 将测速结果通过 API 添加到劫持规则
3. 自动化定期更新优选 IP

```bash
# 假设测速结果保存在 best_ips.txt
# 格式: domain,ipv4
while IFS=',' read -r domain ipv4; do
    curl -s -X POST http://127.0.0.1:8854/api/hijack \
        -H "Content-Type: application/json" \
        -d "{\"domain\":\"$domain\",\"ipv4\":\"$ipv4\"}"
done < best_ips.txt
```
