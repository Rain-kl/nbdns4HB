#!/bin/bash

# 测试 DNS IP 劫持功能
# 使用方法: ./test_hijack.sh

BASE_URL="http://127.0.0.1:8854"

echo "===== DNS IP 劫持功能测试 ====="
echo ""

# 1. 查看当前所有劫持规则
echo "1. 查看当前所有劫持规则:"
curl -s "${BASE_URL}/api/hijack/list" | jq '.'
echo ""

# 2. 添加一个劫持规则 (例如: cloudflare.com -> 1.1.1.1)
echo "2. 添加劫持规则: cloudflare.com -> 1.1.1.1"
curl -s -X POST "${BASE_URL}/api/hijack" \
  -H "Content-Type: application/json" \
  -d '{"domain":"cloudflare.com","ipv4":"1.1.1.1"}' | jq '.'
echo ""

# 3. 添加另一个劫持规则 (例如: www.cloudflare.com -> 1.0.0.1)
echo "3. 添加劫持规则: www.cloudflare.com -> 1.0.0.1"
curl -s -X POST "${BASE_URL}/api/hijack" \
  -H "Content-Type: application/json" \
  -d '{"domain":"www.cloudflare.com","ipv4":"1.0.0.1"}' | jq '.'
echo ""

# 4. 再次查看所有劫持规则
echo "4. 再次查看所有劫持规则:"
curl -s "${BASE_URL}/api/hijack/list" | jq '.'
echo ""

# 5. 测试 DNS 查询 cloudflare.com (应该返回劫持的IP)
echo "5. 测试 DNS 查询 cloudflare.com (应该返回 1.1.1.1):"
dig @127.0.0.1 -p 8853 cloudflare.com A +short
echo ""

# 6. 测试 DNS 查询 www.cloudflare.com (应该返回劫持的IP)
echo "6. 测试 DNS 查询 www.cloudflare.com (应该返回 1.0.0.1):"
dig @127.0.0.1 -p 8853 www.cloudflare.com A +short
echo ""

# 7. 查询 HTTPS 记录 (验证不影响 ECH)
echo "7. 查询 HTTPS 记录 (验证 ECH 不受影响):"
dig @127.0.0.1 -p 8853 cloudflare.com HTTPS +short
echo ""

# 8. 删除一个劫持规则
echo "8. 删除劫持规则: cloudflare.com"
curl -s -X DELETE "${BASE_URL}/api/hijack?domain=cloudflare.com" | jq '.'
echo ""

# 9. 查看删除后的规则列表
echo "9. 查看删除后的规则列表:"
curl -s "${BASE_URL}/api/hijack/list" | jq '.'
echo ""

# 10. 再次测试 cloudflare.com (应该返回真实IP)
echo "10. 再次测试 cloudflare.com (应该返回真实 IP):"
dig @127.0.0.1 -p 8853 cloudflare.com A +short
echo ""

# 11. 清理 - 删除所有测试规则
echo "11. 清理测试数据..."
curl -s -X DELETE "${BASE_URL}/api/hijack?domain=www.cloudflare.com" | jq '.'
echo ""

echo "===== 测试完成 ====="
