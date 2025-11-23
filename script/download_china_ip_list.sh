#!/bin/zsh
# 自动下载 china_ip_list.txt 到 data 目录

set -e

DATA_DIR="$(dirname "$0")/../data"
FILE_URL="https://github.com/17mon/china_ip_list/raw/master/china_ip_list.txt"
TARGET_FILE="$DATA_DIR/china_ip_list.txt"

mkdir -p "$DATA_DIR"
echo "Downloading $FILE_URL to $TARGET_FILE ..."
curl -L "$FILE_URL" -o "$TARGET_FILE"
echo "Download complete."
