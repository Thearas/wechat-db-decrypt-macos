#!/usr/bin/env python3
"""
合并导出的聊天记录 txt 文件并清理乱码。

用法：
    python3 merge_and_clean.py <导出目录> [输出文件] [--clean]

示例：
    python3 merge_and_clean.py exported_personal
    python3 merge_and_clean.py exported_personal merged.txt
    python3 merge_and_clean.py exported_personal --clean
    python3 merge_and_clean.py exported_personal merged.txt --clean

选项：
    --clean    合并完成后删除原导出目录
"""

import os
import re
import shutil
import sys

TIMESTAMP_RE = re.compile(r'^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]')


def merge(src_dir, out_file):
    files = sorted(f for f in os.listdir(src_dir) if f.endswith('.txt'))
    if not files:
        print(f"[-] 目录 {src_dir} 中没有找到 txt 文件")
        sys.exit(1)

    print(f"[*] 合并 {len(files)} 个文件...")
    with open(out_file, 'wb') as out:
        for fname in files:
            with open(os.path.join(src_dir, fname), 'rb') as f:
                out.write(f.read())
            out.write(b'\n' + b'=' * 80 + b'\n\n')

    print(f"[*] 已合并到 {out_file}")


def clean_image_garbage(content: bytes) -> tuple[bytes, int]:
    """清理 [image]/[voice]/[video]/[emoji]/[type:xxx] 等标签后的二进制乱码。"""
    # 先处理 "[tag] (乱码)" 有括号形式
    cleaned, n1 = re.subn(rb'\[(?!\d{4}-\d{2}-\d{2})([^\]]+)\] \([^\n]*\)', rb'[\1]', content)
    # 再处理 "[image]乱码到行尾" 无括号形式（[image] 后仍有非换行内容）
    cleaned, n2 = re.subn(rb'\[image\][^\n]+', b'[image]', cleaned)
    return cleaned, n1 + n2


def clean_garbage_lines(content: str) -> tuple[str, int]:
    """删除含 Unicode 替换字符（乱码）的整条消息块。"""
    lines = content.split('\n')
    output = []
    i = 0
    removed = 0

    while i < len(lines):
        line = lines[i]

        # 保留真正的注释行（# 开头加空格）、纯等号分隔线、空行
        is_comment = line.startswith('# ')
        is_separator = line.startswith('=') and all(c == '=' for c in line.strip())
        if is_comment or is_separator or line.strip() == '':
            output.append(line)
            i += 1
            continue

        # 消息块：以时间戳开头，收集到下一条消息/注释/分隔线为止
        if TIMESTAMP_RE.match(line):
            block = [line]
            j = i + 1
            while j < len(lines):
                nxt = lines[j]
                if (TIMESTAMP_RE.match(nxt) or
                        nxt.startswith('# ') or
                        (nxt.startswith('=') and all(c == '=' for c in nxt.strip()))):
                    break
                block.append(nxt)
                j += 1

            block_text = '\n'.join(block)
            if '\ufffd' in block_text:
                removed += 1
            else:
                output.append(block_text)
            i = j
            continue

        # 其他孤立行（不以时间戳开头）
        if '\ufffd' in line:
            removed += 1
        else:
            output.append(line)
        i += 1

    return '\n'.join(output), removed


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(1)

    src_dir = args[0]
    if not os.path.isdir(src_dir):
        print(f"[-] 目录不存在：{src_dir}")
        sys.exit(1)

    do_clean = '--clean' in args
    positional = [a for a in args[1:] if not a.startswith('--')]
    out_file = positional[0] if positional else src_dir.rstrip('/') + '_merged.txt'

    # 步骤 1：合并
    merge(src_dir, out_file)

    # 步骤 2：清理标签后的二进制乱码
    with open(out_file, 'rb') as f:
        content = f.read()

    cleaned_bytes, n_tag = clean_image_garbage(content)

    with open(out_file, 'wb') as f:
        f.write(cleaned_bytes)

    print(f"[*] 清理标签乱码：{n_tag} 处")

    # 步骤 3：清理含替换字符的消息块
    with open(out_file, 'r', encoding='utf-8', errors='replace') as f:
        text = f.read()

    cleaned_text, n_msg = clean_garbage_lines(text)

    with open(out_file, 'w', encoding='utf-8') as f:
        f.write(cleaned_text)

    print(f"[*] 清理乱码消息块：{n_msg} 条")

    if do_clean:
        shutil.rmtree(src_dir)
        print(f"[*] 已删除原目录：{src_dir}")

    print(f"[✓] 完成：{out_file}")


if __name__ == '__main__':
    main()
