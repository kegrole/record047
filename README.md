# safextract

只依赖 Python 标准库的安全解包器，支持 `zip` 与 `tar`（含 `.tar.gz`、
`.tar.bz2`、`.tar.xz` 等压缩 tar）两类归档。所有条目在落盘前都会经过
路径、符号链接与资源限额校验，任何一项不通过都会中止当前归档并回滚，
不会在解包目标里留下半截目录。

## 支持的归档格式

- ZIP：普通文件、目录、Unix 风格符号链接条目；`zipfile` 原生支持的压缩方法。
- TAR：普通文件、目录、符号链接、硬链接；流式读取未压缩或 gzip/bzip2/xz 压缩的 tar。
- 格式通过魔数自动识别，不依赖文件后缀。
- 保留文件内容、权限位与修改时间；设备节点、FIFO 等特殊条目一律拒绝。

## 路径穿越规则

每个条目名在与解包目录拼接前都会先做词法校验，命中任意一条即记录
安全事件并中止当前归档：

- 含 `..` 路径组件的相对路径，例如 `../evil.txt`、`a/../../b`。
- POSIX 绝对路径，例如 `/etc/passwd`。
- Windows 盘符形式，例如 `C:\evil.txt`、`C:/evil.txt`。
- Windows UNC / 反斜杠根路径，例如 `\\share\x`、`\evil.txt`。
- 反斜杠始终被视为路径分隔符，不会因为 POSIX 下它是合法文件名字符而放行。
- 符号链接会同时检查链接路径与解析后的有效目标，绝对目标或指向解包目录之外的相对目标都会被拒绝。

## 限额规则

阈值由 `safextract.limits.Limits` 配置，默认值如下：

| 限额 | 默认值 | 说明 |
| --- | --- | --- |
| `max_total_bytes` | `100 MiB` | 所有普通文件解压后总字节数 |
| `max_single_file_bytes` | `50 MiB` | 单个文件解压后字节数 |
| `max_file_count` | `10000` | 普通文件数量 |
| `max_compression_ratio` | `100.0` | 原始大小 / 压缩大小，超过即中止 |

ZIP 按条目同时记录 `file_size` 与 `compress_size`；TAR 在流式读取时统计
底层压缩流实际消耗的字节，按整个归档聚合计算压缩比。任何限额触发都会
产生 `limit_exceeded` 事件，压缩比事件的原因文本同时包含实际压缩比与
触发阈值两个数字。文件采用分块流式写入，超限立即停止，避免先把整个
解压结果读进内存。

## 权限处理

- 保留归档中的读/写/执行权限位。
- `setuid`（`04000`）与 `setgid`（`02000`）位在落盘前统一屏蔽。
- 条目未提供权限时使用安全默认值：目录 `0755`、普通文件 `0644`。
- 修改时间在文件写入、权限设置后恢复；目录时间按深度从深到浅最后恢复。

## 原子性

1. 在目标目录的同级目录创建临时暂存目录。
2. 所有条目都解到暂存目录；任何安全事件或解压异常都会删除暂存目录并返回 `aborted=true`。
3. 全部成功后用 `os.replace` 把暂存目录原子替换为目标目录；目标已存在时先改名备份，替换成功再删除备份。
4. 因此中途失败既不会留下半截解包结果，也不会在目标父目录留下新增文件。

## 报告字段

`--out` 写出 JSON 数组，每个归档对应一条记录：

| 字段 | 含义 |
| --- | --- |
| `archive` | 归档路径 |
| `events` | 安全事件列表，按触发顺序记录 |
| `written_files` | 已成功写入的普通文件数量（中止时不会原子替换到目标） |
| `aborted` | 是否因安全事件或错误中止 |

每个事件对象固定包含三个字段：

| 字段 | 含义 |
| --- | --- |
| `type` | 事件类型，如 `path_traversal`、`absolute_path`、`windows_path`、`unsafe_symlink`、`limit_exceeded` |
| `entry` | 被拒绝的条目名 |
| `reason` | 中文原因说明，限额事件包含实际值与阈值 |

## 使用方式

批量解包目录中的归档，每个归档在 `--dest` 下生成一个同名子目录：

```bash
python -m safextract.cli \
  --archives demo/archives \
  --dest out/unpacked \
  --out out/report.json
```

stdout 打印一行摘要，例如：

```text
归档数: 6，事件数: 5，拒绝条目数: 5
```

阈值也可以通过 CLI 覆盖：`--max-total-bytes`、`--max-single-file-bytes`、
`--max-file-count`、`--max-compression-ratio`。

作为库调用：

```python
from safextract import Limits, extract_archive

result = extract_archive("input.zip", "out/input", Limits(max_file_count=100))
print(result.to_row())
```

## 重新生成 demo 与运行测试

```bash
python demo/build_demo_archives.py
cd tests && python -m unittest test_safextract -v
```

测试夹具全部在 `tests/test_safextract.py` 内用标准库现场构造，覆盖正常
归档、相对路径穿越、绝对路径、越界符号链接、高压缩比、Windows 盘符
路径六类场景，并断言解包前后目标父目录的文件集合保持一致。
