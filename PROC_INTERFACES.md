# /proc 控制接口

本模块（`susfs_guard_lkm`）的全部 `/proc` 节点。状态与`reboot(2)`  supercall 同步。

**注意**

写命令**成功返回 `len`，失败返回负 errno**


## 节点一览

| 节点 | 作用 | 写命令 |
|---|---|---|
| [`/proc/susfs_kstat`](#procsusfs_kstat) | `stat()`/`maps` 结果伪装 | `add_sus_kstat` / `add_sus_kstat_statically` / `update_sus_kstat` / `update_sus_kstat_full_clone` / `del` / `clear` |
| [`/proc/susfs_open_redirect`](#procsusfs_open_redirect) | `open()` 重定向（含反向面：`d_path`/`statfs`/`maps`/`fdinfo`） | `add_open_redirect` / `del` / `clear` |
| [`/proc/susfs_enable_log`](#procsusfs_enable_log) | 运行期日志开关 | `0` / `1` |
| [`/proc/susfs_avc_spoof`](#procsusfs_avc_spoof) | 隐藏 SELinux AVC 审计日志 | `0` / `1` |
| [`/proc/susfs_hide_modules`](#procsusfs_hide_modules) | 按名字把**其它内核模块**从 `/proc/modules` 去掉 | `add <名字>` / `del <名字>` / `set <名字>…` / `clear` |
| [`/proc/susfs_hide_mounts`](#procsusfs_hide_mounts) | 哪些挂载算"我们的"（决定隐藏的挂载集合） | `add <前缀>` / `del <前缀>` / `set <前缀>…` / `reset` / `clear` |
| [`/proc/susfs_path`](#procsusfs_path) | sus_path 规则表——**`cat` 就是清单** | `add <路径>` / `del <路径>` / `clear` |

节点只在 sus_path 的 LSM 层装上时才创建（`expose_proc=1` 且 LSM 生效）。
---

## /proc/susfs_kstat

登记一个路径，让 app 看到的 `stat()`/`statx()`/`maps` 里的 inode 与时间戳变成登记时的值（`add_sus_kstat` 用"登记那一刻的真实值"作为伪装值）。

**读**：每条规则一行，外加两组计数器。

```
/data/local/tmp/procdoc/target ino=981881 dev=65099 flags=0xff3 [ino=981881 dev=65099 nlink=1 size=2 atime=1789400211.918607439 mtime=1789400211.930607439 ctime=1789400211.946607439 blocks=8 blksize=4096]
maps: armed=1 hits=0 rewrites=0
vfs_getattr fallback: gattr_hits=6 gattr_spoofs=0
```

外层是登记目标，方括号里是伪装值。`maps:` 是 `maps` 行改写探针；`vfs_getattr fallback:` 是"内核内部调用者"那条回退路径的命中数。

**写**：

```sh
echo "add_sus_kstat /data/local/tmp/x"                       > /proc/susfs_kstat
echo "add_sus_kstat_statically /data/local/tmp/x 1 2 3 4 5 6 7 8 9 10 11 12" > /proc/susfs_kstat
echo "update_sus_kstat /data/local/tmp/x"                    > /proc/susfs_kstat
echo "update_sus_kstat_full_clone /data/local/tmp/x"         > /proc/susfs_kstat
echo "del /data/local/tmp/x"                                 > /proc/susfs_kstat
echo clear                                                   > /proc/susfs_kstat
```

`add_sus_kstat_statically` 后面跟 12 个十进制数：`ino dev nlink size atime_sec atime_nsec mtime_sec mtime_nsec ctime_sec ctime_nsec blocks blksize`。

---

## /proc/susfs_open_redirect

把 `open()` 重定向到另一个文件。

**读**：每条规则一行，空表时 `(empty)`；

```
(empty)
hooks: open=0 dpath=0 statfs=0 maps=0 fdinfo=0 | rev hits: dpath=0 statfs=0 maps=0/0/0 fdinfo=0/0 | su_sid=2907
```

**写**：

```sh
echo "add_open_redirect <目标> <被重定向到的文件> <uid_scheme>" > /proc/susfs_open_redirect
echo "del <目标>"                                               > /proc/susfs_open_redirect
echo clear                                                      > /proc/susfs_open_redirect
```

`uid_scheme` 取值 `0..4` **注意**这个功能并未完全实习 ，3,4不可用。

---

## /proc/susfs_enable_log

运行期日志开关（默认开）。

---

## /proc/susfs_avc_spoof

隐藏 `avc: denied` 审计日志里的 KernelSU 痕迹。打开时会解析 su 与 priv_app 的 sid。

```
0 (su_sid=2907 priv_app_sid=2504 enter=0 hits=0)
```

---

## /proc/susfs_hide_modules

维护一份**模块列表**，把列表里的名字从 `/proc/modules` 的那一行去掉（包括root）、把 `/sys/module/<名字>` 从非 root 调用者眼前隐掉、并过滤 `/proc/kallsyms` 里 `module_name` 匹配的行。

**读**：

```
hide_modules: 1/16 name(s), /sys/module rules=1 (failed=0), /proc/modules lines removed=0, kallsyms lines removed=0
names: susfs_guard_lkm
```

计数分别是：`/sys/module/<名字>` 规则装了 `rules` 条、失败 `failed` 次

**写**：

```sh
echo "add kernelsu"            > /proc/susfs_hide_modules   # 加一个名字
echo "del kernelsu"            > /proc/susfs_hide_modules   # 去掉一个（未列出 -> -ENOENT）
echo "set kernelsu frida"      > /proc/susfs_hide_modules   # 整份替换
echo clear                     > /proc/susfs_hide_modules   # 一个都不隐藏（调试模式，lsmod 会重新列出本模块）
```

已知边界：只过滤"模块自己那一行"。别的模块若**依赖**它，`/proc/modules` 的 used-by 列里仍会出现该名字（实测隐藏 `explorer` 后仍有 `camera 10440704 35 explorer, Live …`）。

---

## /proc/susfs_hide_mounts

决定挂载隐藏（`ksu_susfs hide_sus_mnts_for_non_su_procs 1`）实际会隐藏哪些行；容器这类场景要自己加：

```sh
cat /proc/susfs_hide_mounts
# mount prefixes: 2/8, rescans=1, recorded=0, hidden_by_identity=0, learned_ids=0
# prefixes: /data/adb/ /data/local/tmp/

# 写命令
echo 'add /data/local/tmp/'                 > /proc/susfs_hide_mounts
echo 'del /data/local/tmp/'                 > /proc/susfs_hide_mounts
echo 'set /data/adb/ /data/local/tmp/'      > /proc/susfs_hide_mounts
echo 'reset'                                > /proc/susfs_hide_mounts   # 回到默认
echo 'clear'                                > /proc/susfs_hide_mounts   # 空前缀表
```

---

## /proc/susfs_path

sus_path 的规则表，写是命令：

```sh
# root：读清单
cat /proc/susfs_path
# hide_from_apps=1  enoent: getattr=5 perm=0 nameop=0 meta=0
# dirent: rewrite-fail=0  all-hidden=0  pending=0  calls(l64=2 compat=0)
# identity: 3 hit(s) where the inode pointer did not match and (dev,ino) or (fs type,ino) answered instead
# path=/proc/susfs_kstat  dev=20 ino=4026535246 name=susfs_kstat  [ours: clear/del refuse it]
# path=/data/adb/xxx      dev=253 ino=1234567 name=xxx
# ...

# 命令
echo "add /data/adb/xxx" > /proc/susfs_path     # 普通规则（等价于 ksu_susfs add_sus_path）
echo "del /data/adb/xxx" > /proc/susfs_path     # 撤销，并恢复被放宽的权限
echo clear               > /proc/susfs_path     # 清掉所有**普通**规则
```

---

**残留风险（已知边界）**：第 2 级对**所有**规则生效，所以如果某条规则持有的 inode 真的被解除 hash、而它的号又被同一超级块里的另一个文件拿走，那条规则会连带隐藏那个文件。

## 隐藏 ≠ 访问控制（用之前必须知道）

本模块让**路径名**不可见（`ENOENT`），但不拦不经过路径名的通道：

- 已经打开的 fd（`/proc/<pid>/fd/N`）、注册规则**之前**已经持有的引用；
- 注册**之前**建立的硬链接 / bind mount；
- 按 `(dev, ino)` 而不是按路径工作的接口（`/proc/<pid>/map_files`、`maps`/`smaps` 的 inode 面）。

`add_open_redirect` 需要**三个**参数（工具自己的 usage 少印了第三个）：

```sh
ksu_susfs add_open_redirect <target> <redirected> <uid_scheme>   # uid_scheme: 0..4
```
