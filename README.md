# ZTE-E8820S-clash_setup
ZTE-E8820S 一键安装clash
 

openwrt-ramips-mt7621-zte_e8820s-squashfs-factory.bin 刷机固件
<img width="3840" height="1953" alt="image" src="https://github.com/user-attachments/assets/9196b999-ff88-4685-9e97-bd055749d48a" />
 
 
### 新增功能

#### 1. `--update` 模式（换节点只需 10 秒）
```cmd
# 只换代理链接，不重装二进制
python clash_setup.py 192.168.1.1 "vless://新uuid@新ip:端口#节点名" 123456 --update
```
只做 3 件事：上传新 `config.yaml` → 重启 clash_meta → 验证 Google

#### 2. `--binary` 参数（手动指定本地二进制）
```cmd
# 用手动下载的二进制，完全不联网
python clash_setup.py 192.168.1.1 "vless://..." 123456 --binary G:\clash_setup\clash_cache\clash_meta_mipsle.bin
```

#### 3. 二进制查找优先级（完整安装模式）
```
1. --binary 指定的本地文件            ← 最高优先级
2. clash_cache/ 目录里的 .bin 缓存    ← 上次下载过就直接用
3. 路由器上 /etc/openclash/core/clash_meta  ← 装过 OpenClash 就复用
4. 路由器上已有 /etc/clash_proxy/clash_meta ← 已安装过本脚本
5. GitHub 下载 → 本地缓存             ← 最后手段
```

#### 4. 完整安装结束时打印更换节点命令
```
  更换节点（快速，10秒）:
    python clash_setup.py 192.168.27.1 "<新的代理URL>" 123456 --update
```

---

### 用法速查

| 场景 | 命令 |
|------|------|
| 首次安装新路由器 | `python clash_setup.py 192.168.1.1 "vless://..." 123456` |
| 换节点（秒完成） | `python clash_setup.py 192.168.1.1 "vless://新..." 123456 --update` |
| 离线安装（自带二进制） | `python clash_setup.py 192.168.1.1 "vless://..." 123456 --binary D:\clash_meta_mipsle` |
| 查帮助 | `python clash_setup.py --help` |

文件在 `G:\clash_setup\clash_setup.py`，同时同步到了 `C:\temp\clash_setup.py`。



`clash_cache/` 目录还不存在——因为之前的完整测试走的是"复用路由器上的 `/etc/openclash/core/clash_meta`"路径，根本没触发本地下载，所以缓存目录从未被创建。

**正式路径应该是：**

```
G:\clash_setup\clash_cache\mihomo-linux-mipsle-softfloat-v1.19.25.bin
```





### 手动下载 mihomo-linux-mipsle-softfloat-v1.19.25.bin
```
https://github.com/MetaCubeX/mihomo/releases/download/v1.19.25/mihomo-linux-mipsle-softfloat-v1.19.25.gz
```
下载后解压（.gz），改名放到 `G:\clash_setup\clash_cache\` 即可。

---
