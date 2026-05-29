#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, io
# 强制 stdout/stderr 使用 UTF-8，避免 Windows GBK 报错
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
else:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

"""
clash_setup.py — OpenWrt 路由器一键翻墙配置脚本
=================================================
无需 OpenClash / LuCI，直接安装 Clash Meta 二进制 + 透明代理
支持协议：VLESS、Trojan、VMess

用法:
  # 完整安装（首次）
  python clash_setup.py <路由器IP> "<代理URL>" [root密码]

  # 仅更新节点（已安装过，只换代理链接，10秒完成）
  python clash_setup.py <路由器IP> "<代理URL>" [root密码] --update

  # 指定本地二进制文件（不联网下载）
  python clash_setup.py <路由器IP> "<代理URL>" [root密码] --binary C:\\path\\clash_meta

示例:
  python clash_setup.py 192.168.1.1 "vless://uuid@host:port?..." 123456
  python clash_setup.py 192.168.27.1 "trojan://pass@host:port#name" 123456 --update
  python clash_setup.py 192.168.1.1 "vless://..." 123456 --binary G:\\clash_setup\\clash_cache\\clash_meta_mipsle.bin

二进制查找优先级（完整安装模式）:
  1. --binary 指定的本地文件
  2. 本地缓存 clash_cache/ 目录（上次下载的）
  3. 路由器上已有的 /etc/openclash/core/clash_meta（OpenClash装过）
  4. 路由器上已有的 /etc/clash_proxy/clash_meta（已安装过本脚本）
  5. 从 GitHub 下载（需要网络）→ 自动缓存到 clash_cache/
"""

import sys, os, re, gzip, io, time, json, argparse
import urllib.parse, urllib.request
import warnings
warnings.filterwarnings("ignore")

try:
    import paramiko
except ImportError:
    print("请先安装 paramiko: pip install paramiko")
    sys.exit(1)

# ============================================================
# 配置参数
# ============================================================
CLASH_VERSION   = "v1.19.25"
INSTALL_DIR     = "/etc/clash_proxy"
CLASH_BIN       = f"{INSTALL_DIR}/clash_meta"
CLASH_CFG       = f"{INSTALL_DIR}/config.yaml"
CLASH_MMDB      = f"{INSTALL_DIR}/Country.mmdb"
CLASH_LOG       = "/tmp/clash_proxy.log"
CLASH_PID       = "/tmp/clash_proxy.pid"
REDIR_PORT      = 7892
HTTP_PORT       = 7890
SOCKS_PORT      = 7891
API_PORT        = 9090

GITHUB_BASE     = "https://github.com/MetaCubeX/mihomo/releases/download"
MMDB_URL        = "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/country.mmdb"
MMDB_FALLBACK   = "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb"

# 缓存目录：脚本同级的 clash_cache/
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "clash_cache")

# ============================================================
# URL 解析
# ============================================================
def parse_url(url):
    url = url.strip()
    if url.startswith("vless://"):
        return _parse_vless(url)
    elif url.startswith("trojan://"):
        return _parse_trojan(url)
    elif url.startswith("vmess://"):
        return _parse_vmess(url)
    else:
        raise ValueError("不支持的协议，请使用 VLESS / Trojan / VMess URL")

def _parse_params(params_str):
    params = {}
    for kv in (params_str or "").split('&'):
        if '=' in kv:
            k, v = kv.split('=', 1)
            params[k.strip()] = urllib.parse.unquote(v.strip())
    return params

def _parse_vless(url):
    m = re.match(r'vless://([^@]+)@([^:/?#]+):(\d+)\??([^#]*)#?(.*)', url)
    if not m:
        raise ValueError("VLESS URL 格式错误")
    uuid, host, port, params_str, name = m.groups()
    name = urllib.parse.unquote(name).strip() or f"vless-{host}"
    params = _parse_params(params_str)

    security = params.get('security', 'none').lower()
    net      = params.get('type', 'tcp').lower()
    sni      = params.get('sni', params.get('peer', params.get('host', '')))

    proxy = {
        'name': name, 'type': 'vless',
        'server': host, 'port': int(port),
        'uuid': uuid,
        'network': net,
        'udp': True,
        'tls': security == 'tls',
        'skip-cert-verify': True,
    }
    if sni and security == 'tls':
        proxy['servername'] = sni

    if net == 'ws':
        ws = {}
        if params.get('path'):  ws['path'] = params['path']
        h = params.get('host', '')
        if h: ws['headers'] = {'Host': h}
        if ws: proxy['ws-opts'] = ws
    elif net == 'grpc':
        svc = params.get('serviceName', params.get('service-name', ''))
        if svc: proxy['grpc-opts'] = {'grpc-service-name': svc}

    return proxy

def _parse_trojan(url):
    m = re.match(r'trojan://([^@]+)@([^:/?#]+):(\d+)\??([^#]*)#?(.*)', url)
    if not m:
        raise ValueError("Trojan URL 格式错误")
    password, host, port, params_str, name = m.groups()
    name = urllib.parse.unquote(name).strip() or f"trojan-{host}"
    params = _parse_params(params_str)
    net = params.get('type', 'tcp').lower()

    proxy = {
        'name': name, 'type': 'trojan',
        'server': host, 'port': int(port),
        'password': password,
        'network': net,
        'udp': True,
        'skip-cert-verify': True,
    }
    sni = params.get('sni', params.get('peer', ''))
    if sni: proxy['sni'] = sni

    if net == 'ws':
        ws = {}
        if params.get('path'):  ws['path'] = params['path']
        h = params.get('host', '')
        if h: ws['headers'] = {'Host': h}
        if ws: proxy['ws-opts'] = ws

    return proxy

def _parse_vmess(url):
    import base64
    b64 = url[8:]
    b64 += '=' * (4 - len(b64) % 4)
    try:
        data = json.loads(base64.b64decode(b64).decode('utf-8'))
    except Exception as e:
        raise ValueError(f"VMess Base64 解析失败: {e}")

    net = data.get('net', 'tcp')
    proxy = {
        'name': data.get('ps', f"vmess-{data.get('add','')}"),
        'type': 'vmess',
        'server': data.get('add', ''),
        'port': int(data.get('port', 443)),
        'uuid': data.get('id', ''),
        'alterId': int(data.get('aid', 0)),
        'cipher': data.get('scy', 'auto'),
        'network': net,
        'tls': data.get('tls', '') == 'tls',
        'skip-cert-verify': True,
        'udp': True,
    }
    if proxy['tls'] and data.get('sni'):
        proxy['servername'] = data['sni']
    if net == 'ws':
        ws = {}
        if data.get('path'): ws['path'] = data['path']
        if data.get('host'): ws['headers'] = {'Host': data['host']}
        if ws: proxy['ws-opts'] = ws

    return proxy

# ============================================================
# 配置文件生成
# ============================================================
def _proxy_to_yaml(p, indent=2):
    sp  = ' ' * indent
    sp2 = ' ' * (indent + 2)
    lines = [f"{sp}- name: \"{p['name']}\""]
    skip = {'name', 'ws-opts', 'grpc-opts', 'headers'}
    for k, v in p.items():
        if k in skip: continue
        if isinstance(v, bool):
            lines.append(f"{sp2}{k}: {'true' if v else 'false'}")
        elif isinstance(v, (int, float)):
            lines.append(f"{sp2}{k}: {v}")
        else:
            lines.append(f"{sp2}{k}: {v}")
    for k in ('ws-opts', 'grpc-opts'):
        if k in p:
            lines.append(f"{sp2}{k}:")
            for dk, dv in p[k].items():
                if isinstance(dv, dict):
                    lines.append(f"{sp2}  {dk}:")
                    for ddk, ddv in dv.items():
                        lines.append(f"{sp2}    {ddk}: {ddv}")
                else:
                    lines.append(f"{sp2}  {dk}: {dv}")
    return '\n'.join(lines)

def gen_config(proxy, lan_cidr):
    pname = proxy['name']
    return f"""\
port: {HTTP_PORT}
socks-port: {SOCKS_PORT}
redir-port: {REDIR_PORT}
allow-lan: true
mode: rule
log-level: info
external-controller: 0.0.0.0:{API_PORT}
secret: ''

dns:
  enable: true
  enhanced-mode: redir-host
  nameserver:
    - 114.114.114.114
    - 223.5.5.5
  fallback:
    - 8.8.8.8
    - 1.1.1.1
  fallback-filter:
    geoip: true
    geoip-code: CN

proxies:
{_proxy_to_yaml(proxy)}

proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - "{pname}"
      - DIRECT

rules:
  - GEOIP,PRIVATE,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
"""

def gen_init(lan_cidr):
    return f"""\
#!/bin/sh /etc/rc.common
# Clash Meta 透明代理 — 一键安装版
START=99
STOP=10

BIN="{CLASH_BIN}"
DIR="{INSTALL_DIR}"
CFG="{CLASH_CFG}"
LOG="{CLASH_LOG}"
PID="{CLASH_PID}"
LAN="{lan_cidr}"
PORT={REDIR_PORT}

fw_add() {{
  iptables -t nat -F clash_tp 2>/dev/null
  iptables -t nat -D PREROUTING -s $LAN -p tcp -j clash_tp 2>/dev/null
  iptables -t nat -X clash_tp 2>/dev/null
  iptables -t nat -N clash_tp
  for NET in 0.0.0.0/8 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 224.0.0.0/4 240.0.0.0/4; do
    iptables -t nat -A clash_tp -d $NET -j RETURN
  done
  iptables -t nat -A clash_tp -p tcp -j REDIRECT --to-ports $PORT
  iptables -t nat -A PREROUTING -s $LAN -p tcp -j clash_tp
  logger -t clash_proxy "防火墙规则已添加 LAN=$LAN -> :$PORT"
}}

fw_del() {{
  iptables -t nat -F clash_tp 2>/dev/null
  iptables -t nat -D PREROUTING -s $LAN -p tcp -j clash_tp 2>/dev/null
  iptables -t nat -X clash_tp 2>/dev/null
  logger -t clash_proxy "防火墙规则已删除"
}}

start() {{
  logger -t clash_proxy "启动 Clash Meta..."
  killall clash_meta 2>/dev/null; sleep 1
  cd $DIR
  $BIN -d $DIR -f $CFG >> $LOG 2>&1 &
  echo $! > $PID
  sleep 3
  fw_add
  echo "Clash Meta PID=$(cat $PID) LAN=$LAN -> :$PORT"
}}

stop() {{
  fw_del
  [ -f $PID ] && kill $(cat $PID) 2>/dev/null; rm -f $PID
  killall clash_meta 2>/dev/null
  echo "Clash Meta stopped"
}}

restart() {{ stop; sleep 2; start; }}

status() {{
  if [ -f $PID ] && kill -0 $(cat $PID) 2>/dev/null; then
    echo "Running PID=$(cat $PID)"
    curl -s http://127.0.0.1:{API_PORT}/version 2>/dev/null; echo
  else
    echo "Not running"
  fi
  echo "--- iptables ---"
  iptables -t nat -L clash_tp -n --line-numbers 2>/dev/null || echo "No rules"
}}
"""

# ============================================================
# SSH 工具
# ============================================================
def ssh_run(client, cmd, timeout=30):
    _, out, err = client.exec_command(cmd, timeout=timeout)
    o = out.read().decode('utf-8', errors='replace')
    e = err.read().decode('utf-8', errors='replace')
    return o + e

def ssh_upload(client, remote, data, label=""):
    if isinstance(data, str):
        data = data.encode('utf-8')
    mb = len(data) / 1024 / 1024
    print(f"  上传 {label} ({mb:.1f} MB)...", end='', flush=True)
    stdin, stdout, _ = client.exec_command(f"cat > {remote}", timeout=180)
    CHUNK = 65536
    for i in range(0, len(data), CHUNK):
        stdin.write(data[i:i+CHUNK])
    stdin.channel.shutdown_write()
    stdout.read()
    print(" ✓")

# ============================================================
# 下载（带本地缓存）
# ============================================================
def download(url, label, cache_name=None):
    """下载文件到本地缓存，已有缓存直接用，返回 bytes"""
    os.makedirs(CACHE_DIR, exist_ok=True)
    fname = cache_name or os.path.basename(url.split('?')[0])
    cache_path = os.path.join(CACHE_DIR, fname)

    if os.path.exists(cache_path) and os.path.getsize(cache_path) > 1024:
        size_mb = os.path.getsize(cache_path) / 1024 / 1024
        print(f"  使用本地缓存 {label} ({size_mb:.1f} MB): {cache_path}")
        with open(cache_path, 'rb') as f:
            return f.read()

    print(f"  下载 {label} → {cache_path}")
    req = urllib.request.Request(url, headers={'User-Agent': 'curl/7.85'})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            total = int(r.headers.get('Content-Length', 0))
            buf = io.BytesIO()
            downloaded = 0
            while True:
                chunk = r.read(65536)
                if not chunk: break
                buf.write(chunk)
                downloaded += len(chunk)
                if total:
                    pct = downloaded * 100 // total
                    print(f"\r    {pct:3d}%  {downloaded/1024/1024:.1f}/{total/1024/1024:.1f} MB", end='', flush=True)
            print(f"\r  ✓ 下载完成 ({downloaded/1024/1024:.1f} MB)           ")
            data = buf.getvalue()
    except Exception as e:
        raise RuntimeError(f"下载失败: {e}\n  URL: {url}")

    with open(cache_path, 'wb') as f:
        f.write(data)
    print(f"  已缓存: {cache_path}")
    return data

# ============================================================
# 安装二进制（完整安装模式）
# 优先级: --binary → 本地缓存 → 路由器已有 → GitHub 下载
# ============================================================
def install_binary(client, clash_arch, local_binary_path=None):
    print("\n【4】安装 Clash Meta 核心...")

    # 路由器上是否已有可用二进制
    existing = ssh_run(client, f"[ -x {CLASH_BIN} ] && {CLASH_BIN} -v 2>/dev/null | head -1 || echo NONE").strip()
    if 'NONE' not in existing and existing:
        print(f"  ✓ 已存在: {existing}")
        return

    # 优先级 1: --binary 指定的本地文件
    if local_binary_path:
        if not os.path.exists(local_binary_path):
            raise FileNotFoundError(f"--binary 指定的文件不存在: {local_binary_path}")
        print(f"  使用指定二进制: {local_binary_path}")
        with open(local_binary_path, 'rb') as f:
            binary = f.read()
        ssh_upload(client, CLASH_BIN, binary, "clash_meta")
        ssh_run(client, f"chmod +x {CLASH_BIN}")
        return

    # 优先级 2: 本地缓存（已解压的 .bin）
    cache_bin  = f"mihomo-linux-{clash_arch}-{CLASH_VERSION}.bin"
    cache_bin_path = os.path.join(CACHE_DIR, cache_bin)
    if os.path.exists(cache_bin_path) and os.path.getsize(cache_bin_path) > 1024 * 1024:
        size_mb = os.path.getsize(cache_bin_path) / 1024 / 1024
        print(f"  使用本地缓存 clash_meta ({size_mb:.1f} MB): {cache_bin_path}")
        with open(cache_bin_path, 'rb') as f:
            binary = f.read()
        ssh_upload(client, CLASH_BIN, binary, "clash_meta")
        ssh_run(client, f"chmod +x {CLASH_BIN}")
        return

    # 优先级 3: 路由器上已有 OpenClash 安装的二进制
    cp = ssh_run(client, f"[ -x /etc/openclash/core/clash_meta ] && cp /etc/openclash/core/clash_meta {CLASH_BIN} && echo OK || echo NONE")
    if 'OK' in cp:
        print("  ✓ 复用路由器已有 /etc/openclash/core/clash_meta")
        ssh_run(client, f"chmod +x {CLASH_BIN}")
        return

    # 优先级 4: 从 GitHub 下载 → 本地解压 → 缓存 → 上传
    bin_url  = f"{GITHUB_BASE}/{CLASH_VERSION}/mihomo-linux-{clash_arch}-{CLASH_VERSION}.gz"
    cache_gz = f"mihomo-linux-{clash_arch}-{CLASH_VERSION}.gz"
    print(f"  URL: {bin_url}")
    gz = download(bin_url, f"mihomo-{clash_arch}", cache_gz)
    print("  解压 gz...")
    binary = gzip.decompress(gz)
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(cache_bin_path, 'wb') as f:
        f.write(binary)
    print(f"  已缓存解压文件: {cache_bin_path}")
    ssh_upload(client, CLASH_BIN, binary, "clash_meta")
    ssh_run(client, f"chmod +x {CLASH_BIN}")

# ============================================================
# 主流程
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="OpenWrt Clash Meta 一键安装/更新脚本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("router_ip",  help="路由器 IP，如 192.168.1.1")
    parser.add_argument("proxy_url",  help="代理链接，如 vless://... 或 trojan://...")
    parser.add_argument("password",   nargs='?', default="123456", help="SSH root 密码（默认 123456）")
    parser.add_argument("--update",   action="store_true",
                        help="仅更新节点配置并重启（不重装二进制，10秒完成）")
    parser.add_argument("--binary",   default=None, metavar="PATH",
                        help="指定本地二进制文件路径，跳过下载")
    args = parser.parse_args()

    router_ip = args.router_ip
    proxy_url = args.proxy_url
    root_pass = args.password
    update_mode = args.update

    sep = "=" * 60
    mode_tag = "【更新节点模式】" if update_mode else "【完整安装模式】"
    print(f"\n{sep}")
    print(f"  Clash Meta 一键脚本  {mode_tag}")
    print(f"  路由器: {router_ip}  密码: {root_pass}")
    print(f"{sep}\n")

    # ── 1. 解析代理 URL ───────────────────────────────────────
    print("【1】解析代理 URL...")
    proxy = parse_url(proxy_url)
    print(f"  协议: {proxy['type'].upper()}")
    print(f"  服务器: {proxy['server']}:{proxy['port']}")
    print(f"  节点名: {proxy['name']}")

    # ── 2. SSH 连接 ───────────────────────────────────────────
    print("\n【2】SSH 连接路由器...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(router_ip, port=22, username='root', password=root_pass,
                   timeout=15, auth_timeout=15, allow_agent=False, look_for_keys=False)
    print(f"  ✓ 已连接 {router_ip}")

    # ── 3. 检测路由器信息 ─────────────────────────────────────
    print("\n【3】检测路由器...")
    arch    = ssh_run(client, "uname -m").strip()
    lan_raw = ssh_run(client, "ip addr show br-lan 2>/dev/null | grep 'inet ' | awk '{print $2}' | head -1").strip()

    lan_cidr = "192.168.1.0/24"
    m = re.match(r'(\d+\.\d+\.\d+)\.\d+/(\d+)', lan_raw)
    if m:
        lan_cidr = f"{m.group(1)}.0/{m.group(2)}"
    print(f"  架构: {arch}  LAN: {lan_cidr}")

    arch_map = {
        'mipsel': 'mipsle-softfloat',
        'mips':   'mips-softfloat',
        'armv7l': 'armv7',
        'aarch64':'arm64',
        'x86_64': 'amd64',
        'i686':   '386',
    }
    clash_arch = next((v for k, v in arch_map.items() if k in arch.lower()), 'mipsle-softfloat')
    print(f"  Clash 架构: {clash_arch}")

    ssh_run(client, f"mkdir -p {INSTALL_DIR}")

    # ============================================================
    # 更新节点模式（--update）：只改 config.yaml + 重启
    # ============================================================
    if update_mode:
        print("\n【4】写入新节点配置...")
        config = gen_config(proxy, lan_cidr)
        ssh_upload(client, CLASH_CFG, config, "config.yaml")

        print("\n【5】重启 Clash Meta...")
        try:
            ssh_run(client, "killall clash_meta 2>/dev/null; true", timeout=8)
        except Exception:
            pass
        time.sleep(2)
        try:
            msg = ssh_run(client, "/etc/init.d/clash_proxy start 2>&1 || true", timeout=30)
            print(f"  {msg.strip()[:200]}")
        except Exception as e:
            print(f"  ⚠ 启动超时，稍后检查状态... ({e.__class__.__name__})")
        time.sleep(4)

        print("\n【6】验证...")
        ps = ssh_run(client, "ps | grep clash_meta | grep -v grep")
        print(f"  进程: {'✓ 运行中' if 'clash_meta' in ps else '✗ 未运行！'}")
        google = ssh_run(client,
            f"curl -sk --proxy http://127.0.0.1:{HTTP_PORT} --max-time 12 "
            f"-o /dev/null -w '%{{http_code}}' https://www.google.com", timeout=20)
        print(f"  Google HTTPS: {'✓ 200 OK' if '200' in google else f'结果={google}'}")

        client.close()
        print(f"\n{sep}")
        print(f"  ✓ 节点已更新！  国外流量 → {proxy['name']}")
        print(f"{sep}\n")
        return

    # ============================================================
    # 完整安装模式
    # ============================================================

    # ── 4. 安装二进制 ─────────────────────────────────────────
    install_binary(client, clash_arch, args.binary)

    # ── 5. GeoIP 数据库 ──────────────────────────────────────
    print("\n【5】准备 GeoIP 数据库...")
    mmdb_ok = ssh_run(client, f"[ -s {CLASH_MMDB} ] && echo OK || echo NONE").strip()
    if 'OK' in mmdb_ok:
        print("  ✓ Country.mmdb 已存在")
    else:
        cp = ssh_run(client, f"[ -s /etc/openclash/Country.mmdb ] && cp /etc/openclash/Country.mmdb {CLASH_MMDB} && echo OK || echo NONE")
        if 'OK' in cp:
            print("  ✓ 复用 OpenClash 的 Country.mmdb")
        else:
            done = False
            for url in [MMDB_URL, MMDB_FALLBACK]:
                try:
                    mmdb = download(url, "Country.mmdb", "Country.mmdb")
                    ssh_upload(client, CLASH_MMDB, mmdb, "Country.mmdb")
                    print("  ✓ Country.mmdb 已安装")
                    done = True
                    break
                except Exception as e:
                    print(f"  ⚠ 下载失败({e})，尝试备用源...")
            if not done:
                print("  ⚠ 无法获取 MMDB，GeoIP 分流将不可用（仍可运行）")

    # ── 6. 写入配置文件 ───────────────────────────────────────
    print("\n【6】写入 Clash 配置...")
    config = gen_config(proxy, lan_cidr)
    ssh_upload(client, CLASH_CFG, config, "config.yaml")

    # ── 7. 写入开机自启脚本 ───────────────────────────────────
    print("\n【7】安装开机自启脚本...")
    init_sh = gen_init(lan_cidr)
    ssh_upload(client, "/etc/init.d/clash_proxy", init_sh, "clash_proxy init")
    ssh_run(client, "chmod +x /etc/init.d/clash_proxy && /etc/init.d/clash_proxy enable")
    enabled = ssh_run(client, "ls /etc/rc.d/ | grep clash").strip()
    print(f"  开机自启: {enabled}")

    # ── 8. 测试节点可达性 ─────────────────────────────────────
    print(f"\n【8】测试节点可达性 {proxy['server']}...")
    ping = ssh_run(client, f"ping -c 2 -W 5 {proxy['server']} 2>&1 | tail -2")
    if '0% packet loss' in ping:
        print("  ✓ 节点可达")
    else:
        print(f"  ⚠ Ping 结果: {ping.strip()}")

    # ── 9. 启动服务 ───────────────────────────────────────────
    print("\n【9】启动 Clash Meta 代理...")
    try:
        ssh_run(client, "killall clash clash_meta 2>/dev/null; true", timeout=8)
    except Exception:
        pass
    time.sleep(2)
    try:
        msg = ssh_run(client, "/etc/init.d/clash_proxy restart 2>&1 || true", timeout=35)
        print(f"  {msg.strip()[:200]}")
    except Exception as e:
        print(f"  ⚠ 启动超时，稍后验证状态... ({e.__class__.__name__})")
    time.sleep(5)

    # ── 10. 验证 ─────────────────────────────────────────────
    print("\n【10】验证...")
    ps = ssh_run(client, "ps | grep clash_meta | grep -v grep | head -2")
    print(f"  进程: {'✓ 运行中' if 'clash_meta' in ps else '✗ 未运行！'}")

    ipt = ssh_run(client, "iptables -t nat -L clash_tp -n 2>/dev/null | wc -l").strip()
    print(f"  iptables 规则: {'✓ 已设置' if int(ipt or 0) > 2 else '✗ 未设置'}")

    google = ssh_run(client,
        f"curl -sk --proxy http://127.0.0.1:{HTTP_PORT} --max-time 12 "
        f"-o /dev/null -w '%{{http_code}}' https://www.google.com", timeout=20)
    print(f"  Google HTTPS: {'✓ 200 OK 🎉' if '200' in google else f'结果={google}'}")

    client.close()

    # ── 完成提示 ─────────────────────────────────────────────
    print(f"\n{sep}")
    print(f"  ✓ 安装完成！")
    print(f"")
    print(f"  路由器管理页:  http://{router_ip}/")
    print(f"  Clash 控制台:  http://{router_ip}:{API_PORT}/ui")
    print(f"  HTTP 代理:     {router_ip}:{HTTP_PORT}")
    print(f"  SOCKS5 代理:   {router_ip}:{SOCKS_PORT}")
    print(f"")
    print(f"  手机连接路由器 WiFi 后自动翻墙，无需任何设置")
    print(f"  国内网站 → 直连  |  国外 → {proxy['name']}")
    print(f"")
    print(f"  SSH 管理命令:")
    print(f"    /etc/init.d/clash_proxy start    # 启动")
    print(f"    /etc/init.d/clash_proxy stop     # 停止")
    print(f"    /etc/init.d/clash_proxy status   # 状态")
    print(f"    /etc/init.d/clash_proxy restart  # 重启")
    print(f"")
    print(f"  更换节点（快速，10秒）:")
    print(f"    python clash_setup.py {router_ip} \"<新的代理URL>\" {root_pass} --update")
    print(f"{sep}\n")

if __name__ == "__main__":
    main()
