#!/usr/bin/env python3
"""singbox_sub.lua 的自动测试。

用 lupa 内嵌 Lua 直接加载被测文件，做三件事：
  1. 语法检查：load() 编译 subscribe.lua / node_subscribe_config.lua / singbox_sub.lua
  2. 解密测试：密文 → 明文，必须与 fixtures/plain.json 逐字节一致
  3. 转换测试：sing-box JSON → 分享链接，必须与 fixtures/expected_links.txt 逐字节一致

环境有 openssl 时走真实命令（验证 openssl 参数拼对了）；
没有时用 Python 的 AES 顶上（仍然验证 IV 切分与 hex 格式化）。
"""

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
FIX = os.path.join(HERE, "fixtures")
PW = os.path.join(ROOT, "luci-app-passwall")

LUA_MODULE = os.path.join(PW, "root/usr/share/passwall/singbox_sub.lua")
SYNTAX_FILES = [
    (LUA_MODULE, "singbox_sub.lua"),
    (os.path.join(PW, "root/usr/share/passwall/subscribe.lua"), "subscribe.lua"),
    (os.path.join(PW, "luasrc/model/cbi/passwall/client/node_subscribe_config.lua"),
     "node_subscribe_config.lua"),
]

KEY_EXPECT = "3d7ad5e98d00ef072810c4f7e3b140a7d1cdf3ad512f5a87ea88b91ea2c64bac"

try:
    import lupa
except ImportError:
    sys.exit("需要 lupa：pip install lupa")

HAVE_OPENSSL = shutil.which("openssl") is not None
fails = []


def check(ok, label, detail=""):
    print("  %s %s%s" % ("[OK]  " if ok else "[FAIL]", label, ("  " + detail) if detail else ""))
    if not ok:
        fails.append(label)


lua = lupa.LuaRuntime(unpack_returned_tuples=True)
print("  Lua %s   openssl: %s\n" % (lua.eval("_VERSION"), "有" if HAVE_OPENSSL else "无（用 Python 顶替）"))


def py2lua(obj):
    if isinstance(obj, dict):
        t = lua.table()
        for k, v in obj.items():
            t[k] = py2lua(v)
        return t
    if isinstance(obj, list):
        t = lua.table()
        for i, v in enumerate(obj, 1):
            t[i] = py2lua(v)
        return t
    return obj


def tostr(v):
    return v.decode("utf-8") if isinstance(v, bytes) else v


def call2(fn, *args):
    """Lua 函数返回 (值, 错误) 两个值；lupa 有时给 tuple，有时给单值。"""
    r = fn(*args)
    if isinstance(r, tuple):
        return (r + (None, None))[:2]
    return r, None


# ---------------------------------------------------------------- 1. 语法
compile_only = lua.eval("function(src, name) return load(src, name) end")
print("[1] 语法检查")
for path, name in SYNTAX_FILES:
    src = open(path, encoding="utf-8").read()
    if src.startswith("#"):
        src = src.split("\n", 1)[1]
    res = compile_only(src, "=" + name)
    fn, err = (res[0], res[1] if len(res) > 1 else None) if isinstance(res, tuple) else (res, None)
    check(fn is not None, "编译 %s" % name, "" if fn is not None else str(err))

# ------------------------------------------------------------ 2. 准备运行环境
api = lua.table()


def _b64decode(s):
    if isinstance(s, str):
        s = s.encode("latin-1")
    s = s.replace(b"-", b"+").replace(b"_", b"/")
    return base64.b64decode(s + b"=" * ((-len(s)) % 4))


def _b64encode(s):
    if isinstance(s, str):
        s = s.encode("latin-1", "surrogateescape")
    return base64.b64encode(s)


api["base64Decode"] = _b64decode
api["base64Encode"] = _b64encode
api["UrlEncode"] = lambda s: s
api["UrlDecode"] = lambda s: s
api["jsonc"] = py2lua({})
lua.execute('package.loaded["luci.passwall.api"] = ...', api)

src = open(LUA_MODULE, encoding="utf-8").read()
if src.startswith("#"):
    src = src.split("\n", 1)[1]

if not HAVE_OPENSSL:
    # 没有 openssl 时用 Python 顶替：解析 Lua 拼出的命令，校验密钥/IV 后自己解密
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def fake_exec(cmd):
        m = re.search(r"-K ([0-9a-f]+) -iv ([0-9a-f]+) -in (\S+) -out (\S+)", cmd)
        if not m:
            return 1
        key_hex, iv_hex, in_path, out_path = m.groups()
        if key_hex != KEY_EXPECT:
            return 1
        iv = bytes.fromhex(iv_hex)
        ct = open(in_path, "rb").read()
        dec = Cipher(algorithms.AES(bytes.fromhex(key_hex)), modes.CBC(iv)).decryptor()
        pt = dec.update(ct) + dec.finalize()
        pad = pt[-1] if pt else 0
        if pad < 1 or pad > 16 or pt[-pad:] != bytes([pad]) * pad:
            return 1
        open(out_path, "wb").write(pt[:-pad])
        return 0

    os_stub = lua.table()
    os_stub["execute"] = fake_exec
    os_stub["remove"] = lambda p: (os.path.exists(p) and os.remove(p)) or True
    os_stub["time"] = lambda: 0
    lua.globals()["os"] = os_stub

lua.execute(src)

# ---------------------------------------------------------------- 3. 解密
print("\n[2] 解密")
blob = open(os.path.join(FIX, "encrypted.b64"), encoding="utf-8").read()
plain, derr = call2(lua.globals().singboxSubDecrypt, blob, tempfile.gettempdir())
plain = tostr(plain)
if plain is None:
    print("        解密错误: %s" % derr)
expect_plain = open(os.path.join(FIX, "plain.json"), encoding="utf-8").read()
check(plain == expect_plain, "密文解密与 plain.json 一致",
      "%d 字节" % len(plain or ""))

# ---------------------------------------------------------------- 4. 转换
print("\n[3] 转换")
links, cerr = call2(lua.globals().singboxSubToLinks, plain, lambda s: py2lua(json.loads(s)))
links = tostr(links)
if links is None:
    print("        转换错误: %s" % cerr)
expect_links = open(os.path.join(FIX, "expected_links.txt"), encoding="utf-8").read()
check(links == expect_links, "转换结果与 expected_links.txt 一致",
      "%d 条链接" % (links.count("\n") if links else 0))
if links and links != expect_links:
    a, b = links.strip().split("\n"), expect_links.strip().split("\n")
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            print("        #%d 实际: %s" % (i, a[i][:120]))
            print("        #%d 期望: %s" % (i, b[i][:120]))
            break

# ------------------------------------------------------------ 5. 健壮性
print("\n[4] 健壮性")
is_enc = lua.globals().singboxSubIsEncrypted
cases = [
    ("X-Encrypted: 1\r\n", True),
    ("x-encrypted: 1\r\n", True),
    ("X-Encrypted: 0\r\n", False),
    ("Content-Type: text/plain\r\n", False),
]
check(all(bool(is_enc(h)) == w for h, w in cases), "加密响应头识别")

bad_ok = True
for bad in ("", "not-json", "{}", '{"outbounds":[]}'):
    # 返回的是 (nil, 错误信息) 两个值，必须看第一个
    r, _e = call2(lua.globals().singboxSubToLinks, bad, lambda s: py2lua(json.loads(s)))
    if tostr(r) is not None:
        bad_ok = False
        print("        %r 应当返回 nil，实际返回了内容" % bad)
check(bad_ok, "非法输入返回 nil 而不抛异常")

print()
if fails:
    print("  失败 %d 项：%s" % (len(fails), ", ".join(fails)))
    sys.exit(1)
print("  全部通过")
