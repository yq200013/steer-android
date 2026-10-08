#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""自洽检查：BPF 侧与用户态侧必须严格对应。任何一项不一致 -> 退出码非 0（build.sh 中止）。"""
import re, sys, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BPF = open(os.path.join(ROOT, 'src/steer.bpf.c'), encoding='utf-8').read()
C   = open(os.path.join(ROOT, 'src/steer.c'), encoding='utf-8').read()

fail = []
def bad(m): fail.append(m)

def strip_comments(t):
    t = re.sub(r'/\*.*?\*/', ' ', t, flags=re.S)
    return re.sub(r'//[^\n]*', ' ', t)

TYPEMAP = {'__u8':'u8','uint8_t':'u8','__u16':'u16','uint16_t':'u16',
           '__u32':'u32','uint32_t':'u32','__u64':'u64','uint64_t':'u64',
           'int':'i32','unsigned int':'u32','long':'i64'}
def nt(t): return TYPEMAP.get(t.strip(), t.strip())

def fields(text, sname):
    txt = strip_comments(text)
    m = re.search(r'\bstruct\s+' + re.escape(sname) + r'\s*\{([^}]*)\}', txt, re.S)
    if not m: return None
    out = []
    for decl in m.group(1).split(';'):
        decl = re.sub(r'__attribute__\s*\(\([^)]*\)\)', '', decl).strip()
        if not decl: continue
        toks = decl.split()
        if len(toks) < 2: continue
        typ = nt(toks[0])                 # 类型是第一个 token
        rest = ' '.join(toks[1:])         # 其余全是声明符（可能逗号分隔）
        for n in [x.strip() for x in rest.split(',') if x.strip()]:
            if not n or not re.match(r'^[A-Za-z_]\w*(\[\d+\])?$', n): continue
            out.append((typ, n))
    return out

# ---- 1) 结构体逐字段一致 ----
for s in ['cfg_t', 'stats_t', 'rstats_t', 'dstkey']:
    a, b = fields(BPF, s), fields(C, s)
    if a is None: bad(f"BPF 里找不到 struct {s}"); continue
    if b is None: bad(f"C 里找不到 struct {s}"); continue
    if a != b:
        bad(f"struct {s} 不一致:\n      BPF={a}\n      C  ={b}")

# ---- 2) map 名字 ----
bpf_maps = re.findall(r'\}\s*(\w+)\s+SEC\("\.maps"\)', BPF)
m = re.search(r'MAPNAMES\[\]\s*=\s*\{([^}]*)\}', C, re.S)
c_maps = re.findall(r'"([^"]+)"', m.group(1)) if m else []
if sorted(bpf_maps) != sorted(c_maps):
    bad(f"map 名单不一致:\n      BPF={sorted(bpf_maps)}\n      C  ={sorted(c_maps)}")

# ---- 3) 程序名 ----
progs = []
for m in re.finditer(r'SEC\("([^"]+)"\)', BPF):
    if m.group(1) in ('.maps', 'license'): continue
    tail = BPF[m.end():m.end() + 500]           # 允许 SEC 与函数之间夹注释
    fm = re.search(r'\bint\s+(\w+)\s*\(', tail)
    if fm: progs.append(fm.group(1))
bpf_progs = progs
# C 里出现的所有看起来像 BPF 程序名的字符串（不论直接写还是走数组）
refs = set(re.findall(r'"(steer_\w+)"', C))
if not refs:
    bad("C 里一个 steer_* 程序名都没找到（检查器失效？）")
for u in sorted(refs):
    if u not in bpf_progs:
        bad(f"C 引用的程序 '{u}' 不在 BPF 里（BPF: {bpf_progs}）")
# 反向：BPF 里的每个程序都应当被 C 引用（否则就是死代码/漏挂）
for u in bpf_progs:
    if u not in refs:
        bad(f"BPF 程序 '{u}' 没有任何 C 代码引用它（漏挂？）")

# ---- 4) 常量 ----
def dint(t, n):
    m = re.search(r'#define\s+' + n + r'\s+(\d+)', t)
    return int(m.group(1)) if m else None
for b, c in [('MAX_UDP_SLOT', 'MAX_SLOT')]:
    vb, vc = dint(BPF, b), dint(C, c)
    if vb is None or vc is None: bad(f"常量缺失: BPF.{b}={vb}  C.{c}={vc}")
    elif vb != vc: bad(f"常量不一致: BPF.{b}={vb} vs C.{c}={vc}")

# ---- 5) C 里引用的 map 名（map_fd("xxx")）都必须在 BPF 里 ----
for n in sorted(set(re.findall(r'map_fd\("([^"]+)"\)', C))):
    if n not in bpf_maps:
        bad(f"C 引用了不存在的 map '{n}'")

print("== 自洽检查 ==")
print(f"  maps  : {bpf_maps}")
print(f"  progs : {bpf_progs}")
print(f"  结构体: {[s for s in ['cfg_t','stats_t','rstats_t','dstkey']]}")
if fail:
    print(f"\n!! {len(fail)} 处不自洽：")
    for f in fail: print("  - " + f)
    sys.exit(1)
print("  ✅ 全部一致")
