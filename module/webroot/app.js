import { exec, listPackages, getPackagesInfo, toast, moduleInfo } from './kernelsu.js';

const BIN = '/data/adb/steer/steer';
const MODES = ['direct', 'proxy', 'block'];
const MODE_CN = ['直连', '代理', '拦截'];
/* 四档：-1 = 未单独设置（跟随默认策略）= 删除该条 */
const OPTS = [
  { m: -1, t: '默认' }, { m: 0, t: '直连' },
  { m: 1, t: '代理' },  { m: 2, t: '拦截' },
];

let pkgs = [];              // {pkg,label,uid,isSystem}
let state = new Map();      // uid -> mode(0/1/2)  来自 steer list
let defaultMode = 0;
let info = null;            // steer status
let showSystem = false;
let q = '';
let enabled = true;         // 总开关状态

/* ---------------- 与后端通信 ---------------- */

/* 带超时的 exec：KernelSU 的 exec 要等子进程的管道 EOF 才回调，
 * 万一有后台进程继承了管道，回调就永远不来 —— 不能让界面无限"读取中…" */
function sh(cmd, timeoutMs = 15000) {
  return new Promise((resolve) => {
    let done = false;
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      resolve({ ok: false, out: '', err: `命令 ${timeoutMs / 1000}s 无响应（可能有后台进程占着输出管道）\n请在终端手动执行：\n${cmd}` });
    }, timeoutMs);
    exec(cmd).then((r) => {
      if (done) return;
      done = true; clearTimeout(timer);
      resolve({ ok: r.errno === 0, out: (r.stdout || '').trim(), err: (r.stderr || '').trim() });
    }).catch((e) => {
      if (done) return;
      done = true; clearTimeout(timer);
      resolve({ ok: false, out: '', err: String(e) });
    });
  });
}

/* shell 单引号安全转义（密码可能含空格/特殊字符） */
function shq(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }

let cfg = null;

async function loadCfg() {
  const r = await sh(`${BIN} cfg --json`);
  if (!r.ok || !r.out) return;
  try { cfg = JSON.parse(r.out); } catch (_) { return; }
  el('cHost').value = cfg.socks_host || '';
  el('cPort').value = cfg.socks_port || '';
  el('cUser').value = cfg.socks_user || '';
  el('cPass').value = '';
  el('cPass').placeholder = cfg.socks_pass_set ? '已设置（留空不修改）' : '留空不修改';
  el('cRelay').value = cfg.relay_port || '';
  el('cFlags').checked = !!cfg.flags;
  el('cUdp').checked = !!cfg.udp;
  el('cRelayUdp').value = cfg.relay_udp_port || 25201;
}

async function saveCfg() {
  if (!cfg) { toast('读取配置失败'); return; }
  const btn = el('cfgSave');
  btn.disabled = true;
  document.body.classList.add('busy');

  const want = [
    ['socks_host', el('cHost').value.trim()],
    ['socks_port', String(el('cPort').value).trim()],
    ['socks_user', el('cUser').value.trim()],
    ['relay_port', String(el('cRelay').value).trim()],
    ['flags', el('cFlags').checked ? '1' : '0'],
    ['udp', el('cUdp').checked ? '1' : '0'],
    ['relay_udp_port', String(el('cRelayUdp').value).trim()],
  ];
  const pw = el('cPass').value;
  if (pw) want.push(['socks_pass', pw]);

  let changed = 0, err = '';
  for (const [k, v] of want) {
    if (v === '') continue;
    if (k !== 'flags' && String(cfg[k]) === String(v)) continue;
    if (k === 'flags' && Number(cfg.flags) === Number(v)) continue;
    const r = await sh(`${BIN} cfg set ${shq(k)} ${shq(v)}`);
    if (!r.ok) err += (r.err || r.out || k) + ' ';
    else changed++;
  }

  btn.disabled = false;
  document.body.classList.remove('busy');

  if (err) { toast('保存失败：' + err.trim()); return; }
  if (!changed) { toast('没有改动'); return; }

  toast(`已保存 ${changed} 项，正在重启…`);
  await sh(`${BIN} restart`);
  await new Promise(r => setTimeout(r, 1500));
  await loadCfg();
  await refresh();
}

async function loadPolicy() {
  const r = await sh(`${BIN} list --json`);
  state = new Map();
  if (r.ok && r.out) {
    try { for (const e of JSON.parse(r.out)) state.set(e.uid, e.mode); } catch (_) {}
  }
}

async function loadStatus() {
  const r = await sh(`${BIN} status --json`);
  if (r.ok && r.out) { try { info = JSON.parse(r.out); } catch (_) { info = null; } }
  const s = await sh(`${BIN} stats --json`);
  let st = null;
  if (s.ok && s.out) { try { st = JSON.parse(s.out); } catch (_) {} }
  return st;
}

/* ---------------- 应用列表 ---------------- */

async function loadPackages() {
  let names = [];
  for (const t of ['user', 'system']) {
    if (t === 'system' && !showSystem) continue;
    try { const r = listPackages(t); if (Array.isArray(r)) names = names.concat(r); } catch (_) {}
  }
  if (!names.length) { try { const r = listPackages(); if (Array.isArray(r)) names = r; } catch (_) {} }
  names = [...new Set(names)].filter(Boolean).sort();

  const out = [];
  for (let i = 0; i < names.length; i += 120) {
    const chunk = names.slice(i, i + 120);
    try {
      const infos = getPackagesInfo(chunk) || [];
      for (const p of infos) {
        out.push({
          pkg: p.packageName,
          label: p.appLabel || p.packageName,
          uid: p.uid,
          isSystem: !!p.isSystem,
        });
      }
    } catch (_) {
      for (const n of chunk) out.push({ pkg: n, label: n, uid: -1, isSystem: false });
    }
  }
  pkgs = out;
}

/* ---------------- 渲染 ---------------- */

function el(id) { return document.getElementById(id); }

function renderMaster() {
  const sw = el('masterSw');
  sw.classList.toggle('on', enabled);
  sw.setAttribute('aria-checked', enabled ? 'true' : 'false');
  document.body.classList.toggle('steer-off', !enabled);
  const running = !!(info && info.running);
  el('masterSub').textContent =
    !running ? '服务未运行 —— 点下方「启动 / 重启服务」；仍失败请点「诊断」看原因'
             : enabled ? '已开启 · 按下面的策略接管流量'
                       : '已关闭 · 全部流量直连，策略原样保留';
}

function renderStatus(st) {
  const running = !!(info && info.running);
  const b = el('runBadge');
  b.textContent = running ? '运行中' : '未运行';
  b.className = 'badge ' + (running ? 'on' : 'off');

  if (info) {
    el('stSocks').textContent = info.socks;
    el('stRelay').textContent = '127.0.0.1:' + info.relay_port;
    el('stDefault').textContent = MODE_CN[info.default] ? MODE_CN[info.default] : info.default;
    defaultMode = ['direct', 'proxy', 'block'].indexOf(info.default);
    if (defaultMode < 0) defaultMode = 0;
  }
  for (const btn of el('segDefault').querySelectorAll('button')) {
    btn.classList.toggle('on', Number(btn.dataset.m) === defaultMode);
  }
  if (st) {
    el('stProxy').textContent = st.proxied ?? 0;
    el('stDirect').textContent = st.direct ?? 0;
    el('stBlock').textContent = st.blocked ?? 0;
    el('stFail').textContent = st.failed ?? 0;
  }
  enabled = !!(info && info.enabled);
  renderMaster();
  el('defHint').textContent = defaultMode === 1
    ? '当前：未单独设置的应用【全部走代理】。下面的单独设置优先生效。'
    : '当前：未单独设置的应用直连。下面选中的应用走代理。';
}

function match(p) {
  if (!q) return true;
  const s = q.toLowerCase();
  return p.label.toLowerCase().includes(s) || p.pkg.toLowerCase().includes(s);
}

function renderList() {
  const ul = el('list');
  ul.innerHTML = '';
  const shown = pkgs.filter(match);
  let np = 0, nd = 0, nb = 0;

  for (const p of shown) {
    const m = state.has(p.uid) ? state.get(p.uid) : -1;   /* -1 = 跟随默认 */
    if (m === 1) np++; else if (m === 2) nb++; else if (m === 0) nd++;

    const li = document.createElement('li');
    li.className = 'li';

    const img = document.createElement('img');
    img.src = 'ksu://icon/' + p.pkg;
    img.onerror = () => { img.style.visibility = 'hidden'; };
    li.appendChild(img);

    const meta = document.createElement('div');
    meta.className = 'meta';
    const nm = document.createElement('div');
    nm.className = 'nm';
    nm.textContent = p.label + (p.isSystem ? ' ·系统' : '');
    const pk = document.createElement('div');
    pk.className = 'pk';
    pk.textContent = p.pkg + (p.uid >= 0 ? '  · ' + p.uid : '');
    meta.append(nm, pk);
    li.appendChild(meta);

    const seg = document.createElement('div');
    seg.className = 'seg';
    for (const o of OPTS) {
      const b = document.createElement('button');
      b.textContent = o.t;
      b.dataset.m = o.m;
      if (m === o.m) b.classList.add('on');
      b.onclick = () => onPick(p, o.m);
      seg.appendChild(b);
    }
    li.appendChild(seg);
    ul.appendChild(li);
  }

  el('empty').style.display = shown.length ? 'none' : '';
  el('empty').textContent = shown.length ? '' : '没有匹配的应用';
  el('cntSet').textContent = '已设置 ' + state.size;
  el('cntProxy').textContent = '代理 ' + np;
  el('cntDirect').textContent = '直连 ' + nd;
  el('cntBlock').textContent = '拦截 ' + nb;
}

/* ---------------- 交互 ---------------- */

let busy = false;

async function onPick(p, mode) {
  if (busy) return;                       // 防连点造成并发下命令
  busy = true;
  document.body.classList.add('busy');

  const arg = p.uid >= 0 ? p.uid : p.pkg;
  const cmd = mode < 0 ? `${BIN} del ${arg}` : `${BIN} set ${arg} ${MODES[mode]}`;
  const r = await sh(cmd);

  busy = false;
  document.body.classList.remove('busy');

  if (!r.ok) { toast('失败：' + (r.err || r.out || '未知错误')); return; }

  // 以 CLI 回显的真实 uid 为准（getPackagesInfo 失败时 p.uid 可能是 -1）
  const mm = (r.out || '').match(/(\d+)/);
  const k = mm ? Number(mm[1]) : p.uid;
  if (k >= 0) { if (mode < 0) state.delete(k); else state.set(k, mode); }
  toast(mode < 0 ? `${p.label} → 跟随默认策略` : `${p.label} → ${MODE_CN[mode]}`);
  renderList();
}

async function onDefault(mode) {
  const r = await sh(`${BIN} default ${MODES[mode]}`);
  if (!r.ok) { toast('设置失败：' + (r.err || r.out)); return; }
  defaultMode = mode;
  toast('默认策略 → ' + MODE_CN[mode]);
  await refresh();
}

async function refresh(reloadPkgs) {
  if (reloadPkgs) {
    el('empty').textContent = '加载中…';
    el('empty').style.display = '';
    await loadPackages();
  }
  await loadPolicy();
  const st = await loadStatus();
  renderStatus(st);
  renderList();
}

/* ---------------- 启动 ---------------- */

(async function init() {
  try {
    const id = moduleInfo();
    if (id) el('sub').textContent = '分应用透明代理 · ' + id;
  } catch (_) {}

  el('btnRefresh').onclick = async () => { await refresh(true); toast('已刷新'); };

  el('btnStart').onclick = async () => {
    el('btnStart').disabled = true;
    toast('正在启动服务…');
    await sh(`${BIN} start`);
    await new Promise(r => setTimeout(r, 2000));
    el('btnStart').disabled = false;
    await refresh();
    toast((info && info.running) ? '服务已运行' : '仍未运行，请点「诊断」看原因');
  };

  el('btnDiag').onclick = async () => {
    el('diagModal').hidden = false;
    el('diagOut').textContent = '读取中…';
    const r = await sh(`${BIN} diag`);
    el('diagOut').textContent = (r.out || '') + (r.err ? '\n[stderr]\n' + r.err : '');
    el('diagOut').scrollTop = 0;
  };
  el('diagClose').onclick = () => { el('diagModal').hidden = true; };
  el('diagModal').onclick = (e) => { if (e.target.id === 'diagModal') el('diagModal').hidden = true; };

  el('masterSw').onclick = async () => {
    const next = !enabled;
    el('masterSw').disabled = true;
    const r = await sh(`${BIN} switch ${next ? 'on' : 'off'}`);
    el('masterSw').disabled = false;
    if (!r.ok) { toast('切换失败：' + (r.err || r.out || '未知错误')); return; }
    toast(next ? '已开启代理' : '已关闭代理');
    await refresh();
  };
  el('segDefault').onclick = (e) => {
    const b = e.target.closest('button');
    if (b) onDefault(Number(b.dataset.m));
  };
  el('q').oninput = (e) => { q = e.target.value.trim(); renderList(); };

  el('cfgToggle').onclick = () => {
    const b = el('cfgBody');
    b.hidden = !b.hidden;
    el('cfgChev').classList.toggle('open', !b.hidden);
  };
  el('cfgSave').onclick = saveCfg;
  el('sys').onchange = async (e) => {
    showSystem = e.target.checked;
    el('empty').textContent = '加载中…';
    await loadPackages();
    renderList();
  };

  /* 双保险：确保初始就是收起/隐藏的（CSS 若被覆盖也不会露出） */
  el('diagModal').hidden = true;
  el('cfgBody').hidden = true;
  el('cfgChev').classList.remove('open');

  el('ftInfo').textContent = 'KernelSU · Steer · ' + new Date().toLocaleString();
  await loadPackages();
  await loadCfg();
  await refresh();
})();
