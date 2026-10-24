'use strict';
/* NodeHub admin UI — vanilla JS, no build step. */

// ============ utils ============
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const store = {
  get(k, d) { try { const v = localStorage.getItem('nh_' + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem('nh_' + k, JSON.stringify(v)); } catch {} },
};

async function api(method, path, body) {
  const opt = { method, headers: { 'X-Requested-With': 'nodehub' }, credentials: 'same-origin' };
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  let data = null;
  const ct = r.headers.get('content-type') || '';
  if (ct.includes('json')) data = await r.json(); else data = await r.text();
  if (r.status === 401 && !path.startsWith('/api/auth/login')) { renderLogin(); throw new Error('未登录'); }
  if (!r.ok) { const e = new Error((data && data.error) || ('HTTP ' + r.status)); e.data = data; throw e; }
  return data;
}

function toast(msg, err) {
  const t = document.createElement('div');
  t.className = 'toast' + (err ? ' err' : '');
  t.textContent = msg;
  $('#toasts').appendChild(t);
  setTimeout(() => t.remove(), err ? 6000 : 2800);
}
const fail = (e) => toast(e.message || String(e), true);

function fmtBytes(b, d = 2) {
  b = Number(b) || 0;
  if (b < 1024) return b + ' B';
  const u = ['KB', 'MB', 'GB', 'TB', 'PB']; let i = -1;
  do { b /= 1024; i++; } while (b >= 1024 && i < u.length - 1);
  return b.toFixed(b >= 100 ? 0 : d) + ' ' + u[i];
}
const fmtRate = (b) => fmtBytes(b, 1) + '/s';
const pad = (n) => String(n).padStart(2, '0');
function fmtTime(ts, withYear) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return (withYear ? d.getFullYear() + '/' : '') + pad(d.getMonth() + 1) + '/' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
}
function fmtDate(ts) {
  if (!ts) return '永久';
  const d = new Date(ts * 1000);
  return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
}
function ago(ts) {
  if (!ts) return '从未';
  const s = Math.floor(Date.now() / 1000 - ts);
  if (s < 60) return s + ' 秒前';
  if (s < 3600) return Math.floor(s / 60) + ' 分钟前';
  if (s < 86400) return Math.floor(s / 3600) + ' 小时前';
  return Math.floor(s / 86400) + ' 天前';
}
function fmtUptime(s) {
  s = Number(s) || 0;
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
  return d ? `${d}天${h}时` : `${h}时${Math.floor((s % 3600) / 60)}分`;
}
const toDateInput = (ts) => (ts ? fmtDate(ts) : '');
const fromDateInput = (v) => (v ? Math.floor(new Date(v + 'T23:59:59').getTime() / 1000) : 0);
async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast('已复制'); }
  catch { const t = document.createElement('textarea'); t.value = text; document.body.appendChild(t); t.select(); document.execCommand('copy'); t.remove(); toast('已复制'); }
}

const COUNTRY = { CN: '中国', HK: '香港', TW: '台湾', MO: '澳门', JP: '日本', KR: '韩国', SG: '新加坡', US: '美国', CA: '加拿大', GB: '英国', DE: '德国', FR: '法国', NL: '荷兰', SE: '瑞典', NO: '挪威', FI: '芬兰', DK: '丹麦', CH: '瑞士', AT: '奥地利', IT: '意大利', ES: '西班牙', PT: '葡萄牙', IE: '爱尔兰', BE: '比利时', PL: '波兰', CZ: '捷克', RU: '俄罗斯', UA: '乌克兰', TR: '土耳其', IL: '以色列', AE: '阿联酋', SA: '沙特', IN: '印度', PK: '巴基斯坦', BD: '孟加拉', TH: '泰国', VN: '越南', MY: '马来西亚', ID: '印尼', PH: '菲律宾', KH: '柬埔寨', MM: '缅甸', AU: '澳大利亚', NZ: '新西兰', BR: '巴西', AR: '阿根廷', CL: '智利', CO: '哥伦比亚', PE: '秘鲁', MX: '墨西哥', ZA: '南非', NG: '尼日利亚', EG: '埃及', KE: '肯尼亚', RO: '罗马尼亚', HU: '匈牙利', BG: '保加利亚', GR: '希腊', LU: '卢森堡', IS: '冰岛', EE: '爱沙尼亚', LV: '拉脱维亚', LT: '立陶宛', KZ: '哈萨克斯坦', MN: '蒙古', NP: '尼泊尔', LK: '斯里兰卡', MD: '摩尔多瓦', RS: '塞尔维亚', HR: '克罗地亚', SK: '斯洛伐克', SI: '斯洛文尼亚' };
const cn = (cc) => (cc ? COUNTRY[cc.toUpperCase()] || cc.toUpperCase() : '未知');
const flag = (cc) => (cc && cc.length === 2 ? String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65)) : '');

// ============ icons ============
const I = {
  dash: '<path d="M3 13h8V3H3zm10 8h8V11h-8zM3 21h8v-6H3zm10-18v6h8V3z"/>',
  server: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><circle cx="7" cy="7.5" r="1" fill="currentColor"/><circle cx="7" cy="16.5" r="1" fill="currentColor"/>',
  node: '<circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="M8.2 11 15.8 7M8.2 13l7.6 4"/>',
  shield: '<path d="M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6z"/><path d="m9 12 2 2 4-4"/>',
  users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c.8-3.6 3.4-5.5 6.5-5.5s5.7 1.9 6.5 5.5"/><path d="M16 4.5a3.5 3.5 0 0 1 0 7M18 14.8c1.9.7 3.1 2.4 3.5 5.2"/>',
  link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="m11 12 9-9M17 6l3 3M15 8l2 2"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
  log: '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6M8 13h8M8 17h5"/>',
  refresh: '<path d="M20 11a8 8 0 0 0-14.3-4.9L4 8"/><path d="M4 3v5h5M4 13a8 8 0 0 0 14.3 4.9L20 16"/><path d="M20 21v-5h-5"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  more: '<circle cx="5" cy="12" r="1.3" fill="currentColor"/><circle cx="12" cy="12" r="1.3" fill="currentColor"/><circle cx="19" cy="12" r="1.3" fill="currentColor"/>',
  pin: '<path d="M12 21s-7-6.2-7-11.5a7 7 0 0 1 14 0C19 14.8 12 21 12 21z"/><circle cx="12" cy="9.5" r="2.5"/>',
  dc: '<rect x="4" y="3" width="16" height="18" rx="1.5"/><path d="M8 7h3M8 11h3M8 15h3M13 7h3M13 11h3M13 15h3"/>',
  home: '<path d="m3 11 9-7 9 7"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>',
  phone: '<rect x="7" y="2.5" width="10" height="19" rx="2"/><path d="M11 18h2"/>',
  biz: '<rect x="3" y="7" width="18" height="13" rx="2"/><path d="M8 7V5a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/>',
  logout: '<path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3M10 17l5-5-5-5M15 12H3"/>',
  moon: '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
};
const icon = (n) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${I[n] || ''}</svg>`;

// ============ modal & menus ============
function modal(title, body, { ok, okText = '保存', wide, cancelText = '取消', noFooter } = {}) {
  const bg = document.createElement('div');
  bg.className = 'modal-bg';
  bg.innerHTML = `<div class="modal ${wide ? 'wide' : ''}" role="dialog" aria-modal="true"><div class="modal-h"><h3>${esc(title)}</h3><span class="spacer"></span><button class="btn icon sm" data-x aria-label="关闭">✕</button></div>
    <div class="modal-b">${body}</div>${noFooter ? '' : `<div class="modal-f"><button class="btn" data-x>${cancelText}</button>${ok ? `<button class="btn primary" data-ok>${okText}</button>` : ''}</div>`}</div>`;
  const close = () => { bg.remove(); document.removeEventListener('keydown', onKey); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  bg.addEventListener('click', async (e) => {
    if (e.target === bg || e.target.closest('[data-x]')) close();
    if (e.target.closest('[data-ok]') && ok) {
      const b = e.target.closest('[data-ok]'); b.disabled = true;
      try { if ((await ok(bg)) !== false) close(); } catch (err) { fail(err); } finally { b.disabled = false; }
    }
  });
  document.body.appendChild(bg);
  const first = bg.querySelector('input:not([type=checkbox]),select,textarea');
  if (first) setTimeout(() => first.focus(), 30);
  return { el: bg, close };
}
function confirmBox(msg, fn, okText = '确定') {
  modal('确认操作', `<p style="margin:0">${msg}</p>`, { ok: fn, okText });
}
document.addEventListener('click', (e) => {
  const m = e.target.closest('.menu');
  $$('.menu.open').forEach((x) => { if (x !== m) x.classList.remove('open'); });
  if (m && e.target.closest('.menu > .btn')) {
    m.classList.toggle('open');
    if (m.classList.contains('open')) { placeMenu(m); menuOpenedAt = Date.now(); }
  } else if (m && e.target.closest('.menu-list button')) m.classList.remove('open');
});
// The list is position:fixed so table scroll containers can't clip it; place it next to its button
// and open upward when there isn't enough room below.
let menuOpenedAt = 0;
function placeMenu(m) {
  const btn = m.querySelector('.btn').getBoundingClientRect();
  const list = m.querySelector('.menu-list');
  list.style.top = '0px'; list.style.left = '0px';
  const h = list.offsetHeight, w = list.offsetWidth;
  const below = window.innerHeight - btn.bottom - 8;
  const top = below >= h || below >= btn.top ? btn.bottom + 4 : Math.max(8, btn.top - h - 4);
  list.style.top = Math.min(top, window.innerHeight - Math.min(h, window.innerHeight - 16) - 8) + 'px';
  list.style.left = Math.max(8, Math.min(btn.right - w, window.innerWidth - w - 8)) + 'px';
}
const closeMenus = () => $$('.menu.open').forEach((x) => x.classList.remove('open'));
window.addEventListener('resize', closeMenus);
document.addEventListener('scroll', (e) => {
  if (Date.now() - menuOpenedAt < 300 || (e.target.closest && e.target.closest('.menu-list'))) return;
  closeMenus();
}, true);
const menu = (items) => `<div class="menu"><button class="btn icon sm" aria-label="更多">${icon('more')}</button><div class="menu-list">${items.filter(Boolean).map(([act, label, cls]) => `<button data-act="${act}" class="${cls || ''}">${label}</button>`).join('')}</div></div>`;

// form helpers: inputs carry name="a.b" and optional data-type="int|float|bool|date"
function readForm(el) {
  const out = {};
  $$('[name]', el).forEach((inp) => {
    if (inp.closest('[data-when]') && inp.closest('[data-when]').style.display === 'none') return;
    let v;
    const t = inp.dataset.type;
    if (inp.type === 'checkbox') v = inp.checked;
    else if (t === 'int') v = inp.value === '' ? 0 : parseInt(inp.value, 10);
    else if (t === 'float') v = inp.value === '' ? 0 : parseFloat(inp.value);
    else if (t === 'date') v = fromDateInput(inp.value);
    else v = inp.value.trim();
    const path = inp.name.split('.');
    let o = out;
    while (path.length > 1) { const k = path.shift(); o = o[k] = o[k] || {}; }
    o[path[0]] = v;
  });
  return out;
}
const get = (o, path) => path.split('.').reduce((a, k) => (a == null ? a : a[k]), o);
function inp(label, name, val, { type = 'text', dtype, hint, full, ph, opts, when, attrs = '' } = {}) {
  let ctl;
  if (opts) ctl = `<select class="inp" name="${name}" ${dtype ? `data-type="${dtype}"` : ''} ${attrs}>${opts.map((o) => { const [v, l] = Array.isArray(o) ? o : [o, o]; return `<option value="${esc(v)}" ${String(v) === String(val ?? '') ? 'selected' : ''}>${esc(l)}</option>`; }).join('')}</select>`;
  else if (type === 'checkbox') ctl = `<label class="check"><input type="checkbox" name="${name}" ${val ? 'checked' : ''} ${attrs}> ${esc(hint || '')}</label>`;
  else if (type === 'textarea') ctl = `<textarea class="inp" name="${name}" placeholder="${esc(ph || '')}" ${attrs}>${esc(val ?? '')}</textarea>`;
  else ctl = `<input class="inp" type="${type}" name="${name}" value="${esc(val ?? '')}" ${dtype ? `data-type="${dtype}"` : ''} placeholder="${esc(ph || '')}" ${attrs}>`;
  return `<div class="field ${full ? 'full' : ''}" ${when ? `data-when="${when}"` : ''}><label>${esc(label)}</label>${ctl}${hint && type !== 'checkbox' ? `<span class="hint">${hint}</span>` : ''}</div>`;
}

// ============ app shell ============
const NAV = [
  ['dashboard', '概览', 'dash'], ['servers', '服务器', 'server'], ['nodes', '节点', 'node'], ['ipq', 'IP 质量', 'shield'],
  ['users', '用户', 'users'], ['panels', '面板对接', 'link'], ['api', 'API 与 Webhook', 'key'], ['settings', '设置', 'gear'], ['logs', '日志', 'log'],
];
let ME = null;
let refreshTimer = null;

function setTheme(t) {
  if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
  store.set('theme', t || '');
}
setTheme(store.get('theme', ''));

function shell() {
  const r = route().page;
  $('#root').innerHTML = `<div class="app">
    <aside class="side"><div class="brand"><span class="brand-mark">${icon('node').replace('stroke="currentColor"', 'stroke="currentColor" style="width:16px;height:16px"')}</span>${esc(ME.site_name || 'NodeHub')}</div>
      <nav class="nav">${NAV.map(([k, l, i]) => `<a href="#/${k}" class="${r === k ? 'on' : ''}">${icon(i)}${l}</a>`).join('')}</nav>
      <div class="side-foot"><div class="row"><span>${esc(ME.username)}</span><span class="spacer"></span>
        <button class="btn icon sm" id="themeBtn" title="切换深浅色" aria-label="切换深浅色">${icon('moon')}</button>
        <button class="btn icon sm" id="logoutBtn" title="退出登录" aria-label="退出登录">${icon('logout')}</button></div></div>
    </aside>
    <div><nav class="mobile-nav">${NAV.map(([k, l]) => `<a href="#/${k}" class="${r === k ? 'on' : ''}">${l}</a>`).join('')}</nav>
    <main class="main" id="main"></main></div></div>`;
  $('#logoutBtn').onclick = async () => { await api('POST', '/api/auth/logout'); location.hash = ''; renderLogin(); };
  $('#themeBtn').onclick = () => {
    const cur = document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    setTheme(cur === 'dark' ? 'light' : 'dark');
  };
}

function route() {
  const [page, ...rest] = location.hash.replace(/^#\/?/, '').split('/');
  return { page: page || 'dashboard', args: rest };
}

async function render() {
  clearInterval(refreshTimer);
  $$('.modal-bg').forEach((m) => m.remove());
  if (!ME) {
    try { ME = await api('GET', '/api/auth/me'); } catch { return; }
  }
  shell();
  const { page } = route();
  const fn = PAGES[page] || PAGES.dashboard;
  try { await fn($('#main')); } catch (e) { if (e.message !== '未登录') $('#main').innerHTML = `<div class="card empty">加载失败：${esc(e.message)}</div>`; }
}
window.addEventListener('hashchange', render);

function renderLogin(needTotp) {
  ME = null;
  clearInterval(refreshTimer);
  $('#root').innerHTML = `<div class="login"><form class="card" id="loginForm"><h2>NodeHub</h2><p>多节点管理控制台</p>
    ${inp('用户名', 'username', '', { attrs: 'autocomplete="username" required' })}
    ${inp('密码', 'password', '', { type: 'password', attrs: 'autocomplete="current-password" required' })}
    <div id="totpBox" style="display:${needTotp ? 'block' : 'none'}">${inp('两步验证码', 'code', '', { attrs: 'inputmode="numeric" autocomplete="one-time-code"' })}</div>
    <button class="btn primary" style="width:100%;justify-content:center;padding:10px">登录</button></form></div>`;
  $('#loginForm').onsubmit = async (e) => {
    e.preventDefault();
    try {
      await api('POST', '/api/auth/login', readForm(e.target));
      ME = null; render();
    } catch (err) {
      if (err.data && err.data.need_totp) { $('#totpBox').style.display = 'block'; $('[name=code]').focus(); toast('请输入两步验证码'); }
      else fail(err);
    }
  };
}

function topbar(title, sub, actions = '') {
  return `<div class="topbar"><div><h1>${esc(title)}</h1>${sub ? `<div class="sub">${sub}</div>` : ''}</div><span class="spacer"></span>${actions}</div>`;
}
function bind(root, handlers) {
  root.onclick = async (e) => {
    const el = e.target.closest('[data-act]');
    if (!el || !root.contains(el)) return;
    const act = el.dataset.act;
    const holder = el.closest('[data-id]');
    const id = holder ? holder.dataset.id : null;
    if (handlers[act]) { e.preventDefault(); try { await handlers[act](id, el, e); } catch (err) { fail(err); } }
  };
}
function autoRefresh(fn, ms = 10000) {
  clearInterval(refreshTimer);
  refreshTimer = setInterval(() => { if (!document.hidden && !$('.modal-bg') && !$('.menu.open')) fn().catch(() => {}); }, ms);
}
function meter(used, total, label) {
  const p = total > 0 ? Math.min(100, (used / total) * 100) : 0;
  const cls = p > 90 ? 'd' : p > 75 ? 'w' : '';
  return `<div class="meter"><div class="bar ${cls}"><i style="width:${p.toFixed(1)}%"></i></div><span>${label ?? p.toFixed(0) + '%'}</span></div>`;
}

// ============ chart ============
function barChart(points, days) {
  const W = 720, H = 200, P = { l: 52, r: 8, t: 10, b: 24 };
  const now = new Date(); now.setHours(0, 0, 0, 0);
  const buckets = [];
  for (let i = days - 1; i >= 0; i--) { const d = new Date(now); d.setDate(d.getDate() - i); buckets.push({ t: Math.floor(d / 1000), up: 0, down: 0 }); }
  points.forEach((p) => { const b = buckets.find((x) => Math.abs(x.t - p.t) < 43200); if (b) { b.up += p.up; b.down += p.down; } });
  const max = Math.max(1, ...buckets.map((b) => b.up + b.down));
  const cw = (W - P.l - P.r) / buckets.length, bw = Math.max(4, cw * 0.62);
  const y = (v) => H - P.b - (v / max) * (H - P.t - P.b);
  let s = `<svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="流量趋势">`;
  for (let i = 0; i <= 4; i++) { const v = (max * i) / 4, yy = y(v); s += `<line class="axis" x1="${P.l}" x2="${W - P.r}" y1="${yy}" y2="${yy}"/><text x="${P.l - 6}" y="${yy + 3}" text-anchor="end">${fmtBytes(v, 0)}</text>`; }
  buckets.forEach((b, i) => {
    const x = P.l + i * cw + (cw - bw) / 2;
    const yd = y(b.down), yu = y(b.down + b.up);
    s += `<rect x="${x}" y="${yd}" width="${bw}" height="${H - P.b - yd}" fill="var(--accent)" rx="1.5"><title>${fmtDate(b.t)} 下行 ${fmtBytes(b.down)}</title></rect>`;
    s += `<rect x="${x}" y="${yu}" width="${bw}" height="${Math.max(0, yd - yu)}" fill="var(--accent-line)" rx="1.5"><title>${fmtDate(b.t)} 上行 ${fmtBytes(b.up)}</title></rect>`;
    if (buckets.length <= 16 || i % Math.ceil(buckets.length / 10) === 0) { const d = new Date(b.t * 1000); s += `<text x="${x + bw / 2}" y="${H - 8}" text-anchor="middle">${d.getMonth() + 1}/${d.getDate()}</text>`; }
  });
  return s + '</svg>';
}

// ============ pages ============
const PAGES = {};

// ---------- dashboard ----------
PAGES.dashboard = async (el) => {
  const load = async () => {
    const [d, pts] = await Promise.all([api('GET', '/api/dashboard'), api('GET', '/api/traffic?days=14')]);
    const maxN = Math.max(1, ...d.top_nodes.map((x) => x.up + x.down));
    const maxU = Math.max(1, ...d.top_users.map((x) => x.up + x.down));
    el.innerHTML = topbar('概览', `运行 ${fmtUptime(d.uptime)} · 每 10 秒自动刷新`) + `
    <div class="grid g4">
      <div class="card stat"><div class="k">服务器在线</div><div class="v">${d.servers_online}<span class="faint" style="font-size:15px"> / ${d.servers_total}</span></div><div class="s">${d.servers_total - d.servers_online ? `<span class="bad-t">${d.servers_total - d.servers_online} 台离线</span>` : '全部在线'}</div></div>
      <div class="card stat"><div class="k">节点运行</div><div class="v">${d.nodes_online}<span class="faint" style="font-size:15px"> / ${d.nodes_total}</span></div><div class="s">在线连接 ${d.online_users}</div></div>
      <div class="card stat"><div class="k">今日流量</div><div class="v">${fmtBytes(d.today_up + d.today_down)}</div><div class="s">本月 ${fmtBytes(d.month_up + d.month_down)}</div></div>
      <div class="card stat"><div class="k">实时带宽</div><div class="v" style="font-size:19px">↓ ${fmtRate(d.rx_rate)}</div><div class="s">↑ ${fmtRate(d.tx_rate)}</div></div>
      <div class="card stat"><div class="k">用户</div><div class="v">${d.users_active}<span class="faint" style="font-size:15px"> / ${d.users_total}</span></div><div class="s">可用 / 全部（本地用户）</div></div>
      <div class="card stat"><div class="k">IP 风险</div><div class="v ${d.ip_risky ? 'warn-t' : ''}">${d.ip_risky}</div><div class="s">已检测 ${d.ip_checked} 个节点</div></div>
    </div>
    <div class="grid g2 mt" style="grid-template-columns:2fr 1fr">
      <div class="card"><div class="card-h"><h3>近 14 天流量</h3><span class="spacer"></span><div class="legend"><span><i style="background:var(--accent)"></i>下行</span><span><i style="background:var(--accent-line)"></i>上行</span></div></div><div class="card-b">${barChart(pts, 14)}</div></div>
      <div class="card"><div class="card-h"><h3>最近事件</h3><span class="spacer"></span><a href="#/logs" class="faint" style="font-size:12px">全部 →</a></div><div class="card-b events" style="max-height:248px;overflow:auto">
        ${d.events.length ? d.events.map((e) => `<div class="event"><span class="lv ${e.level}"></span><span>${esc(e.message)}</span><time>${ago(e.created_at)}</time></div>`).join('') : '<div class="faint">暂无事件</div>'}</div></div>
    </div>
    <div class="grid g2 mt">
      <div class="card"><div class="card-h"><h3>节点流量排行 · 7 天</h3></div><div class="card-b rank">${d.top_nodes.length ? d.top_nodes.map((x) => `<div class="rank-row"><span>${esc(x.name || '#' + x.id)}</span><span class="num muted">${fmtBytes(x.up + x.down)}</span><div class="bar"><i style="width:${((x.up + x.down) / maxN) * 100}%"></i></div></div>`).join('') : '<div class="faint">暂无数据</div>'}</div></div>
      <div class="card"><div class="card-h"><h3>用户流量排行 · 7 天</h3></div><div class="card-b rank">${d.top_users.length ? d.top_users.map((x) => `<div class="rank-row"><span>${esc(x.name || '#' + x.id)}</span><span class="num muted">${fmtBytes(x.up + x.down)}</span><div class="bar"><i style="width:${((x.up + x.down) / maxU) * 100}%"></i></div></div>`).join('') : '<div class="faint">暂无数据</div>'}</div></div>
    </div>`;
  };
  await load();
  autoRefresh(load);
};

// ---------- servers ----------
function unlockPills(u) {
  if (!u || !u.items) return '<span class="faint">未检测</span>';
  const order = ['ChatGPT', 'Claude', 'Gemini', 'Netflix', 'YouTube Premium', 'Disney+', 'TikTok'];
  return `<div class="unlock" title="检测于 ${fmtTime(u.checked_at)}">${order.filter((k) => u.items[k]).map((k) => {
    const v = u.items[k]; const yes = /^yes|^likely/.test(v), part = /originals|unknown/.test(v);
    const m = v.match(/\(([^)]*)\)/);
    return `<span class="pill ${yes ? 'ok' : part ? 'warn' : 'bad'}" title="${esc(k + ': ' + v)}">${esc(k.replace(' Premium', ''))}${m && m[1] ? ' ' + esc(m[1]) : ''}</span>`;
  }).join('')}</div>`;
}

function serverForm(v = {}) {
  return `<div class="form">
    ${inp('名称', 'name', v.name, { ph: '例如 东京-AWS-01' })}
    ${inp('地区代码', 'region', v.region, { ph: 'JP / US / HK…', hint: '两位国家代码，用于订阅中的国旗' })}
    ${inp('连接地址', 'host', v.host, { ph: '域名或 IP，留空则用 Agent 上报的公网 IP', full: true })}
    ${inp('标签', 'tags', v.tags, { ph: '逗号分隔' })}
    ${inp('服务商', 'provider', v.provider, { ph: 'AWS / 阿里云 / Vultr…' })}
    ${inp('价格', 'price', v.price, { ph: '$5/月' })}
    ${inp('到期日', 'expire_at', toDateInput(v.expire_at), { type: 'date', dtype: 'date' })}
    ${inp('月流量额度 (GB)', 'traffic_limit_gb', v.traffic_limit ? (v.traffic_limit / 1073741824).toFixed(0) : '', { dtype: 'float', type: 'number', ph: '0 = 不限' })}
    ${inp('流量重置日', 'traffic_reset_day', v.traffic_reset_day || 1, { dtype: 'int', type: 'number', hint: '每月几号重置 VPS 流量统计 (1-28)' })}
    ${inp('备注', 'note', v.note, { full: true })}
    ${inp('', 'enabled', v.enabled ?? true, { type: 'checkbox', hint: '启用（关闭后该服务器上的所有节点停止服务）', full: true })}
  </div>`;
}
const serverPayload = (f) => { f.traffic_limit = Math.round((f.traffic_limit_gb || 0) * 1073741824); delete f.traffic_limit_gb; return f; };

function showInstall(res) {
  modal('安装 Agent', `<p style="margin-top:0">在 VPS 上以 root 运行以下命令，Agent 会自动安装 Xray 与 sing-box 并连接到面板：</p>
    <div class="codebox" id="ic">${esc(res.install_command)}</div>
    <div class="btns mt"><button class="btn primary" id="copyIc">${icon('copy')}复制命令</button></div>
    <div class="note mt">令牌只显示这一次。丢失后可在服务器菜单里「重置令牌」。<br>国内 VPS 下载 GitHub 慢时，可在命令前加 <code>GH_PROXY=https://你的镜像/</code>。</div>`, { cancelText: '完成' });
  $('#copyIc').onclick = () => copy(res.install_command);
}

async function importFlow(serverId, reload) {
  const { command_id } = await api('POST', `/api/servers/${serverId}/import/scan`);
  const m = modal('导入现有节点', '<div class="muted">正在让 Agent 扫描这台服务器上已有的节点（约 10 秒）…</div>', { cancelText: '关闭' });
  let res;
  for (let i = 0; i < 40; i++) {
    await new Promise((r) => setTimeout(r, 1500));
    if (!document.body.contains(m.el)) return;
    res = await api('GET', `/api/servers/${serverId}/import/preview?command_id=${command_id}`);
    if (res.status === 'done' || res.status === 'failed') break;
  }
  m.close();
  if (!res || res.status !== 'done') {
    const why = res && res.error ? res.error : '扫描超时，请确认 Agent 在线（服务器页面应显示在线）。';
    return modal('没有可导入的节点', `<p style="margin-top:0"><b>${esc(why)}</b></p>
      <div class="note info">导入功能目前只认识「hysteria2-installer」脚本装出来的节点。这台服务器上没有那个脚本的配置，所以什么都没有导入，节点页面也不会有变化。</div>
      <p class="muted" style="font-size:13px;margin-bottom:0">如果这台上的节点是别的方式装的（x-ui、3x-ui、手写 Xray 等），可以直接在「节点」页面新建，端口被占用时会提示并推荐空闲端口。</p>`, { cancelText: '知道了' });
  }
  const sc = res.scan;
  const users = sc.users || [];
  const body = `<div class="note info" style="margin-bottom:12px">检测到 <b>${esc(sc.kind)}</b>${sc.version ? '（Hysteria ' + esc(sc.version) + '）' : ''}。导入后 NodeHub 用 sing-box 接管，<b>端口、密码、混淆密钥、证书全部沿用</b>，客户端不用改配置；原服务会被停用但文件保留，可随时回滚。</div>
    <div class="grid g2" style="font-size:13px;margin-bottom:12px">
      <div><span class="muted">端口</span><div class="mono">${sc.port}</div></div>
      <div><span class="muted">证书</span><div>${esc({ acme: 'ACME 自动证书', file: '证书文件', self: '自签' }[sc.cert_mode] || sc.cert_mode)} ${esc(sc.domain || '')}</div></div>
      <div><span class="muted">混淆</span><div>${sc.obfs ? 'salamander' : '无'}</div></div>
      <div><span class="muted">端口跳跃</span><div>${esc(sc.hop_ports || '无')}</div></div>
      <div><span class="muted">带宽声明</span><div>↑ ${sc.up_mbps || '不限'} / ↓ ${sc.down_mbps || '不限'} Mbps</div></div>
      <div><span class="muted">正在运行</span><div class="mono" style="font-size:12px">${esc((sc.running || []).join(' ')) || '—'}</div></div>
    </div>
    ${sc.conflict ? `<div class="note" style="margin-bottom:12px">${esc(sc.conflict)}</div>` : ''}
    ${(sc.warnings || []).map((w) => `<div class="note" style="margin-bottom:8px">${esc(w)}</div>`).join('')}
    <div class="tbl-wrap" style="margin-bottom:14px"><table class="tbl"><thead><tr><th>用户</th><th>状态</th><th>已用</th><th>额度</th><th>到期</th><th>设备</th><th></th></tr></thead><tbody>
    ${users.map((u) => `<tr><td>${esc(u.ID)}<br><small class="muted">${esc(u.Note || '')}</small></td><td>${esc(u.Status)}</td><td>${fmtBytes(u.UsedBytes, 1)}</td><td>${u.LimitBytes ? fmtBytes(u.LimitBytes, 0) : '不限'}</td><td>${u.ExpiresAt ? fmtDate(u.ExpiresAt) : '永久'}</td><td>${u.IPLimit || '不限'}</td><td>${u.Exists ? '<span class="pill">已存在，复用</span>' : '<span class="pill ok">新建</span>'}</td></tr>`).join('') || '<tr><td colspan="7" class="faint">没有用户</td></tr>'}</tbody></table></div>
    <div class="form">${inp('节点名称', 'name', '', { ph: '默认：服务器名 Hysteria2' })}${inp('分组', 'groups', '', { ph: '留空 = 所有用户可用' })}
    ${inp('伪装网站', 'masquerade', '', { full: true, ph: '可选，例如 https://www.bing.com' })}</div>
    <p class="muted" style="font-size:12px;margin-bottom:0">注意：原脚本的设备数限制、网页门户、WARP 分流不会迁移；NodeHub 不强制设备数。</p>`;
  modal('确认导入', body, {
    wide: true, okText: '导入并接管',
    ok: async (mm) => {
      const f = readForm(mm);
      const r = await api('POST', `/api/servers/${serverId}/import`, { command_id, ...f });
      toast(`已导入：节点 #${r.node_id}，新建用户 ${r.users_created.length} 个。Agent 下次心跳（约 10 秒）接管`);
      reload && reload();
      setTimeout(() => modal('导入完成', `<p style="margin-top:0">接管命令已下发。几十秒后到「服务器 → 详情与命令记录」查看 <code>takeover</code> 的结果。</p>
        <p>如果客户端连不上，可以一键回滚到原来的服务：</p><div class="btns"><button class="btn danger" id="rbBtn">回滚到原脚本</button></div>`, { cancelText: '关闭' }), 300);
      setTimeout(() => {
        const b = document.getElementById('rbBtn');
        if (b) b.onclick = () => confirmBox('停用导入的节点并恢复原 Hysteria 服务？', async () => {
          await api('POST', `/api/servers/${serverId}/import/rollback`, { node_id: r.node_id }); toast('已下发回滚');
          $$('.modal-bg').forEach((x) => x.remove());
        });
      }, 500);
    },
  });
}


// attach a node that the hysteria2-installer script already runs, without touching the server
async function adoptFlow(serverId, reload) {
  const { command_id } = await api('POST', `/api/servers/${serverId}/import/scan`);
  const m = modal('接入原版脚本节点', '<div class="muted">正在让 Agent 读取这台服务器上脚本的配置（约 10 秒）…</div>', { cancelText: '关闭' });
  let res;
  for (let i = 0; i < 40; i++) {
    await new Promise((r) => setTimeout(r, 1500));
    if (!document.body.contains(m.el)) return;
    res = await api('GET', `/api/servers/${serverId}/import/preview?command_id=${command_id}`);
    if (res.status === 'done' || res.status === 'failed') break;
  }
  m.close();
  if (!res || res.status !== 'done') return modal('没有找到', `<p style="margin-top:0"><b>${esc((res && res.error) || '扫描超时，请确认 Agent 在线')}</b></p>`, { cancelText: '知道了' });
  const sc = res.scan;
  modal('确认接入', `<div class="note info" style="margin-bottom:12px">只把节点信息读进面板用于生成订阅，<b>不会停用、也不会修改服务器上的脚本和 Hysteria 服务</b>。订阅里所有用户共用脚本的主密码。</div>
    <div class="grid g2" style="font-size:13px;margin-bottom:12px">
      <div><span class="muted">端口</span><div class="mono">${sc.port}</div></div>
      <div><span class="muted">证书</span><div>${esc({ acme: 'ACME 自动证书', file: '证书文件', self: '自签' }[sc.cert_mode] || sc.cert_mode)} ${esc(sc.domain || '')}</div></div>
      <div><span class="muted">混淆</span><div>${sc.obfs ? 'salamander' : '无'}</div></div>
      <div><span class="muted">端口跳跃</span><div>${esc(sc.hop_ports || '无')}</div></div></div>
    <div class="form">${inp('节点名称', 'name', '', { ph: '默认：服务器名 Hysteria2' })}${inp('分组', 'groups', '', { ph: '留空 = 所有用户可用' })}</div>`, {
    okText: '接入',
    ok: async (mm) => {
      const f = readForm(mm);
      const r = await api('POST', `/api/servers/${serverId}/script-node/adopt`, { command_id, ...f });
      toast('已接入：节点 #' + r.node_id); reload && reload();
    },
  });
}

PAGES.servers = async (el) => {
  const load = async () => {
    const list = await api('GET', '/api/servers');
    const head = topbar('服务器', `${list.filter((s) => s.online).length} / ${list.length} 在线`, `<button class="btn" data-act="cmdAll">${icon('refresh')}全部解锁检测</button><button class="btn primary" data-act="add">${icon('plus')}添加服务器</button>`);
    if (!list.length) { el.innerHTML = head + `<div class="card empty">还没有服务器。点击右上角「添加服务器」，在 VPS 上运行一条安装命令即可接入。</div>`; return; }
    el.innerHTML = head + `<div class="card tbl-wrap"><table class="tbl"><thead><tr><th>服务器</th><th>状态</th><th>CPU</th><th>内存</th><th>磁盘</th><th>网速</th><th>本期流量</th><th>到期</th><th>Agent / 配置</th><th>流媒体与 AI 解锁</th><th></th></tr></thead><tbody>
    ${list.map((s) => {
      const st = s.status || {};
      const memP = st.mem_total ? st.mem_used / st.mem_total : 0;
      const used = s.month_rx + s.month_tx;
      const days = s.expire_at ? Math.ceil((s.expire_at - Date.now() / 1000) / 86400) : null;
      const cfgOk = !s.apply_error;
      return `<tr data-id="${s.id}">
        <td><div class="cell-2"><b>${flag(s.region)} ${esc(s.name)}</b><small class="mono">${esc(s.public_ipv4 || s.host || '—')}</small><small>${esc(st.os || '')}${st.cpu_cores ? ' · ' + st.cpu_cores + ' 核' : ''}</small></div></td>
        <td><div class="cell-2"><span class="row"><span class="dot ${s.online ? 'on' : s.last_seen ? 'off' : ''}"></span>${s.online ? '在线' : s.last_seen ? '离线' : '未接入'}</span><small>${s.online ? '运行 ' + fmtUptime(st.uptime) : ago(s.last_seen)}</small></div></td>
        <td>${s.online ? meter(st.cpu_usage || 0, 100, (st.cpu_usage || 0).toFixed(0) + '% · 负载 ' + (st.load1 || 0).toFixed(2)) : '—'}</td>
        <td>${s.online ? meter(st.mem_used, st.mem_total, fmtBytes(st.mem_used, 1) + ' / ' + fmtBytes(st.mem_total, 1)) : '—'}</td>
        <td>${s.online ? meter(st.disk_used, st.disk_total, fmtBytes(st.disk_used, 1) + ' / ' + fmtBytes(st.disk_total, 1) + ' · ' + Math.round(st.disk_used / Math.max(1, st.disk_total) * 100) + '%') : '—'}</td>
        <td class="num nowrap">${s.online ? `↓ ${fmtRate(st.net_rx_rate)}<br>↑ ${fmtRate(st.net_tx_rate)}` : '—'}</td>
        <td>${s.traffic_limit ? meter(used, s.traffic_limit, fmtBytes(used, 1) + ' / ' + fmtBytes(s.traffic_limit, 0)) : `<span class="num">${fmtBytes(used, 1)}</span>`}</td>
        <td class="nowrap">${days == null ? '<span class="faint">—</span>' : `<span class="${days <= 3 ? 'bad-t' : days <= 7 ? 'warn-t' : ''}">${fmtDate(s.expire_at)}</span><br><small class="muted">${days} 天</small>`}</td>
        <td><div class="cell-2"><span>${s.agent_version ? 'v' + esc(s.agent_version) : '<span class="faint">—</span>'} · ${s.node_count} 节点</span>
          <small title="${esc(s.apply_error)}" class="${cfgOk ? '' : 'bad-t'}">${s.last_seen ? (cfgOk ? '配置已同步 ' + esc((s.applied_version || '').slice(0, 6)) : '⚠ ' + esc((s.apply_error || '').slice(0, 40))) : ''}</small>
          <small>${st.core_versions ? Object.entries(st.core_versions).filter(([, v]) => v).map(([k, v]) => `${k === 'singbox' ? 'sing-box' : k} ${esc(v)}${st.core_running && st.core_running[k] ? '' : ' (停)'}`).join(' · ') : ''}</small></div></td>
        <td>${unlockPills(s.unlock)}</td>
        <td>${menu([['edit', '编辑'], ['detail', '详情与命令记录'], ['adopt', '接入原版脚本节点'], ['import', '导入现有节点（由 NodeHub 接管）'], ['token', '重置令牌 / 安装命令'], ['cmd:restart_core', '重启内核'], ['cmd:reload', '重新下发配置'], ['cmd:unlock_test', '解锁检测'], ['cmd:upgrade_agent', '升级 Agent'], ['resetTraffic', '重置本期流量'], ['del', '删除', 'danger']])}</td>
      </tr>`;
    }).join('')}</tbody></table></div>`;
  };
  const cmd = (type) => async (id) => { await api('POST', `/api/servers/${id}/command`, { type }); toast('命令已下发，Agent 下次心跳时执行'); };
  bind(el, {
    add: () => modal('添加服务器', serverForm(), { ok: async (m) => { const res = await api('POST', '/api/servers', serverPayload(readForm(m))); await load(); showInstall(res); } }),
    edit: async (id) => {
      const { server } = await api('GET', '/api/servers/' + id);
      modal('编辑服务器', serverForm(server), { ok: async (m) => { await api('PUT', '/api/servers/' + id, serverPayload(readForm(m))); toast('已保存'); load(); } });
    },
    token: (id) => confirmBox('重置后旧令牌立即失效，需要在 VPS 上用新命令重新安装（或修改 /etc/nodehub/agent.json）。继续？', async () => { showInstall(await api('POST', `/api/servers/${id}/token`)); }),
    'cmd:restart_core': cmd('restart_core'), 'cmd:reload': cmd('reload'), 'cmd:unlock_test': cmd('unlock_test'), 'cmd:upgrade_agent': cmd('upgrade_agent'),
    cmdAll: async () => { await api('POST', '/api/servers/0/command', { type: 'unlock_test' }); toast('已向全部服务器下发解锁检测'); },
    resetTraffic: (id) => confirmBox('将本期流量统计清零？', async () => { await api('POST', `/api/servers/${id}/reset-traffic`); load(); }),
    del: (id) => confirmBox('删除服务器会同时删除其上所有节点，且无法恢复。确定删除？', async () => { await api('DELETE', '/api/servers/' + id); toast('已删除'); load(); }, '删除'),
    import: (id) => importFlow(id, load),
    adopt: (id) => adoptFlow(id, load),
    detail: async (id) => {
      const [{ server: s, nodes }, cmds] = await Promise.all([api('GET', '/api/servers/' + id), api('GET', `/api/servers/${id}/commands`)]);
      const st = s.status || {};
      modal(s.name, `<div class="grid g2"><div><b>系统</b><div class="muted" style="font-size:13px">${esc(st.os)}<br>${esc(st.kernel)} · ${esc(st.arch)}<br>${esc(st.cpu_model)}<br>TCP ${st.tcp_conns ?? '—'} · UDP ${st.udp_conns ?? '—'}<br>IPv4 ${esc(s.public_ipv4 || '—')}<br>IPv6 ${esc(s.public_ipv6 || '—')}</div></div>
        <div><b>节点</b><div class="muted" style="font-size:13px">${nodes.length ? nodes.map((n) => `${esc(n.name)} · ${n.protocol}:${n.port} ${n.enabled ? '' : '(停用)'}`).join('<br>') : '无'}</div></div></div>
        ${s.apply_error ? `<div class="note mt"><b>配置错误：</b>${esc(s.apply_error)}</div>` : ''}
        <h4 style="margin:18px 0 8px">命令记录</h4><div class="tbl-wrap"><table class="tbl"><thead><tr><th>时间</th><th>命令</th><th>状态</th><th>输出</th></tr></thead><tbody>
        ${cmds.length ? cmds.map((c) => `<tr><td class="nowrap">${fmtTime(c.created_at)}</td><td>${esc(c.type)}</td><td><span class="pill ${c.status === 'done' ? 'ok' : c.status === 'failed' ? 'bad' : ''}">${c.status}</span></td><td class="mono" style="max-width:360px;word-break:break-all">${esc((c.output || '').slice(0, 400))}</td></tr>`).join('') : '<tr><td colspan="4" class="faint">无</td></tr>'}</tbody></table></div>`, { wide: true, cancelText: '关闭' });
    },
  });
  await load();
  autoRefresh(load);
};

// ---------- nodes ----------
const PROTOS = ['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'anytls'];
const CORES = { vless: ['xray', 'singbox'], vmess: ['xray', 'singbox'], trojan: ['xray', 'singbox'], shadowsocks: ['xray', 'singbox'], hysteria2: ['singbox'], tuic: ['singbox'], anytls: ['singbox'] };
const SS_CIPHERS = ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305', 'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305'];
const protoLabel = (n) => {
  const s = n.settings || {};
  const parts = [n.protocol];
  if (['vless', 'vmess', 'trojan'].includes(n.protocol)) { parts.push(s.network || 'tcp'); if (s.security && s.security !== 'none') parts.push(s.security); }
  if (n.protocol === 'shadowsocks') parts.push((s.cipher || '').replace('2022-blake3-', '2022-'));
  if (s.hop_ports) parts.push('跳跃 ' + s.hop_ports);
  if (s.cert_mode === 'acme') parts.push('ACME');
  return parts.join(' · ');
};

function nodeForm(n, servers, panels) {
  const s = n.settings || {};
  const srvOpts = servers.map((v) => [v.id, `${v.name}${v.public_ipv4 ? ' (' + v.public_ipv4 + ')' : ''}`]);
  const panelOpts = [[0, '— 选择面板 —'], ...panels.map((p) => [p.id, `${p.name} (${p.type})`])];
  return `<div class="form" id="nodeForm">
    <h4 style="border:0;padding:0;margin-top:0">基本</h4>
    ${inp('节点名称', 'name', n.name, { ph: '例如 东京 01' })}
    ${inp('服务器', 'server_id', n.server_id, { opts: srvOpts, dtype: 'int' })}
    ${inp('协议', 'protocol', n.protocol || 'vless', { opts: PROTOS })}
    ${inp('内核', 'core', n.core || '', { opts: [['', '自动'], ['xray', 'Xray'], ['singbox', 'sing-box']] })}
    ${inp('监听端口', 'port', n.port || '', { type: 'number', dtype: 'int', ph: '留空自动选空闲端口', hint: '<span id="portHint"></span>' })}
    ${inp('监听地址', 'listen', n.listen, { ph: '默认 0.0.0.0（全部）' })}
    ${inp('客户端连接地址', 'address', n.address, { ph: '默认用服务器地址；可填 CDN/中转域名', hint: '写进订阅的地址' })}
    ${inp('检测 IP', 'egress_ip', n.egress_ip, { ph: '默认用服务器公网 IP', hint: '多 IP / 落地机时填出口 IP' })}

    <h4 data-when="proto:vless,vmess,trojan">传输与安全</h4>
    ${inp('传输方式', 'settings.network', s.network || 'tcp', { opts: [['tcp', 'TCP (RAW)'], ['ws', 'WebSocket'], ['grpc', 'gRPC'], ['xhttp', 'XHTTP（仅 Xray）'], ['httpupgrade', 'HTTPUpgrade']], when: 'proto:vless,vmess,trojan' })}
    ${inp('安全', 'settings.security', s.security || 'none', { opts: [['none', '无'], ['tls', 'TLS'], ['reality', 'REALITY']], when: 'proto:vless,vmess,trojan' })}
    ${inp('Flow', 'settings.flow', s.flow || '', { opts: [['', '无'], ['xtls-rprx-vision', 'xtls-rprx-vision']], when: 'proto:vless;net:tcp;sec:tls,reality' })}
    ${inp('路径 Path', 'settings.path', s.path, { ph: '/', when: 'proto:vless,vmess,trojan;net:ws,xhttp,httpupgrade' })}
    ${inp('Host', 'settings.host', s.host, { when: 'proto:vless,vmess,trojan;net:ws,xhttp,httpupgrade' })}
    ${inp('gRPC ServiceName', 'settings.service_name', s.service_name, { when: 'proto:vless,vmess,trojan;net:grpc' })}

    ${inp('REALITY 目标 (dest)', 'settings.reality_dest', s.reality_dest || 'www.cloudflare.com:443', { when: 'sec:reality;proto:vless,trojan', hint: '被借用证书的网站，需支持 TLS1.3 + H2。<b>不要用 www.microsoft.com</b>（在 AWS 上握手失败，连接会被断开），推荐 www.cloudflare.com 或 www.apple.com' })}
    ${inp('REALITY serverNames', 'settings.reality_server_name', s.reality_server_name, { when: 'sec:reality;proto:vless,trojan', ph: '默认取 dest 的域名' })}
    ${inp('REALITY 私钥', 'settings.reality_private_key', s.reality_private_key, { when: 'sec:reality;proto:vless,trojan', ph: '留空自动生成', full: true })}
    ${inp('REALITY 公钥', 'settings.reality_public_key', s.reality_public_key, { when: 'sec:reality;proto:vless,trojan', attrs: 'readonly', ph: '保存后自动计算' })}
    ${inp('Short ID', 'settings.reality_short_id', s.reality_short_id, { when: 'sec:reality;proto:vless,trojan', ph: '留空自动生成' })}

    ${inp('SNI', 'settings.sni', s.sni, { when: 'tlsish', ph: 'hy2/tuic 默认 www.bing.com' })}
    ${inp('ALPN', 'settings.alpn', s.alpn, { when: 'tlsish', ph: '逗号分隔，留空用默认' })}
    ${inp('证书', 'settings.cert_mode', s.cert_mode || 'self', { opts: [['self', '自签证书（客户端需允许不安全）'], ['acme_dns', 'ACME · DNS 验证（Cloudflare，推荐，不占端口，仅 sing-box）'], ['acme', 'ACME · HTTP 验证（需 80 端口空闲，仅 sing-box）'], ['file', '使用服务器上的证书文件']], when: 'tlsish' })}
    ${inp('ACME 邮箱', 'settings.acme_email', s.acme_email, { when: 'tlsish;cert:acme,acme_dns', hint: '<span id="acmeHint">SNI 填你的域名。DNS 验证需先在「设置 → 证书」填 Cloudflare 令牌；HTTP 验证需要 80 端口空闲且域名解析到本机。</span>' })}
    ${inp('证书路径', 'settings.cert_file', s.cert_file, { when: 'tlsish;cert:file', ph: '/etc/ssl/xxx/fullchain.pem' })}
    ${inp('私钥路径', 'settings.key_file', s.key_file, { when: 'tlsish;cert:file', ph: '/etc/ssl/xxx/privkey.pem' })}
    ${inp('uTLS 指纹', 'settings.fingerprint', s.fingerprint || 'chrome', { opts: ['chrome', 'firefox', 'safari', 'ios', 'edge', 'random'], when: 'proto:vless,vmess,trojan;sec:tls,reality' })}

    <h4 data-when="proto:shadowsocks">Shadowsocks</h4>
    ${inp('加密方式', 'settings.cipher', s.cipher || '2022-blake3-aes-128-gcm', { opts: SS_CIPHERS, when: 'proto:shadowsocks' })}
    ${inp('服务端密钥', 'settings.server_key', s.server_key, { when: 'proto:shadowsocks', ph: '2022 加密留空自动生成' })}

    <h4 data-when="proto:hysteria2,tuic">QUIC 参数</h4>
    ${inp('上行带宽 Mbps', 'settings.up_mbps', s.up_mbps || '', { type: 'number', dtype: 'int', when: 'proto:hysteria2', ph: '0 = 不限（BBR）' })}
    ${inp('下行带宽 Mbps', 'settings.down_mbps', s.down_mbps || '', { type: 'number', dtype: 'int', when: 'proto:hysteria2', ph: '0 = 不限' })}
    ${inp('混淆', 'settings.obfs', s.obfs || '', { opts: [['', '无'], ['salamander', 'salamander']], when: 'proto:hysteria2' })}
    ${inp('混淆密码', 'settings.obfs_password', s.obfs_password, { when: 'proto:hysteria2' })}
    ${inp('端口跳跃区间', 'settings.hop_ports', s.hop_ports, { when: 'proto:hysteria2', ph: '例如 20000-40000，留空关闭', hint: '只转发发往本机的 UDP，不影响用户访问外部的 UDP' })}
    ${inp('伪装网站', 'settings.masquerade', s.masquerade, { when: 'proto:hysteria2', ph: 'https://www.bing.com，留空不伪装', hint: '非 Hysteria 的 HTTP/3 探测会看到这个网站' })}
    ${inp('拥塞控制', 'settings.congestion', s.congestion || 'bbr', { opts: ['bbr', 'cubic', 'new_reno'], when: 'proto:tuic' })}

    <h4>用户来源</h4>
    ${inp('用户来源', 'source', n.source || 'local', { opts: [['local', '本地用户（本系统 / 开放 API 创建的用户）'], ['panel', '对接面板（Xboard / V2Board / SSPanel）']], full: true })}
    ${inp('分组', 'groups', n.groups, { when: 'src:local', ph: '逗号分隔；留空 = 所有用户可用', hint: '用户分组与节点分组有交集才能使用该节点' })}
    ${inp('流量倍率', 'rate', n.rate ?? 1, { type: 'number', dtype: 'float', when: 'src:local', attrs: 'step="0.1"' })}
    ${inp('面板', 'panel_id', n.panel_id || 0, { opts: panelOpts, dtype: 'int', when: 'src:panel' })}
    ${inp('面板节点 ID', 'panel_node_id', n.panel_node_id || '', { type: 'number', dtype: 'int', when: 'src:panel' })}
    ${inp('面板节点类型', 'panel_node_type', n.panel_node_type || '', { when: 'src:panel', ph: '留空自动：vless/vmess/trojan/shadowsocks/hysteria/tuic/anytls' })}
    ${inp('', 'panel_sync_config', n.panel_sync_config, { type: 'checkbox', hint: '从面板同步端口和协议参数（Xboard/V2Board）', when: 'src:panel' })}

    <h4>其他</h4>
    ${inp('单用户限速 Mbps', 'speed_limit', n.speed_limit || '', { type: 'number', dtype: 'int', ph: '0 = 不限', hint: '下发给内核与面板；Xray/sing-box 原生不做按用户限速' })}
    ${inp('设备数限制', 'device_limit', n.device_limit || '', { type: 'number', dtype: 'int', ph: '0 = 不限' })}
    ${inp('排序', 'sort', n.sort || 0, { type: 'number', dtype: 'int' })}
    ${inp('备注', 'note', n.note)}
    ${inp('', 'enabled', n.enabled ?? true, { type: 'checkbox', hint: '启用', full: true })}
  </div>`;
}

function nodeTransports(proto) {
  return proto === 'hysteria2' || proto === 'tuic' ? 'udp' : proto === 'shadowsocks' ? 'tcp,udp' : 'tcp';
}

function wireNodeForm(m, nodeId, isNew) {
  const f = $('#nodeForm', m);
  const val = (k) => ($(`[name="${k}"]`, f) || {}).value;
  let portTimer;
  const checkPort = async (autofill) => {
    const sid = val('server_id'), box = $('#portHint', f), ah = $('#acmeHint', f);
    if (!sid || !box) return;
    try {
      const portEl = $('[name=port]', f);
      const want = autofill ? 0 : Number(portEl.value) || 0;
      const r = await api('GET', `/api/servers/${sid}/ports?transport=${nodeTransports(val('protocol'))}&want=${want}&self=${nodeId || 0}`);
      if (!r.known) { box.textContent = '（这台服务器的 Agent 还没上报端口，升级 Agent 后可自动检测占用）'; box.style.color = ''; return; }
      if (autofill || !want) { if (!portEl.value && r.suggest) { portEl.value = r.suggest; box.textContent = '✓ 已自动选择空闲端口 ' + r.suggest; box.style.color = 'var(--ok, #2f855a)'; } return; }
      if (r.busy) { box.innerHTML = `⚠ 端口 ${want} 已被「${esc(r.proc)}」占用。<a href="#" data-usep="${r.suggest}">改用 ${r.suggest}</a>`; box.style.color = 'var(--bad, #c53030)'; }
      else { box.textContent = '✓ 端口 ' + want + ' 空闲'; box.style.color = 'var(--ok, #2f855a)'; }
      if (ah) ah.dataset.p80 = r.port80_busy ? r.port80_proc : '';
      acmeNote();
    } catch (e) { /* hint only */ }
  };
  const acmeNote = () => {
    const ah = $('#acmeHint', f); if (!ah) return;
    if (val('settings.cert_mode') === 'acme' && ah.dataset.p80) { ah.innerHTML = `⚠ 80 端口被「${esc(ah.dataset.p80)}」占用，HTTP 验证会失败，请改用 <b>DNS 验证</b>。`; ah.style.color = 'var(--bad, #c53030)'; }
  };
  f.addEventListener('click', (e) => { const a = e.target.closest('[data-usep]'); if (a) { e.preventDefault(); $('[name=port]', f).value = a.dataset.usep; checkPort(); } });
  f.addEventListener('input', (e) => { if (e.target.name === 'port') { clearTimeout(portTimer); portTimer = setTimeout(() => checkPort(), 400); } });
  f.addEventListener('change', (e) => { if (['server_id', 'protocol', 'settings.cert_mode'].includes(e.target.name)) checkPort(isNew && !val('port')); });
  setTimeout(() => checkPort(isNew && !val('port')), 0);
  const apply = () => {
    const ctx = { proto: val('protocol'), net: val('settings.network'), sec: val('settings.security'), src: val('source'), cert: val('settings.cert_mode') };
    const tlsish = ['hysteria2', 'tuic', 'anytls'].includes(ctx.proto) || (['vless', 'vmess', 'trojan'].includes(ctx.proto) && ctx.sec === 'tls');
    $$('[data-when]', f).forEach((el) => {
      const show = el.dataset.when.split(';').every((cond) => {
        if (cond === 'tlsish') return tlsish;
        const [k, vs] = cond.split(':');
        return vs.split(',').includes(ctx[k]);
      });
      el.style.display = show ? '' : 'none';
    });
    const core = $('[name=core]', f);
    const allowed = CORES[ctx.proto] || [];
    [...core.options].forEach((o) => { o.disabled = o.value && !allowed.includes(o.value); });
    if (core.value && !allowed.includes(core.value)) core.value = '';
    const netSel = $('[name="settings.network"]', f);
    [...netSel.options].forEach((o) => { o.disabled = o.value === 'xhttp' && core.value === 'singbox'; });
  };
  f.addEventListener('change', apply);
  apply();
}

function shareModal(n) {
  modal('节点信息 · ' + n.name, `<div class="grid g2" style="font-size:13px">
    <div><span class="muted">连接地址</span><div class="mono">${esc(n.connect_addr)}:${n.port}</div></div>
    <div><span class="muted">协议</span><div>${esc(protoLabel(n))} · ${n.core === 'singbox' ? 'sing-box' : 'Xray'}</div></div>
    ${n.settings.reality_public_key ? `<div class="full" style="grid-column:1/-1"><span class="muted">REALITY 公钥 / Short ID</span><div class="mono">${esc(n.settings.reality_public_key)} / ${esc(n.settings.reality_short_id)}</div></div>` : ''}
    ${n.settings.server_key ? `<div style="grid-column:1/-1"><span class="muted">SS 服务端密钥</span><div class="mono">${esc(n.settings.server_key)}</div></div>` : ''}
    </div><div class="note info mt">用户的分享链接与订阅在「用户」页面获取；面板对接节点由面板生成订阅。</div>`, { cancelText: '关闭' });
}

function ipSummary(c) {
  if (!c) return '<span class="faint">未检测</span>';
  if (c.error) return `<span class="pill bad" title="${esc(c.error)}">检测失败</span>`;
  const risks = [c.is_proxy && '代理', c.is_vpn && 'VPN', c.is_abuse && '滥用', c.is_tor && 'Tor'].filter(Boolean);
  return `<div class="row wrap" style="gap:4px">${c.native ? `<span class="pill ok">原生·${esc(cn(c.geo_country))}</span>` : `<span class="pill warn">广播</span>`}${risks.length ? `<span class="pill bad">${risks.join('/')}</span>` : ''}<span class="score ${c.fraud_score >= 70 ? 'hi' : c.fraud_score >= 30 ? 'mid' : 'lo'}">${c.fraud_score}</span></div>`;
}


// ---------- script nodes: run the hysteria2-installer script on a VPS ----------
async function scriptFlow(servers, reload) {
  const online = servers.filter((s) => s.online);
  if (!online.length) return toast('没有在线的服务器，请先让 Agent 连上面板', true);
  const body = `<div class="note info" style="margin-bottom:12px">在所选服务器上以 root 运行你的 <b>hysteria2-installer</b> 原版脚本（免交互），装好后自动收进面板，由脚本自己的 Hysteria 服务运行，NodeHub 不再起内核。每台服务器装一份。</div>
    <div class="form">
    ${inp('服务器', 'server_id', online[0].id, { opts: online.map((s) => [s.id, s.name + (s.public_ipv4 ? ' · ' + s.public_ipv4 : '')]), dtype: 'int', full: true })}
    ${inp('节点名称', 'name', '', { ph: '默认：服务器名 Hysteria2' })}
    ${inp('分组', 'groups', '', { ph: '留空 = 所有用户可用' })}
    ${inp('端口（UDP）', 'port', '', { dtype: 'int', ph: '留空自动选一个空闲端口' })}
    ${inp('证书', 'cert_type', '1', { opts: [['1', '自签名（无需域名，客户端跳过证书校验）'], ['3', '域名证书（Let\'s Encrypt 自动申请）']], dtype: 'int' })}
    ${inp('域名', 'domain', '', { ph: '仅域名证书需要，例如 hy2.example.com', hint: '域名必须已解析到这台服务器，且安全组放行 TCP 80' })}
    ${inp('证书邮箱', 'email', '', { ph: '可选' })}
    </div>`;
  modal('添加节点（原版脚本 Hysteria2）', body, {
    wide: true, okText: '开始安装',
    ok: async (mm) => {
      const f = readForm(mm);
      if (f.cert_type === 3 && !f.domain) throw new Error('选择域名证书时必须填写域名');
      const r = await api('POST', `/api/servers/${f.server_id}/script-node`, { port: f.port || 0, cert_type: f.cert_type, domain: f.domain, email: f.email, name: f.name, groups: f.groups });
      scriptProgress(f.server_id, r.command_id, r.port, f, reload);
    },
  });
}
function scriptProgress(serverId, cmdId, port, f, reload) {
  const m = modal('正在安装…', `<div class="muted" id="spMsg">已下发给 Agent，正在下载并运行脚本，通常 1–3 分钟（域名证书可能更久）。可以关闭这个窗口：安装会在服务器上继续，装好后节点自动出现在列表里。</div>
    <pre class="codebox mt" id="spLog" style="display:none;max-height:260px;overflow:auto;white-space:pre-wrap"></pre>`, { cancelText: '关闭' });
  (async () => {
    for (let i = 0; i < 300; i++) {
      await new Promise((r) => setTimeout(r, 4000));
      if (!document.body.contains(m.el)) return;
      let list;
      try { list = await api('GET', `/api/servers/${serverId}/commands`); } catch (e) { continue; }
      const c = (list || []).find((x) => x.id === cmdId);
      if (!c || c.status === 'pending' || c.status === 'sent') continue;
      if (c.status === 'failed') {
        $('#spMsg', m.el).innerHTML = '<b class="bad-t">安装失败</b>';
        const l = $('#spLog', m.el); l.style.display = ''; l.textContent = c.output || '';
        return;
      }
      try {
        const r = await api('POST', `/api/servers/${serverId}/script-node/finish`, { command_id: cmdId, name: f.name, groups: f.groups });
        m.close(); reload && reload();
        modal('节点已创建', `<p style="margin-top:0">脚本已装好，节点 #${r.node_id} 已加入面板。</p>
          <div class="note">请在云厂商的<b>安全组 / 防火墙</b>放行：<br>· UDP ${port}（主端口）<br>· UDP 20000-40000（端口跳跃，不放行就把节点里的「端口跳跃」清空）<br>${f.cert_type === 3 ? '· TCP 80（证书续期）<br>' : ''}</div>`, { cancelText: '知道了' });
      } catch (e) { $('#spMsg', m.el).innerHTML = '<b class="bad-t">脚本已装好，但收进面板失败：</b>' + esc(e.message || String(e)); }
      return;
    }
    if (document.body.contains(m.el)) $('#spMsg', m.el).textContent = '等待超时。请到「服务器 → 详情与命令记录」查看 install_hy2 的结果。';
  })();
}
async function scriptEdit(n, reload) {
  modal('编辑节点（原版脚本）', `<div class="form">${inp('节点名称', 'name', n.name)}${inp('分组', 'groups', n.groups || '')}
    ${inp('倍率', 'rate', n.rate, { dtype: 'float' })}
    ${inp('端口跳跃', 'hop_ports', n.settings.hop_ports || '', { ph: '例如 20000-40000，清空 = 订阅里不带跳跃', hint: '只影响订阅内容；服务器上的跳跃规则由脚本管理' })}
    ${inp('伪装 / 带宽等', 'info', `端口 ${n.port}/UDP · 证书 ${n.settings.cert_mode} · SNI ${n.settings.sni}`, { attrs: 'disabled', full: true })}</div>
    <p class="muted" style="font-size:12px;margin-bottom:0">端口、证书、密码由原版脚本管理。要改它们，请登录服务器运行脚本菜单（<code>bash install.sh</code>），改完在服务器页面「导入现有节点」重新扫描。</p>`, {
    ok: async (mm) => {
      const f = readForm(mm);
      n.name = f.name; n.groups = f.groups; n.rate = f.rate || 1; n.settings.hop_ports = f.hop_ports;
      await api('PUT', '/api/nodes/' + n.id, n); toast('已保存'); reload && reload();
    },
  });
}
function scriptDelete(id, reload) {
  const m = modal('删除脚本节点', `<p style="margin-top:0">选择删除方式：</p>
    <div class="btns" style="flex-direction:column;align-items:stretch;gap:8px">
      <button class="btn" data-d="keep">只从面板删除（服务器上的 Hysteria 继续运行）</button>
      <button class="btn danger" data-d="un">同时在服务器上卸载（运行脚本的卸载功能，节点会失效）</button></div>`, { cancelText: '取消' });
  m.el.addEventListener('click', async (e) => {
    const b = e.target.closest('[data-d]'); if (!b) return;
    try { await api('DELETE', '/api/nodes/' + id + (b.dataset.d === 'un' ? '?uninstall=1' : '')); toast('已删除'); m.close(); reload && reload(); } catch (err) { fail(err); }
  });
}

PAGES.nodes = async (el) => {
  let servers = [], panels = [];
  const filter = { q: store.get('nodes_q', '') };
  const load = async () => {
    const [list, sv, pv] = await Promise.all([api('GET', '/api/nodes'), api('GET', '/api/servers'), api('GET', '/api/panels')]);
    servers = sv; panels = pv;
    const q = filter.q.toLowerCase();
    const rows = list.filter((n) => !q || [n.name, n.server_name, n.protocol, n.connect_addr, String(n.port), n.groups].join(' ').toLowerCase().includes(q));
    el.innerHTML = topbar('节点', `${list.filter((n) => n.enabled && n.server_online).length} / ${list.length} 运行中`,
      `<input class="inp search" id="nq" placeholder="搜索名称 / 服务器 / 端口" value="${esc(filter.q)}"><button class="btn" data-act="addAdv">高级节点</button><button class="btn primary" data-act="add">${icon('plus')}添加节点</button>`) +
      (!list.length ? `<div class="card empty">${servers.length ? '还没有节点，点击「添加节点」。' : '请先在「服务器」页面添加一台服务器。'}</div>` :
      `<div class="card tbl-wrap"><table class="tbl"><thead><tr><th>节点</th><th>服务器</th><th>协议</th><th>地址</th><th>用户</th><th>在线</th><th>累计流量</th><th>IP 质量</th><th>状态</th><th></th></tr></thead><tbody>
      ${rows.map((n) => `<tr data-id="${n.id}">
        <td><div class="cell-2"><b>${esc(n.name)}</b><small>${n.source === 'panel' ? `面板 · ${esc(n.panel_name || '')} #${n.panel_node_id}` : `本地${n.groups ? ' · ' + esc(n.groups) : ''}${n.rate !== 1 ? ' · ×' + n.rate : ''}`}</small></div></td>
        <td><span class="row"><span class="dot ${n.server_online ? 'on' : 'off'}"></span>${esc(n.server_name)}</span></td>
        <td><div class="cell-2"><span>${esc(protoLabel(n))}</span><small>${n.core === 'singbox' ? 'sing-box' : n.core === 'script' ? '原版脚本' : 'Xray'}</small></div></td>
        <td class="mono">${esc(n.connect_addr)}:${n.port}</td>
        <td class="num">${n.user_count}</td>
        <td class="num">${n.online_users}</td>
        <td class="num nowrap">↑ ${fmtBytes(n.up_total, 1)}<br>↓ ${fmtBytes(n.down_total, 1)}</td>
        <td>${ipSummary(n.ip_check)}</td>
        <td>${n.enabled ? '<span class="pill ok">启用</span>' : '<span class="pill">停用</span>'}</td>
        <td><div class="row" style="gap:4px"><button class="btn sm" data-act="edit">编辑</button>${menu([['info', '连接信息'], ['toggle', n.enabled ? '停用' : '启用'], ['online', '在线 IP'], ['ipcheck', '检测 IP 质量'], ['copyNode', '复制节点'], n.source === 'panel' && ['psync', '立即同步面板'], ['del', '删除', 'danger']])}</div></td>
      </tr>`).join('')}</tbody></table></div>`);
    const nq = $('#nq');
    if (nq) nq.oninput = () => { filter.q = nq.value; store.set('nodes_q', nq.value); clearTimeout(nq._t); nq._t = setTimeout(async () => { await load(); const x = $('#nq'); x.focus(); x.setSelectionRange(x.value.length, x.value.length); }, 250); };
    PAGES.nodes._list = list;
  };
  const find = (id) => PAGES.nodes._list.find((n) => String(n.id) === String(id));
  const save = (id) => async (m) => {
    const body = readForm(m);
    if (!body.core) delete body.core;
    const url = id ? '/api/nodes/' + id : '/api/nodes';
    let r;
    try { r = await api(id ? 'PUT' : 'POST', url, body); }
    catch (e) {
      if (!/已被服务器上的|需要 80 端口/.test(e.message || '')) throw e;
      const go = await new Promise((res) => { const onEsc = (ev) => { if (ev.key === 'Escape') { document.removeEventListener('keydown', onEsc); res(false); } }; document.addEventListener('keydown', onEsc); const d = modal('端口被占用', `<p style="margin:0">${esc(e.message)}</p>`, { ok: async () => { res(true); }, okText: '仍然保存', cancelText: '返回修改' }); d.el.addEventListener('click', (ev) => { if (ev.target.closest('[data-x]') || ev.target === d.el) res(false); }); });
      if (!go) return false;
      r = await api(id ? 'PUT' : 'POST', url + '?force=1', body);
    }
    toast(id ? '已保存，配置将在 10 秒内下发' : '节点已创建'); await load();
    if (!id) shareModal({ ...r, connect_addr: (find(r.id) || {}).connect_addr || '' });
  };
  bind(el, {
    add: () => {
      if (!servers.length) return toast('请先添加服务器', true);
      scriptFlow(servers, load);
    },
    addAdv: () => {
      if (!servers.length) return toast('请先添加服务器', true);
      const m = modal('添加节点（NodeHub 内核：Xray / sing-box）', nodeForm({ server_id: servers[0].id }, servers, panels), { ok: save(null), wide: true, okText: '创建' });
      wireNodeForm(m.el, 0, true);
    },
    edit: async (id) => { const n = await api('GET', '/api/nodes/' + id); if (n.core === 'script') return scriptEdit(n, load); const m = modal('编辑节点', nodeForm(n, servers, panels), { ok: save(id), wide: true }); wireNodeForm(m.el, id, false); },
    info: (id) => shareModal(find(id)),
    toggle: async (id) => { await api('POST', `/api/nodes/${id}/toggle`); load(); },
    copyNode: async (id) => { const r = await api('POST', `/api/nodes/${id}/copy`, {}); toast(`已复制为「${r.name}」（端口 ${r.port}，默认停用）`); load(); },
    psync: async (id) => { const r = await api('POST', `/api/nodes/${id}/panel-sync`); toast(`同步完成，${r.users} 个用户`); load(); },
    ipcheck: async (id, b) => { toast('检测中，约需 10 秒…'); await api('POST', `/api/nodes/${id}/ipcheck`); toast('检测完成'); load(); },
    online: async (id) => {
      const list = await api('GET', `/api/nodes/${id}/online`);
      modal('在线 IP（5 分钟内）', list.length ? `<div class="tbl-wrap"><table class="tbl"><thead><tr><th>用户标识</th><th>IP</th><th>最后活跃</th></tr></thead><tbody>${list.map((o) => `<tr><td class="mono">${esc(o.user_key)}</td><td class="mono">${o.ip === '-' ? '<span class="faint">sing-box 不提供 IP</span>' : esc(o.ip)}</td><td>${ago(o.last_seen)}</td></tr>`).join('')}</tbody></table></div>` : '<div class="faint">暂无在线用户</div>', { cancelText: '关闭' });
    },
    del: (id) => { const n = find(id); if (n && n.core === 'script') return scriptDelete(id, load); confirmBox('确定删除该节点？', async () => { await api('DELETE', '/api/nodes/' + id); toast('已删除'); load(); }, '删除'); },
  });
  await load();
  autoRefresh(load, 15000);
};

// ---------- IP quality ----------
const CONN = { datacenter: ['机房', 'dc'], residential: ['家宽', 'home'], mobile: ['移动', 'phone'], business: ['企业', 'biz'], unknown: ['未知', 'dc'] };
const ipcURL = (id) => (String(id).startsWith('s') ? `/api/servers/${String(id).slice(1)}/ipcheck` : `/api/nodes/${id}/ipcheck`);
PAGES.ipq = async (el) => {
  let tab = store.get('ipq_tab', 'all');
  const load = async () => {
    const { items, running } = await api('GET', '/api/ipchecks');
    const done = items.filter((r) => r.check && !r.check.error);
    const risky = (c) => c.is_proxy || c.is_vpn || c.is_tor || c.is_abuse || c.fraud_score >= 70;
    const tabs = [
      ['all', '全部', items], ['native', '原生', done.filter((r) => r.check.native)], ['bcast', '广播', done.filter((r) => !r.check.native)],
      ['dual', '双 ISP', done.filter((r) => r.check.dual_isp)], ['risk', '有风险', done.filter((r) => risky(r.check))], ['none', '未检测', items.filter((r) => !r.check || r.check.error)],
    ];
    const rows = (tabs.find((t) => t[0] === tab) || tabs[0])[2];
    el.innerHTML = topbar('IP 质量', '原生/广播、连接类型、双 ISP、风险标记与欺诈分，多数据源聚合' + (running ? ' · <span class="warn-t">检测进行中…</span>' : ''),
      `<button class="btn primary" data-act="runAll" ${running ? 'disabled' : ''}>${icon('refresh')}全部检测</button>`) +
      `<div class="tabs" style="margin-bottom:12px">${tabs.map(([k, l, arr]) => `<button data-act="tab" data-tab="${k}" class="${tab === k ? 'on' : ''}">${l}<span class="c">${arr.length}</span></button>`).join('')}</div>
      <div class="card tbl-wrap"><table class="tbl"><thead><tr><th>服务器 / IP</th><th>原生 IP</th><th>连接类型</th><th>双 ISP</th><th>风险标记</th><th>欺诈分</th><th>解锁（从该服务器访问）</th><th>ASN / 归属</th><th>检测时间</th><th></th></tr></thead><tbody>
      ${rows.length ? rows.map((r) => {
        const c = r.check;
        if (!c || c.error) return `<tr data-id="${r.node_id || 's' + r.server_id}"><td><div class="cell-2"><b>${esc(r.node_name)}</b><small class="mono">${esc(r.ip || '—')}</small></div></td><td colspan="8" class="${c ? 'bad-t' : 'faint'}">${c ? '检测失败：' + esc(c.error.slice(0, 120)) : '未检测'}</td><td><button class="btn icon sm" data-act="check" title="检测" aria-label="检测">${icon('refresh')}</button></td></tr>`;
        const risks = [[c.is_proxy, '代理'], [c.is_vpn, 'VPN'], [c.is_abuse, '滥用'], [c.is_tor, 'Tor']].filter((x) => x[0]);
        const [ct, ci] = CONN[c.conn_type] || CONN.unknown;
        return `<tr data-id="${r.node_id || 's' + r.server_id}">
          <td><div class="cell-2"><b>${esc(r.node_name)}</b><small class="mono" title="${esc((r.nodes || []).join('、'))}">${esc(c.ip)}</small></div></td>
          <td>${c.native ? `<span class="pill ok">${icon('pin')} 原生 · ${esc(cn(c.geo_country))}</span>` : `<div class="cell-2"><span><span class="pill warn">广播</span></span><small>注册 ${esc(cn(c.reg_country))} → 使用 ${esc(cn(c.geo_country))}</small></div>`}</td>
          <td><span class="pill ok">${icon(ci)} ${ct}</span></td>
          <td>${c.dual_isp ? '<span class="pill ok">双 ISP</span>' : '<span class="muted">否</span>'}</td>
          <td>${risks.length ? `<div class="row wrap" style="gap:4px">${risks.map((x) => `<span class="pill bad">${x[1]}</span>`).join('')}</div>` : '<span class="ok-t">无风险</span>'}</td>
          <td><span class="score ${c.fraud_score >= 70 ? 'hi' : c.fraud_score >= 30 ? 'mid' : 'lo'}" title="来源：${esc({ ipqs: 'IPQualityScore', scamalytics: 'Scamalytics', estimate: '估算（配置 IPQS / Scamalytics Key 可得到真实分数）' }[c.fraud_source] || c.fraud_source)}">${c.fraud_score}</span>${c.fraud_source === 'estimate' ? '<small class="faint"> 估</small>' : ''}</td>
          <td>${unlockPills(r.unlock)}</td>
          <td><div class="cell-2"><span>${esc(c.asn)}</span><small>${esc(c.org)}</small></div></td>
          <td class="nowrap">${fmtTime(c.checked_at)}</td>
          <td><div class="row" style="gap:4px"><button class="btn icon sm" data-act="check" title="重新检测" aria-label="重新检测">${icon('refresh')}</button><button class="btn sm" data-act="raw">详情</button></div></td></tr>`;
      }).join('') : '<tr><td colspan="10" class="empty">没有符合条件的服务器</td></tr>'}</tbody></table></div>
      <p class="faint" style="font-size:12px">免费数据源：RDAP（注册地）、ip-api、ipapi.is。在「设置 → IP 检测」中填入 IPQualityScore / Scamalytics / AbuseIPDB / ipinfo / ipapi.is 的 Key 可提高准确度（ipapi.is 免 Key 时只返回基础信息，双 ISP 判断需要它的 Key）。</p>`;
  };
  bind(el, {
    tab: (id, b) => { tab = b.dataset.tab; store.set('ipq_tab', tab); load(); },
    runAll: async () => { await api('POST', '/api/ipchecks/run'); toast('已开始后台检测，每个 IP 约 2 秒'); load(); },
    check: async (id, b) => { b.disabled = true; toast('检测中…'); await api('POST', ipcURL(id)); toast('检测完成'); load(); },
    raw: async (id) => {
      const { latest, history } = await api('GET', ipcURL(id));
      modal('IP 检测详情 · ' + latest.ip, `<div class="tbl-wrap"><table class="tbl"><thead><tr><th>时间</th><th>原生</th><th>类型</th><th>风险</th><th>欺诈分</th></tr></thead><tbody>${history.map((h) => `<tr><td>${fmtTime(h.checked_at)}</td><td>${h.native ? '原生' : '广播'} ${esc(h.reg_country)}→${esc(h.geo_country)}</td><td>${esc((CONN[h.conn_type] || CONN.unknown)[0])}</td><td>${[h.is_proxy && '代理', h.is_vpn && 'VPN', h.is_abuse && '滥用', h.is_tor && 'Tor'].filter(Boolean).join(' / ') || '无'}</td><td>${h.fraud_score}</td></tr>`).join('')}</tbody></table></div>
        <h4 style="margin:16px 0 6px">各数据源原始返回</h4><div class="codebox" style="max-height:340px;overflow:auto">${esc(JSON.stringify(latest.raw, null, 2))}</div>`, { wide: true, cancelText: '关闭' });
    },
  });
  await load();
  autoRefresh(load, 15000);
};

// ---------- users ----------
const STATUS = { active: ['正常', 'ok'], expired: ['已到期', 'bad'], exhausted: ['流量用尽', 'warn'], disabled: ['已停用', ''] };
function userForm(u = {}) {
  return `<div class="form">
    ${inp('用户名', 'username', u.username, { ph: '可选，便于识别' })}
    ${inp('外部 ID', 'external_id', u.external_id, { ph: '商城中的用户/订单 ID', hint: '开放 API 可通过 ext:ID 引用' })}
    ${inp('流量额度 (GB)', 'traffic_limit_gb', u.traffic_limit ? +(u.traffic_limit / 1073741824).toFixed(2) : '', { type: 'number', dtype: 'float', ph: '0 = 不限' })}
    ${inp('到期日', 'expire_at', toDateInput(u.expire_at), { type: 'date', dtype: 'date', hint: '留空 = 永不过期' })}
    ${inp('分组', 'groups', u.groups, { ph: '逗号分隔，对应节点分组' })}
    ${inp('连接密码', 'password', u.password, { ph: '可选，留空用 UUID', hint: 'Trojan / Hysteria2 / TUIC / AnyTLS 使用；导入的老用户保留原密码' })}
    ${inp('流量重置', 'reset_strategy', u.reset_strategy || 'none', { opts: [['none', '不重置'], ['monthly', '每月 1 号'], ['day_of_month', '每月指定日']] })}
    ${inp('重置日', 'reset_day', u.reset_day || 1, { type: 'number', dtype: 'int' })}
    ${inp('限速 Mbps', 'speed_limit', u.speed_limit || '', { type: 'number', dtype: 'int', ph: '0 = 不限' })}
    ${inp('设备数', 'device_limit', u.device_limit || '', { type: 'number', dtype: 'int', ph: '0 = 不限' })}
    ${inp('备注', 'note', u.note, { full: true })}
    ${u.id ? inp('UUID', 'uuid', u.uuid, { full: true, hint: '修改会让旧链接失效' }) : ''}
    ${inp('', 'enabled', u.enabled ?? true, { type: 'checkbox', hint: '启用', full: true })}
  </div>`;
}
function subModal(u) {
  const base = u.sub_url;
  const rows = [['通用（自动识别客户端）', base], ['V2Ray / Shadowrocket / v2rayN', base + '?target=v2ray'], ['Clash Meta / mihomo / Stash', base + '?target=clash'], ['sing-box', base + '?target=singbox'], ['Surge', base + '?target=surge']];
  modal('订阅 · ' + (u.username || u.uuid.slice(0, 8)), rows.map(([l, url]) => `<div class="field" style="margin-bottom:12px"><label>${l}</label><div class="row"><input class="inp mono" readonly value="${esc(url)}"><button class="btn sm" data-copy="${esc(url)}">复制</button></div></div>`).join('') +
    `<div class="note info">UUID：<span class="mono">${esc(u.uuid)}</span><br>已用 ${fmtBytes(u.used)}${u.traffic_limit ? ' / ' + fmtBytes(u.traffic_limit) : ''} · 到期 ${fmtDate(u.expire_at)}</div>`, { cancelText: '关闭' })
    .el.addEventListener('click', (e) => { const b = e.target.closest('[data-copy]'); if (b) copy(b.dataset.copy); });
}
const userPayload = (f) => { f.traffic_limit = Math.round((f.traffic_limit_gb || 0) * 1073741824); delete f.traffic_limit_gb; return f; };

PAGES.users = async (el) => {
  const st = { q: '', status: '', offset: 0, limit: 50 };
  const load = async () => {
    const p = new URLSearchParams({ q: st.q, status: st.status, offset: st.offset, limit: st.limit });
    const { items, total } = await api('GET', '/api/users?' + p);
    PAGES.users._items = items;
    el.innerHTML = topbar('用户', `共 ${total} 个本地用户 · 面板对接节点的用户由面板管理`,
      `<input class="inp search" id="uq" placeholder="搜索用户名 / UUID / 外部 ID" value="${esc(st.q)}">
       <select class="inp" id="us" style="width:auto">${[['', '全部状态'], ...Object.entries(STATUS).map(([k, v]) => [k, v[0]])].map(([k, l]) => `<option value="${k}" ${st.status === k ? 'selected' : ''}>${l}</option>`).join('')}</select>
       <button class="btn" data-act="batch">批量创建</button><button class="btn primary" data-act="add">${icon('plus')}新建用户</button>`) +
      `<div class="card tbl-wrap"><table class="tbl"><thead><tr><th>用户</th><th>状态</th><th>流量</th><th>到期</th><th>在线 IP</th><th>分组</th><th>重置</th><th></th></tr></thead><tbody>
      ${items.length ? items.map((u) => `<tr data-id="${u.id}">
        <td><div class="cell-2"><b>${esc(u.username || u.uuid.slice(0, 8))}</b><small class="mono">${u.external_id ? 'ext:' + esc(u.external_id) + ' · ' : ''}${esc(u.uuid.slice(0, 13))}…</small></div></td>
        <td><span class="pill ${STATUS[u.status][1]}">${STATUS[u.status][0]}</span></td>
        <td>${u.traffic_limit ? meter(u.used, u.traffic_limit, fmtBytes(u.used, 1) + ' / ' + fmtBytes(u.traffic_limit, 0)) : `<span class="num">${fmtBytes(u.used, 1)} <span class="faint">/ 不限</span></span>`}</td>
        <td class="nowrap">${u.expire_at ? `${fmtDate(u.expire_at)}<br><small class="${u.expire_days <= 3 ? 'bad-t' : 'muted'}">${u.expire_days} 天</small>` : '<span class="faint">永久</span>'}</td>
        <td class="num">${u.online_ips}${u.device_limit ? ' / ' + u.device_limit : ''}</td>
        <td>${esc(u.groups) || '<span class="faint">—</span>'}</td>
        <td class="muted" style="font-size:12px">${{ none: '—', monthly: '每月1号', day_of_month: '每月' + u.reset_day + '号' }[u.reset_strategy]}</td>
        <td><div class="row" style="gap:4px"><button class="btn sm" data-act="sub">订阅</button><button class="btn sm" data-act="edit">编辑</button>${menu([['renew', '续费 / 加流量'], ['traffic', '流量明细'], ['reset', '重置已用流量'], ['creds', '重置 UUID 与订阅链接'], ['del', '删除', 'danger']])}</div></td>
      </tr>`).join('') : '<tr><td colspan="8" class="empty">没有用户</td></tr>'}</tbody></table></div>
      <div class="row mt"><span class="muted" style="font-size:13px">第 ${st.offset + 1}-${Math.min(st.offset + st.limit, total)} 条，共 ${total} 条</span><span class="spacer"></span>
      <button class="btn sm" data-act="prev" ${st.offset ? '' : 'disabled'}>上一页</button><button class="btn sm" data-act="next" ${st.offset + st.limit < total ? '' : 'disabled'}>下一页</button></div>`;
    const uq = $('#uq');
    uq.oninput = () => { clearTimeout(uq._t); uq._t = setTimeout(async () => { st.q = uq.value; st.offset = 0; await load(); const x = $('#uq'); x.focus(); x.setSelectionRange(x.value.length, x.value.length); }, 300); };
    $('#us').onchange = (e) => { st.status = e.target.value; st.offset = 0; load(); };
  };
  const find = (id) => PAGES.users._items.find((u) => String(u.id) === String(id));
  bind(el, {
    add: () => modal('新建用户', userForm(), { ok: async (m) => { const u = await api('POST', '/api/users', userPayload(readForm(m))); await load(); subModal(u); }, okText: '创建' }),
    edit: (id) => modal('编辑用户', userForm(find(id)), { ok: async (m) => { await api('PUT', '/api/users/' + id, userPayload(readForm(m))); toast('已保存'); load(); } }),
    sub: (id) => subModal(find(id)),
    renew: (id) => modal('续费 / 加流量', `<div class="form">${inp('延长天数', 'extend_days', '', { type: 'number', dtype: 'int', hint: '从当前到期日（已过期则从今天）起算' })}${inp('增加流量 (GB)', 'add_traffic_gb', '', { type: 'number', dtype: 'float' })}${inp('', 'reset_traffic', false, { type: 'checkbox', hint: '同时清零已用流量', full: true })}</div>`,
      { ok: async (m) => { const f = readForm(m); if (!f.extend_days) delete f.extend_days; if (!f.add_traffic_gb) delete f.add_traffic_gb; await api('PUT', '/api/users/' + id, f); toast('已更新'); load(); } }),
    traffic: async (id) => {
      const pts = await api('GET', `/api/users/${id}/traffic?days=30`);
      modal('近 30 天流量', `<div class="legend"><span><i style="background:var(--accent)"></i>下行</span><span><i style="background:var(--accent-line)"></i>上行</span></div>${barChart(pts, 30)}`, { wide: true, cancelText: '关闭' });
    },
    reset: (id) => confirmBox('清零该用户已用流量？', async () => { await api('POST', `/api/users/${id}/reset-traffic`); load(); }),
    creds: (id) => confirmBox('重置后旧的 UUID 与订阅链接立即失效，用户需重新导入订阅。继续？', async () => { const u = await api('POST', `/api/users/${id}/reset-credentials`, {}); await load(); subModal(u); }),
    del: (id) => confirmBox('确定删除该用户？', async () => { await api('DELETE', '/api/users/' + id); toast('已删除'); load(); }, '删除'),
    prev: () => { st.offset = Math.max(0, st.offset - st.limit); load(); },
    next: () => { st.offset += st.limit; load(); },
    batch: () => modal('批量创建用户', `<div class="form">${inp('数量', 'count', 10, { type: 'number', dtype: 'int' })}${inp('用户名前缀', 'prefix', 'user_', {})}${inp('流量额度 (GB)', 'gb', '', { type: 'number', dtype: 'float' })}${inp('有效天数', 'days', '', { type: 'number', dtype: 'int' })}${inp('分组', 'groups', '', { full: true })}</div>`,
      { ok: async (m) => { const f = readForm(m); const input = { groups: f.groups }; if (f.gb) input.traffic_limit_gb = f.gb; if (f.days) input.extend_days = f.days; const r = await api('POST', '/api/users/batch', { count: f.count, prefix: f.prefix, input }); toast(`已创建 ${r.length} 个用户`); load(); } }),
  });
  await load();
};

// ---------- panels ----------
function panelForm(p = {}) {
  return `<div class="form">
    ${inp('名称', 'name', p.name, { ph: '我的商城' })}
    ${inp('类型', 'type', p.type || 'xboard', { opts: [['xboard', 'Xboard'], ['v2board', 'V2Board（含 wyx2685 分支）'], ['sspanel', 'SSPanel-UIM']] })}
    ${inp('面板地址', 'base_url', p.base_url, { ph: 'https://panel.example.com', full: true })}
    ${inp('通讯密钥', 'token', p.token, { full: true, hint: 'Xboard/V2Board：系统设置 → 服务端 → 通讯密钥；SSPanel：muKey' })}
    ${inp('同步间隔（秒）', 'sync_interval', p.sync_interval || 60, { type: 'number', dtype: 'int' })}
    ${inp('', 'enabled', p.enabled ?? true, { type: 'checkbox', hint: '启用', full: true })}
  </div>`;
}
PAGES.panels = async (el) => {
  const load = async () => {
    const list = await api('GET', '/api/panels');
    PAGES.panels._list = list;
    el.innerHTML = topbar('面板对接', 'NodeHub 作为节点后端，对接已有的 Xboard / V2Board / SSPanel 商城：拉取用户、上报流量与在线 IP', `<button class="btn primary" data-act="add">${icon('plus')}添加面板</button>`) +
      `<div class="card tbl-wrap"><table class="tbl"><thead><tr><th>名称</th><th>类型</th><th>地址</th><th>同步</th><th>最后同步</th><th>状态</th><th></th></tr></thead><tbody>
      ${list.length ? list.map((p) => `<tr data-id="${p.id}"><td><b>${esc(p.name)}</b></td><td>${esc(p.type)}</td><td class="mono">${esc(p.base_url)}</td><td>每 ${p.sync_interval} 秒</td><td>${ago(p.last_sync_at)}</td>
        <td>${!p.enabled ? '<span class="pill">停用</span>' : p.last_error ? `<span class="pill bad" title="${esc(p.last_error)}">错误</span> <small class="bad-t">${esc(p.last_error.slice(0, 60))}</small>` : p.last_sync_at ? '<span class="pill ok">正常</span>' : '<span class="pill">等待</span>'}</td>
        <td><div class="row" style="gap:4px"><button class="btn sm" data-act="sync">立即同步</button><button class="btn sm" data-act="edit">编辑</button><button class="btn sm danger" data-act="del">删除</button></div></td></tr>`).join('') : '<tr><td colspan="7" class="empty">尚未对接面板</td></tr>'}</tbody></table></div>
      <div class="card mt"><div class="card-b" style="font-size:13px;line-height:1.8"><b>使用步骤</b><br>
      1. 在面板后台创建节点，记下节点 ID；<br>2. 在这里添加面板（地址 + 通讯密钥）；<br>3. 在「节点」页新建节点，用户来源选「对接面板」，填写面板节点 ID；勾选「从面板同步」可直接使用面板里的端口与协议参数；<br>
      4. NodeHub 每个同步周期拉取用户、上报流量（原始字节，倍率由面板计算）、在线 IP（Xboard 设备数限制依赖它）与节点负载。</div></div>`;
  };
  bind(el, {
    add: () => modal('添加面板', panelForm(), { ok: async (m) => { await api('POST', '/api/panels', readForm(m)); toast('已添加'); load(); } }),
    edit: (id) => modal('编辑面板', panelForm(PAGES.panels._list.find((p) => String(p.id) === id)), { ok: async (m) => { await api('PUT', '/api/panels/' + id, readForm(m)); toast('已保存'); load(); } }),
    sync: async (id) => { toast('同步中…'); const r = await api('POST', `/api/panels/${id}/sync`); r.errors.length ? toast(r.errors.join('\n'), true) : toast(`同步完成（${r.nodes} 个节点）`); load(); },
    del: (id) => confirmBox('删除该面板对接？', async () => { await api('DELETE', '/api/panels/' + id); load(); }, '删除'),
  });
  await load();
};

// ---------- API & webhooks ----------
PAGES.api = async (el) => {
  const load = async () => {
    const [keys, hooks] = await Promise.all([api('GET', '/api/apikeys'), api('GET', '/api/webhooks')]);
    PAGES.api._hooks = hooks; PAGES.api._keys = keys;
    const base = location.origin + '/api/open/v1';
    el.innerHTML = topbar('API 与 Webhook', '给你的 VPN 商城调用：创建/续费/停用用户、获取订阅、读取节点状态与 IP 质量') + `
    <div class="card"><div class="card-h"><h3>API Key</h3><span class="spacer"></span><button class="btn primary sm" data-act="addKey">${icon('plus')}创建 Key</button></div>
    <div class="tbl-wrap"><table class="tbl"><thead><tr><th>名称</th><th>前缀</th><th>权限</th><th>IP 白名单</th><th>最后使用</th><th>状态</th><th></th></tr></thead><tbody>
    ${keys.length ? keys.map((k) => `<tr data-id="${k.id}"><td><b>${esc(k.name)}</b></td><td class="mono">${esc(k.prefix)}…</td><td>${esc(k.scopes)}</td><td class="mono">${esc(k.ip_whitelist) || '<span class="faint">不限</span>'}</td><td>${ago(k.last_used_at)}</td><td>${k.enabled ? '<span class="pill ok">启用</span>' : '<span class="pill">停用</span>'}</td>
      <td><div class="row" style="gap:4px"><button class="btn sm" data-act="editKey">编辑</button><button class="btn sm danger" data-act="delKey">删除</button></div></td></tr>`).join('') : '<tr><td colspan="7" class="empty">还没有 API Key</td></tr>'}</tbody></table></div></div>

    <div class="card mt"><div class="card-h"><h3>Webhook</h3><span class="spacer"></span><button class="btn primary sm" data-act="addHook">${icon('plus')}添加 Webhook</button></div>
    <div class="tbl-wrap"><table class="tbl"><thead><tr><th>URL</th><th>事件</th><th>最近投递</th><th>状态</th><th></th></tr></thead><tbody>
    ${hooks.length ? hooks.map((h) => `<tr data-id="${h.id}"><td class="mono">${esc(h.url)}</td><td class="mono">${esc(h.events)}</td><td class="muted">${esc(h.last_status) || '—'}</td><td>${h.enabled ? '<span class="pill ok">启用</span>' : '<span class="pill">停用</span>'}</td>
      <td><div class="row" style="gap:4px"><button class="btn sm" data-act="testHook">测试</button><button class="btn sm" data-act="editHook">编辑</button><button class="btn sm danger" data-act="delHook">删除</button></div></td></tr>`).join('') : '<tr><td colspan="5" class="empty">未配置</td></tr>'}</tbody></table></div></div>

    <div class="card mt"><div class="card-h"><h3>快速参考</h3><span class="spacer"></span><span class="faint" style="font-size:12px">完整文档见 docs/API.md</span></div><div class="card-b">
    <div class="codebox">BASE=${esc(base)}
AUTH="Authorization: Bearer nhk_你的Key"

# 下单成功：按商城订单/用户 ID 创建或续费（幂等 upsert）
curl -X PUT $BASE/users/by-external/order_1001 -H "$AUTH" -H "Content-Type: application/json" \\
  -H "Idempotency-Key: order_1001_paid" \\
  -d '{"username":"alice","traffic_limit_gb":200,"extend_days":30,"groups":"vip","reset_strategy":"monthly"}'

# 获取订阅链接（返回 sub_url 与各客户端格式）
curl $BASE/users/ext:order_1001/subscription -H "$AUTH"

# 加流量 / 停用 / 启用 / 重置流量 / 删除
curl -X PATCH $BASE/users/ext:order_1001 -H "$AUTH" -d '{"add_traffic_gb":50}'
curl -X POST  $BASE/users/ext:order_1001/disable -H "$AUTH"
curl -X POST  $BASE/users/ext:order_1001/reset-traffic -H "$AUTH"
curl -X DELETE $BASE/users/ext:order_1001 -H "$AUTH"

# 节点列表（含在线状态、负载、IP 质量、解锁情况）
curl $BASE/nodes -H "$AUTH"</div>
    <p class="muted" style="font-size:13px;margin-bottom:0">Webhook 请求头带 <code>X-NodeHub-Event</code>、<code>X-NodeHub-Timestamp</code>、<code>X-NodeHub-Signature: sha256=HMAC(secret, timestamp + "." + body)</code>。事件：user.created / user.exhausted / user.expired / user.activated / user.traffic_reset / server.offline / server.online / server.expiring / server.traffic_high / ipcheck.risk_changed / panel.error，填 <code>*</code> 订阅全部，<code>user.*</code> 订阅一类。</p></div></div>`;
  };
  const keyForm = (k = {}) => `<div class="form">${inp('名称', 'name', k.name, { ph: '例如 商城生产环境' })}${inp('权限', 'scopes', k.scopes || 'read,write', { opts: [['read,write', '读写'], ['read', '只读']] })}${inp('IP 白名单', 'ip_whitelist', k.ip_whitelist, { full: true, ph: '逗号分隔，支持 CIDR；留空不限制' })}${k.id ? inp('', 'enabled', k.enabled, { type: 'checkbox', hint: '启用', full: true }) : ''}</div>`;
  const hookForm = (h = {}) => `<div class="form">${inp('URL', 'url', h.url, { full: true, ph: 'https://shop.example.com/webhooks/nodehub' })}${inp('事件', 'events', h.events || '*', { full: true, hint: '逗号分隔；* 表示全部' })}${inp('', 'enabled', h.enabled ?? true, { type: 'checkbox', hint: '启用', full: true })}</div>`;
  const secretBox = (title, label, val) => { modal(title, `<p style="margin-top:0">${label}只显示这一次，请立即保存：</p><div class="codebox">${esc(val)}</div><div class="btns mt"><button class="btn primary" id="cpk">${icon('copy')}复制</button></div>`, { cancelText: '完成' }); $('#cpk').onclick = () => copy(val); };
  bind(el, {
    addKey: () => modal('创建 API Key', keyForm(), { ok: async (m) => { const r = await api('POST', '/api/apikeys', readForm(m)); await load(); secretBox('API Key 已创建', 'Key ', r.key); }, okText: '创建' }),
    editKey: (id) => modal('编辑 API Key', keyForm(PAGES.api._keys.find((k) => String(k.id) === id)), { ok: async (m) => { await api('PUT', '/api/apikeys/' + id, readForm(m)); load(); } }),
    delKey: (id) => confirmBox('删除后使用该 Key 的请求会立即失败。确定删除？', async () => { await api('DELETE', '/api/apikeys/' + id); load(); }, '删除'),
    addHook: () => modal('添加 Webhook', hookForm(), { ok: async (m) => { const r = await api('POST', '/api/webhooks', readForm(m)); await load(); secretBox('Webhook 已添加', '签名密钥', r.secret); }, okText: '添加' }),
    editHook: (id) => modal('编辑 Webhook', hookForm(PAGES.api._hooks.find((h) => String(h.id) === id)), { ok: async (m) => { await api('PUT', '/api/webhooks/' + id, readForm(m)); load(); } }),
    delHook: (id) => confirmBox('删除该 Webhook？', async () => { await api('DELETE', '/api/webhooks/' + id); load(); }, '删除'),
    testHook: async (id) => { toast('发送中…'); const r = await api('POST', `/api/webhooks/${id}/test`); toast('结果：' + r.status); load(); },
  });
  await load();
};

// ---------- settings ----------
PAGES.settings = async (el) => {
  const s = await api('GET', '/api/settings');
  const section = (title, body, key) => `<div class="card" data-sec="${key}"><div class="card-h"><h3>${title}</h3><span class="spacer"></span><button class="btn primary sm" data-act="save">保存</button></div><div class="card-b"><div class="form">${body}</div></div></div>`;
  el.innerHTML = topbar('设置', '') + `<div class="grid" style="gap:14px">
    ${section('基本', `${inp('站点名称', 'site_name', s.site_name)}${inp('面板公开地址', 'public_url', s.public_url, { ph: 'https://nodes.example.com', hint: 'Agent 安装命令与订阅使用；留空则按访问地址' })}
      ${inp('订阅域名', 'sub_url', s.sub_url, { ph: '留空同上', hint: '可单独给订阅一个域名，与后台分开' })}${inp('订阅节点名模板', 'sub_name_template', s.sub_name_template, { hint: '可用 {flag} {name} {region} {protocol} {rate}' })}${inp('订阅分流规则', 'sub_rule_mode', s.sub_rule_mode || 'global', { opts: [['global', '全部走代理（和单独导入节点一样，最稳）'], ['smart', '国内直连、国外走代理（省流量，个别网站可能误判）']], hint: 'Clash / Surge 订阅使用；也可在订阅链接后加 ?rules=smart 或 ?rules=global 单独指定' })}
      ${inp('订阅「官网」链接', 'sub_support_url', s.sub_support_url, { full: true, ph: '客户端里显示的网站链接，可填商城地址' })}`, 'basic')}
    ${section('Agent 与监控', `${inp('Agent 上报间隔（秒）', 'report_interval', s.report_interval, { type: 'number' })}${inp('离线判定（秒无心跳）', 'offline_after', s.offline_after, { type: 'number' })}
      ${inp('流量明细保留天数', 'traffic_retention_days', s.traffic_retention_days, { type: 'number' })}${inp('VPS 到期提前提醒（天）', 'server_expire_remind_days', s.server_expire_remind_days || 3, { type: 'number' })}
      ${inp('解锁检测间隔（小时）', 'unlock_interval_hours', s.unlock_interval_hours, { type: 'number' })}${inp('', 'agent_insecure_tls', s.agent_insecure_tls === '1', { type: 'checkbox', hint: 'Agent 不校验面板 HTTPS 证书（面板用自签证书时）' })}`, 'agent')}
    ${section('IP 检测数据源', `${inp('自动检测间隔（小时）', 'ipcheck_interval_hours', s.ipcheck_interval_hours, { type: 'number' })}<div></div>
      ${inp('IPQualityScore Key', 'ipcheck_ipqs_key', s.ipcheck_ipqs_key, { hint: '提供真实欺诈分（免费 5000 次/月）' })}${inp('ipapi.is Key', 'ipcheck_ipapiis_key', s.ipcheck_ipapiis_key, { hint: '免费注册 1000 次/天；用于判断双 ISP、机房、滥用' })}
      ${inp('Scamalytics API 地址', 'ipcheck_scamalytics_url', s.ipcheck_scamalytics_url, { ph: 'https://api12.scamalytics.com/v3/你的用户名/' })}${inp('Scamalytics Key', 'ipcheck_scamalytics_key', s.ipcheck_scamalytics_key)}
      ${inp('AbuseIPDB Key', 'ipcheck_abuseipdb_key', s.ipcheck_abuseipdb_key)}${inp('ipinfo Token', 'ipcheck_ipinfo_token', s.ipcheck_ipinfo_token)}`, 'ipcheck')}
    ${section('证书（DNS 验证）', `${inp('Cloudflare API 令牌', 'cf_api_token', s.cf_api_token, { full: true, hint: '在 Cloudflare「我的个人资料 → API 令牌」创建，权限：区域 · DNS · 编辑，范围选你的域名。只存在面板里，节点选「ACME · DNS 验证」时下发给对应服务器；任何 VPS 都能共用，不需要 80 端口。' })}`, 'cert')}
    ${section('通知', `${inp('Telegram Bot Token', 'tg_bot_token', s.tg_bot_token)}${inp('Telegram Chat ID', 'tg_chat_id', s.tg_chat_id)}
      ${inp('推送的事件', 'notify_events', s.notify_events, { full: true, hint: '逗号分隔，* 表示全部' })}<div class="full"><button class="btn sm" data-act="tg">发送测试消息</button></div>`, 'notify')}
    <div class="card"><div class="card-h"><h3>账户安全</h3></div><div class="card-b"><div class="btns"><button class="btn" data-act="pwd">修改密码</button>
      ${ME.totp ? '<button class="btn" data-act="totpOff">关闭两步验证</button>' : '<button class="btn" data-act="totpOn">开启两步验证</button>'}<button class="btn" data-act="backup">下载数据库备份</button></div></div></div>
  </div>`;
  bind(el, {
    save: async (id, b) => {
      const sec = b.closest('[data-sec]'); const f = readForm(sec);
      Object.keys(f).forEach((k) => { if (typeof f[k] === 'boolean') f[k] = f[k] ? '1' : '0'; else f[k] = String(f[k]); });
      await api('PUT', '/api/settings', f); toast('已保存');
      if (f.site_name) { ME.site_name = f.site_name; }
    },
    tg: async () => { await api('POST', '/api/settings/test-telegram'); toast('已发送，请查看 Telegram'); },
    pwd: () => modal('修改密码', `<div class="form">${inp('原密码', 'old', '', { type: 'password', full: true })}${inp('新密码', 'new', '', { type: 'password', full: true, hint: '至少 8 位' })}</div>`, { ok: async (m) => { await api('POST', '/api/auth/password', readForm(m)); toast('已修改，请重新登录'); setTimeout(() => renderLogin(), 800); } }),
    totpOn: async () => {
      const r = await api('POST', '/api/auth/totp/setup');
      modal('开启两步验证', `<p style="margin-top:0">在 Google Authenticator / 1Password 等应用中手动添加以下密钥（或复制 otpauth 链接），然后输入 6 位验证码：</p><div class="codebox">${esc(r.secret)}</div><div class="codebox mt" style="font-size:11px">${esc(r.uri)}</div><div class="form mt">${inp('验证码', 'code', '', { full: true, attrs: 'inputmode="numeric"' })}</div>`,
        { ok: async (m) => { await api('POST', '/api/auth/totp/enable', { secret: r.secret, code: readForm(m).code }); ME.totp = true; toast('两步验证已开启'); render(); }, okText: '开启' });
    },
    totpOff: () => modal('关闭两步验证', inp('当前密码', 'password', '', { type: 'password' }), { ok: async (m) => { await api('POST', '/api/auth/totp/disable', readForm(m)); ME.totp = false; toast('已关闭'); render(); } }),
    backup: () => { location.href = '/api/backup'; },
  });
};

// ---------- logs ----------
PAGES.logs = async (el) => {
  let tab = 'events';
  const load = async () => {
    const list = await api('GET', tab === 'events' ? '/api/events?limit=300' : '/api/audit?limit=300');
    el.innerHTML = topbar('日志', '') + `<div class="tabs" style="margin-bottom:12px"><button data-act="tab" data-t="events" class="${tab === 'events' ? 'on' : ''}">系统事件</button><button data-act="tab" data-t="audit" class="${tab === 'audit' ? 'on' : ''}">操作审计</button></div>
    <div class="card tbl-wrap"><table class="tbl"><thead>${tab === 'events' ? '<tr><th>时间</th><th>级别</th><th>类型</th><th>内容</th></tr>' : '<tr><th>时间</th><th>操作者</th><th>操作</th><th>对象</th><th>详情</th><th>IP</th></tr>'}</thead><tbody>
    ${list.length ? list.map((x) => tab === 'events'
      ? `<tr><td class="nowrap">${fmtTime(x.created_at, true)}</td><td><span class="pill ${x.level === 'error' ? 'bad' : x.level === 'warn' ? 'warn' : 'info'}">${x.level}</span></td><td class="mono">${esc(x.type)}</td><td>${esc(x.message)}</td></tr>`
      : `<tr><td class="nowrap">${fmtTime(x.created_at, true)}</td><td>${esc(x.actor)}</td><td class="mono">${esc(x.action)}</td><td>${esc(x.target)}</td><td class="muted" style="max-width:300px;word-break:break-all">${esc(x.detail)}</td><td class="mono">${esc(x.ip)}</td></tr>`).join('') : '<tr><td colspan="6" class="empty">暂无记录</td></tr>'}</tbody></table></div>`;
  };
  bind(el, { tab: (id, b) => { tab = b.dataset.t; load(); } });
  await load();
};

render();
