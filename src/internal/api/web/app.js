// GateWeaver 管理台前端（零依赖，中文）
'use strict';
const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);
let token = sessionStorage.getItem('gw_token') || '';
let licPending = null; // 等待授权确认后要继续的动作

async function api(path, opts = {}) {
  opts.headers = Object.assign({'Content-Type': 'application/json'}, opts.headers || {});
  if (token) opts.headers['Authorization'] = 'Bearer ' + token;
  if (opts.body && typeof opts.body !== 'string') opts.body = JSON.stringify(opts.body);
  const r = await fetch('/api' + path, opts);
  if (r.status === 401) { showAuth(); throw new Error('会话过期'); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

function fmtTime(t) { return t ? new Date(t).toLocaleString('zh-CN', {hour12:false}) : '—'; }
function ipToInt(s){ const p=s.split('.'); return ((+p[0]<<24)|(+p[1]<<16)|(+p[2]<<8)|+p[3])>>>0; }
function inCidr(ip, base, bits){ const m = bits===0?0:((-1)<<(32-bits))>>>0; return (ipToInt(ip)&m)===(ipToInt(base)&m); }
const stateZh = {disabled:'未启用', injecting:'注入中', active:'已生效 ✓', no_traffic:'未见流量（可能被静态ARP/防护）'};

// ---------- 视图切换 ----------
function show(view) {
  $$('.view').forEach(v => v.classList.add('hidden'));
  $('#view-' + view).classList.remove('hidden');
  $$('.tab').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  ({overview: loadOverview, targets: loadTargets, discover: ()=>{}, settings: loadSettings, logs: loadLogs}[view] || (()=>{}))();
}
$('#nav').addEventListener('click', e => { if (e.target.dataset.view) show(e.target.dataset.view); });

// ---------- 登录/初始化 ----------
function showAuth() { $('#nav').classList.add('hidden'); $$('.view').forEach(v=>v.classList.add('hidden')); $('#view-auth').classList.remove('hidden'); }
async function initAuth(needsSetup) {
  $('#auth-title').textContent = needsSetup ? '首次使用：设置管理口令' : '登录';
  $('#auth-hint').textContent = needsSetup ? '至少 8 位。此口令用于管理台全部操作。' : '';
  $('#auth-pw2').classList.toggle('hidden', !needsSetup);
  $('#auth-btn').textContent = needsSetup ? '设置并进入' : '登录';
}
$('#auth-btn').addEventListener('click', async () => {
  const pw = $('#auth-pw').value, pw2 = $('#auth-pw2').value;
  $('#auth-err').textContent = '';
  try {
    const init = await fetch('/api/initial').then(r=>r.json());
    if (init.needs_setup) {
      if (pw.length < 8 || pw !== pw2) throw new Error('口令需≥8位且两次一致');
      await fetch('/api/setup', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({password:pw})}).then(async r=>{if(!r.ok) throw new Error((await r.json()).error);});
    }
    const r = await fetch('/api/login', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({password:pw})});
    if (!r.ok) throw new Error('口令错误');
    token = (await r.json()).token;
    sessionStorage.setItem('gw_token', token);
    enterApp();
  } catch (e) { $('#auth-err').textContent = e.message; }
});
$('#logout').addEventListener('click', async () => {
  try { await api('/logout', {method:'POST'}); } catch {}
  token=''; sessionStorage.removeItem('gw_token'); showAuth();
});

async function enterApp() {
  $('#nav').classList.remove('hidden');
  show('overview');
  const init = await fetch('/api/initial').then(r=>r.json());
  if (init.needs_license) askLicense();
}

// ---------- 授权声明 ----------
function askLicense(after) {
  licPending = after || null;
  $('#license-mask').classList.remove('hidden');
  $('#license-chk').checked = false;
  $('#license-ok').disabled = true;
}
$('#license-chk').addEventListener('change', e => $('#license-ok').disabled = !e.target.checked);
$('#license-no').addEventListener('click', () => { licPending=null; $('#license-mask').classList.add('hidden'); });
$('#license-ok').addEventListener('click', async () => {
  await api('/license/ack', {method:'POST'});
  $('#license-mask').classList.add('hidden');
  const a = licPending; licPending = null;
  if (a) await a();
  loadOverview();
});

// ---------- 总览 ----------
async function loadOverview() {
  try {
    const ov = await api('/overview');
    $('#global-sw').checked = ov.global_enabled;
    $('#global-txt').textContent = ov.global_enabled ? '开启' : '关闭';
    let banner = '';
    if (!ov.upstream_ok) banner = '<div class="banner warn">上游网关不可达：已自动放开（fail-open），恢复后自动重接管。</div>';
    else if (ov.tun && ov.tun.enabled && ov.tun.withdrawn) banner = '<div class="banner warn">TUN 接管失效：已撤销全部引导，设备直连真实网关；TUN 恢复后自动重引导。</div>';
    else if (ov.counts && ov.counts.enabled > 0 && !ov.global_enabled) banner = '<div class="banner info">存在启用中的目标，但全局开关关闭。</div>';
    $('#ov-banner').innerHTML = banner;
    // 本机（接管侧）MAC：被接管设备学到的"网关 MAC"就是它
    let nasRow = '';
    try {
      const ifs = await api('/interfaces');
      for (const [name, info] of Object.entries(ifs)) {
        for (const cidr of (info.addrs||[])) {
          const [base, bits] = cidr.split('/');
          if (ov.gateway.ip && inCidr(ov.gateway.ip, base, +bits)) {
            nasRow = `<tr><td>本机 ${name}</td><td>${info.mac||'?'}</td><td colspan="2" class="muted">目标设备学到的网关 MAC（NAS 自身）</td></tr>`;
          }
        }
      }
    } catch {}
    const tn = ov.tun || {};
    const tunTxt = !tn.enabled ? '<span class="muted">未启用（纯转发模型，出口由你自行保证）</span>'
      : (tn.healthy ? `✓ 正常（默认路由 dev ${tn.tun_iface}*，controller ${tn.controller}）`
      : (tn.withdrawn ? `✗ 失效已撤销引导（route:${tn.route_ok?'✓':'✗'} ctrl:${tn.ctrl_ok?'✓':'✗'}）`
      : `✗ 失效（route:${tn.route_ok?'✓':'✗'} ctrl:${tn.ctrl_ok?'✓':'✗'}，未启用自动撤销）`));
    $('#ov-gw').innerHTML = `
      <tr><td>IP</td><td>${ov.gateway.ip||'—'}</td><td>来源</td><td>${ov.gateway.source==='config'?'手动指定':'默认路由探测'}</td></tr>
      <tr><td>真实 MAC</td><td>${ov.gateway.known?ov.gateway.mac:'未知（探测中/失败）'}</td><td>健康</td><td>${ov.upstream_ok?'✓ 可达':'✗ 不可达'}</td></tr>
      ${nasRow}
      <tr><td>TUN 接管</td><td colspan="3">${tunTxt}</td></tr>
      <tr><td>送达模式</td><td colspan="3">${ov.forward_mode==='masquerade'?'地址伪装':'直连路由'}</td></tr>`;
    const tb = $('#ov-table tbody'); tb.innerHTML = '';
    for (const row of ov.targets) {
      const st = row.status || {};
      tb.insertAdjacentHTML('beforeend', `<tr><td>${row.target.mac}</td><td>${row.target.ip}</td><td>${row.target.iface}</td>
        <td>${stateZh[st.state]||'未启用'}</td><td>${fmtTime(st.last_inject)}</td>
        <td>${st.seen_pkts||0} / ${st.seen_bytes||0}</td></tr>`);
    }
  } catch (e) { console.error(e); }
}
$('#global-sw').addEventListener('change', async e => {
  const want = e.target.checked;
  if (want) {
    const init = await fetch('/api/initial').then(r=>r.json());
    if (init.needs_license) { askLicense(()=>setGlobal(true)); e.target.checked=false; return; }
  }
  await setGlobal(want);
});
async function setGlobal(v){ try{ await api('/global',{method:'POST',body:{enabled:v}}); }catch(e){alert(e.message);} loadOverview(); }
$('#recover-all').addEventListener('click', async () => {
  if (!confirm('将立即恢复所有被接管设备的网关（配置保留）。继续？')) return;
  await api('/recover', {method:'POST'}); loadOverview();
});

// ---------- 目标管理 ----------
let ifaceList = [];
async function loadIfaceSelect() {
  try {
    ifaceList = await api('/interfaces');
    const opts = Object.entries(ifaceList).map(([i, info]) => `<option value="${i}">${i}${info.mac?' · '+info.mac:''}</option>`).join('');
    $('#tg-iface').innerHTML = opts || '<option value="eth0">eth0</option>';
  } catch { $('#tg-iface').innerHTML = '<option value="eth0">eth0</option>'; }
}
async function loadTargets() {
  loadIfaceSelect();
  const ts = await api('/targets');
  const tb = $('#tg-table tbody'); tb.innerHTML = '';
  for (const t of ts) {
    tb.insertAdjacentHTML('beforeend', `<tr>
      <td>${t.mac}</td><td>${t.ip}</td><td>${t.iface}</td>
      <td><input type="checkbox" class="tg-en" data-mac="${t.mac}" ${t.enabled?'checked':''}></td>
      <td>${t.note||''}</td>
      <td><button class="ghost tg-del" data-mac="${t.mac}">删除</button></td></tr>`);
  }
  tb.querySelectorAll('.tg-en').forEach(cb => cb.addEventListener('change', async e => {
    const enable = e.target.checked;
    const go = async () => { try { await api('/targets/'+e.target.dataset.mac, {method:'PUT', body:{enabled:enable}}); } catch(err){ alert(err.message); } loadTargets(); };
    if (enable) {
      const init = await fetch('/api/initial').then(r=>r.json());
      if (init.needs_license) { askLicense(go); e.target.checked=false; return; }
    }
    go();
  }));
  tb.querySelectorAll('.tg-del').forEach(b => b.addEventListener('click', async e => {
    if (!confirm('删除并恢复该设备？')) return;
    try { await api('/targets/'+e.target.dataset.mac, {method:'DELETE'}); } catch(err){ alert(err.message); }
    loadTargets();
  }));
}
$('#tg-add').addEventListener('click', async () => {
  $('#tg-err').textContent='';
  try {
    await api('/targets', {method:'POST', body:{mac:$('#tg-mac').value.trim(), ip:$('#tg-ip').value.trim(), iface:$('#tg-iface').value, enabled:$('#tg-enabled').checked, note:$('#tg-note').value.trim()}});
    $('#tg-mac').value=$('#tg-ip').value=$('#tg-note').value='';
    loadTargets();
  } catch(e){ $('#tg-err').textContent=e.message; }
});

// ---------- 发现 ----------
$('#dc-refresh').addEventListener('click', async () => {
  const cidr = $('#dc-cidr').value.trim();
  const list = await api('/discover' + (cidr? '?probe='+encodeURIComponent(cidr):''));
  const tb = $('#dc-table tbody'); tb.innerHTML='';
  for (const e of list) {
    tb.insertAdjacentHTML('beforeend', `<tr><td>${e.ip}</td><td>${e.mac||'—'}</td><td>${e.iface||'—'}</td><td>${e.state}</td>
      <td>${e.mac?`<button class="primary dc-add" data-ip="${e.ip}" data-mac="${e.mac}" data-iface="${e.iface}">设为目标</button>`:''}</td></tr>`);
  }
  tb.querySelectorAll('.dc-add').forEach(b=>b.addEventListener('click', async ()=>{
    try { await api('/targets',{method:'POST', body:{mac:b.dataset.mac, ip:b.dataset.ip, iface:b.dataset.iface, enabled:false, note:'发现添加'}}); alert('已添加（默认未启用）'); } catch(e){ alert(e.message); }
  }));
});

// ---------- 设置 ----------
async function loadSettings() {
  const c = await api('/config');
  $('#st-gw').value = c.gateway_ip; $('#st-gwmac').value = c.gateway_mac_fixed;
  $('#st-interval').value = c.inject_interval_sec; $('#st-rate').value = c.inject_rate_per_sec;
  $('#st-mode').value = c.forward_mode; $('#st-failopen').checked = c.fail_open;
  $('#st-port').value = c.port;
  $('#st-tun-en').checked = c.tun_guard_enabled; $('#st-tun-iface').value = c.tun_iface || 'tun';
  $('#st-tun-ctrl').value = c.controller_addr || '127.0.0.1:19090';
  $('#st-tun-withdraw').checked = c.tun_fail_withdraw;
}
$('#st-save').addEventListener('click', async () => {
  $('#st-err').textContent='';
  try {
    await api('/config', {method:'PUT', body:{
      gateway_ip: $('#st-gw').value.trim(), gateway_mac_fixed: $('#st-gwmac').value.trim(),
      inject_interval_sec: +$('#st-interval').value, inject_rate_per_sec: +$('#st-rate').value,
      forward_mode: $('#st-mode').value, fail_open: $('#st-failopen').checked, port: +$('#st-port').value,
      tun_guard_enabled: $('#st-tun-en').checked, tun_iface: $('#st-tun-iface').value.trim() || 'tun',
      controller_addr: $('#st-tun-ctrl').value.trim() || '127.0.0.1:19090',
      tun_fail_withdraw: $('#st-tun-withdraw').checked }});
    alert('已保存并热生效（端口变更需重启应用）');
  } catch(e){ $('#st-err').textContent=e.message; }
});

// ---------- 日志 ----------
async function loadLogs() {
  const evs = await api('/events?limit=300');
  const tb = $('#lg-table tbody'); tb.innerHTML='';
  const kindZh = {takeover:'接管', restore:'恢复', upstream:'上游', config:'配置', audit:'审计', error:'错误'};
  for (const e of evs.reverse()) {
    tb.insertAdjacentHTML('beforeend', `<tr><td>${fmtTime(e.time)}</td><td>${kindZh[e.kind]||e.kind}</td><td>${e.target||''}</td><td>${e.actor||''}</td><td>${e.message}</td></tr>`);
  }
}
$('#lg-refresh').addEventListener('click', loadLogs);

// ---------- 启动 ----------
(async function boot() {
  const init = await fetch('/api/initial').then(r=>r.json()).catch(()=>({needs_setup:true}));
  if (init.needs_setup) { showAuth(); initAuth(true); return; }
  if (token) {
    try { await api('/overview'); enterApp(); return; } catch { }
  }
  showAuth(); initAuth(false);
})();
