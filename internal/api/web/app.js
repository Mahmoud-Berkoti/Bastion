// bastion dashboard — polls stats, streams events over SSE, manages rules.
"use strict";

const $ = (id) => document.getElementById(id);

const fmt = (n) => {
  if (n >= 1e9) return (n / 1e9).toFixed(1) + "G";
  if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + "k";
  return String(n);
};
const fmtBytes = (n) => {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? 1 : 0) + " " + units[i];
};

function toast(msg) {
  const t = document.createElement("div");
  t.className = "toast";
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3000);
}

async function api(path, opts) {
  const res = await fetch("/api/v1" + path, opts);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || res.statusText);
  return body;
}

/* ---- status ---- */
async function loadStatus() {
  try {
    const s = await api("/status");
    $("status").innerHTML =
      `<span class="ok">●</span> ${s.iface} · xdp ${s.mode} · prog ${s.prog_id}`;
  } catch {
    $("status").textContent = "control plane unreachable";
  }
}

/* ---- stats + sparkline ---- */
let prev = null;
const history = [];
const SPARK_N = 60;

async function pollStats() {
  try {
    const s = await api("/stats");
    const now = performance.now();
    if (prev) {
      const dt = (now - prev.t) / 1000;
      const pps = Math.max(0, (s.total_packets - prev.s.total_packets) / dt);
      $("pps").textContent = fmt(Math.round(pps));
      history.push(pps);
      if (history.length > SPARK_N) history.shift();
      drawSpark();
    }
    prev = { s, t: now };

    const rate = s.total_packets ? (100 * s.dropped_packets / s.total_packets) : 0;
    $("droprate").textContent = rate.toFixed(1);
    $("dropsplit").textContent =
      `cidr ${fmt(s.drop_blocklist)} · port ${fmt(s.drop_port)} · rate ${fmt(s.drop_ratelimit)}`;
    $("totalpkts").textContent = fmt(s.total_packets);
    $("totalbytes").textContent = fmtBytes(s.total_bytes);
    $("droppedpkts").textContent = fmt(s.dropped_packets);
    $("droppedbytes").textContent = fmtBytes(s.dropped_bytes);
  } catch { /* transient; next poll retries */ }
}

function drawSpark() {
  const c = $("spark");
  const ctx = c.getContext("2d");
  const w = c.width, h = c.height;
  ctx.clearRect(0, 0, w, h);
  if (history.length < 2) return;
  const max = Math.max(...history, 1);
  ctx.beginPath();
  history.forEach((v, i) => {
    const x = (i / (SPARK_N - 1)) * w;
    const y = h - 2 - (v / max) * (h - 6);
    i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
  });
  ctx.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue("--accent");
  ctx.lineWidth = 1.5;
  ctx.stroke();
}

/* ---- rules ---- */
function ruleItem(label, meta, onDelete) {
  const li = document.createElement("li");
  const span = document.createElement("span");
  span.textContent = label;
  if (meta) {
    const m = document.createElement("span");
    m.className = "meta";
    m.textContent = meta;
    span.appendChild(m);
  }
  const x = document.createElement("button");
  x.className = "x";
  x.textContent = "×";
  x.title = "remove";
  x.onclick = onDelete;
  li.append(span, x);
  return li;
}

function renderList(el, items, build) {
  el.replaceChildren();
  if (!items || !items.length) {
    const li = document.createElement("li");
    li.className = "none";
    li.textContent = "none";
    el.appendChild(li);
    return;
  }
  items.forEach((it) => el.appendChild(build(it)));
}

function renderRules(cfg) {
  renderList($("blocklist"), cfg.blocklist, (cidr) =>
    ruleItem(cidr, "", () => del({ type: "blocklist", cidr })));
  renderList($("portrules"), cfg.port_rules, (r) =>
    ruleItem(`${r.proto}/${r.port}`, r.action, () =>
      del({ type: "port", proto: r.proto, port: r.port })));
  renderList($("ratelimits"), cfg.rate_limits, (r) =>
    ruleItem(r.cidr, `${fmt(r.pps)}pps burst ${r.burst}`, () =>
      del({ type: "ratelimit", cidr: r.cidr })));
}

async function loadRules() {
  try { renderRules(await api("/rules")); } catch (e) { toast(e.message); }
}

async function post(body) {
  try {
    renderRules(await api("/rules", { method: "POST", body: JSON.stringify(body) }));
  } catch (e) { toast(e.message); }
}

async function del(body) {
  try {
    renderRules(await api("/rules", { method: "DELETE", body: JSON.stringify(body) }));
  } catch (e) { toast(e.message); }
}

$("form-blocklist").onsubmit = (e) => {
  e.preventDefault();
  post({ type: "blocklist", cidr: e.target.cidr.value.trim() });
  e.target.reset();
};
$("form-port").onsubmit = (e) => {
  e.preventDefault();
  post({
    type: "port",
    proto: e.target.proto.value,
    port: +e.target.port.value,
    action: e.target.action.value,
  });
  e.target.reset();
};
$("form-ratelimit").onsubmit = (e) => {
  e.preventDefault();
  post({
    type: "ratelimit",
    cidr: e.target.cidr.value.trim(),
    pps: +e.target.pps.value,
    burst: +e.target.burst.value,
  });
  e.target.reset();
};

/* ---- events ---- */
const MAX_ROWS = 50;

function addEventRow(ev) {
  $("events-empty").style.display = "none";
  const tbody = $("events").querySelector("tbody");
  const tr = document.createElement("tr");
  const t = new Date(ev.time).toLocaleTimeString();
  const cells = [
    t,
    ev.src_port ? `${ev.src}:${ev.src_port}` : ev.src,
    ev.dst_port ? `${ev.dst}:${ev.dst_port}` : ev.dst,
    ev.proto,
    ev.reason.replace("drop_", "") + (ev.rule_name ? ` (${ev.rule_name})` : ""),
  ];
  cells.forEach((c, i) => {
    const td = document.createElement("td");
    td.textContent = c;
    if (i === 4) td.className = "reason";
    tr.appendChild(td);
  });
  tbody.prepend(tr);
  while (tbody.rows.length > MAX_ROWS) tbody.deleteRow(-1);

  const dot = $("live-dot");
  dot.classList.add("on");
  clearTimeout(dot._t);
  dot._t = setTimeout(() => dot.classList.remove("on"), 300);
}

async function loadRecentEvents() {
  try {
    const evs = await api("/events?limit=" + MAX_ROWS);
    evs.reverse().forEach(addEventRow);
  } catch { /* ignore */ }
}

function streamEvents() {
  const es = new EventSource("/api/v1/events/stream");
  es.onmessage = (m) => addEventRow(JSON.parse(m.data));
  es.onerror = () => {
    es.close();
    setTimeout(streamEvents, 2000);
  };
}

/* ---- boot ---- */
loadStatus();
loadRules();
loadRecentEvents();
streamEvents();
pollStats();
setInterval(pollStats, 1000);
setInterval(loadStatus, 10000);
