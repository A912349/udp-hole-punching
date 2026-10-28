(function installAccountUI() {
  const connect = document.querySelector('.connect');
  if (!connect) return;
  const auth = document.createElement('div');
  auth.className = 'accountAuth';
  auth.innerHTML = '<input id="accountUsername" autocomplete="username" placeholder="Account"><input id="accountPassword" type="password" autocomplete="current-password" placeholder="Password"><input id="accountRegistrationInvite" autocomplete="off" placeholder="Registration invite"><button id="accountLogin">Log in</button><button id="accountRegister" class="ghost">Register</button><button id="accountLogout" class="ghost" hidden>Log out</button>';
  connect.insertBefore(auth, connect.firstChild);
  const access = document.querySelector('#access .columns');
  if (access) {
    const tokenCard = document.createElement('article');
    tokenCard.className = 'card';
    tokenCard.innerHTML = '<h2>Your network token</h2><p class="muted">Use this separate token with <code>mesh-node --network-token</code>. It is shown after registration or rotation.</p><button id="rotateAccountToken">Rotate token</button><div id="accountNetworkToken" class="inviteCode long">—</div><button class="ghost copyBtn" data-copy-target="accountNetworkToken">Copy token</button>';
    access.appendChild(tokenCard);
    const card = document.createElement('article');
    card.className = 'card';
    card.innerHTML = '<h2>Invite another account</h2><p class="muted">One-use invitation, valid for 24 hours. The raw token is shown once.</p><button id="createAccountInvite">Generate account invite</button><div id="newAccountInvite" class="inviteCode long">—</div><button class="ghost copyBtn" data-copy-target="newAccountInvite">Copy invite</button>';
    access.appendChild(card);
    const list = document.createElement('article');
    list.className = 'card';
    list.innerHTML = '<h2>Account invitations</h2><table><thead><tr><th>Created</th><th>Expires</th><th>Status</th></tr></thead><tbody id="accountInviteRows"></tbody></table>';
    access.appendChild(list);
  }
})();
const $ = id => document.getElementById(id);
let state = {
    topology: {
      nodes: [],
      links: []
    },
    topologies: {
      online: {
        nodes: [],
        links: []
      },
      all: {
        nodes: [],
        links: []
      }
    },
    scope: 'online',
    audit: [],
    config: {},
    invites: [],
    manualLinks: [],
    blockedLinks: []
  },
  timer,
  graphTimer;
let graphUI = {
  positions: {},
  source: null,
  selectedNode: null,
  selectedEdge: null,
  view: null,
  lastSig: null,
  dragging: null,
  viewSaveTimer: null
};
const graphPositionsCookie = 'mesh_graph_positions',
  graphPositionsStorage = 'meshGraphPositions',
  VIEW_W = 1100,
  VIEW_H = 600,
  GRID_STEP = 28,
  viewStorage = 'meshGraphView',
  MIN_ZOOM = 0.15,
  MAX_ZOOM = 4;

function loadGraphPositions() {
  let raw = cookieValue(graphPositionsCookie);
  if (!raw) {
    try {
      raw = localStorage.getItem(graphPositionsStorage) || ''
    } catch (e) {}
  }
  if (!raw) return;
  try {
    let stored = JSON.parse(decodeURIComponent(raw));
    Object.entries(stored).forEach(([id, p]) => {
      let x = Number(p?.x),
        y = Number(p?.y);
      if (Number.isFinite(x) && Number.isFinite(y)) graphUI.positions[id] = {
        x,
        y
      };
    });
  } catch (e) {}
}

function saveGraphPositions() {
  let stored = {};
  Object.entries(graphUI.positions).forEach(([id, p]) => {
    stored[id] = {
      x: Math.round(p.x * 10) / 10,
      y: Math.round(p.y * 10) / 10
    }
  });
  let encoded = encodeURIComponent(JSON.stringify(stored));
  if (encoded.length <= 3800) document.cookie = graphPositionsCookie + '=' + encoded + '; Max-Age=31536000; Path=/; SameSite=Lax';
  else document.cookie = graphPositionsCookie + '=; Max-Age=0; Path=/; SameSite=Lax';
  try {
    localStorage.setItem(graphPositionsStorage, JSON.stringify(stored))
  } catch (e) {}
}
loadGraphPositions();

function loadView() {
  try {
    let v = JSON.parse(localStorage.getItem(viewStorage) || 'null');
    if (v && Number.isFinite(v.k) && Number.isFinite(v.x) && Number.isFinite(v.y) && v.k >= MIN_ZOOM && v.k <= MAX_ZOOM) return {
      k: v.k,
      x: v.x,
      y: v.y
    };
  } catch (e) {}
  return null;
}

function saveView() {
  if (!graphUI.view) return;
  try {
    localStorage.setItem(viewStorage, JSON.stringify(graphUI.view))
  } catch (e) {}
}

// applyView mirrors the viewport transform onto the dot grid backdrop so the
// canvas feels infinite: the grid moves and scales with pan/zoom.
function applyView() {
  let v = graphUI.view;
  if (!v) return;
  let g = document.querySelector('#graphViewport');
  if (g) g.setAttribute('transform', `translate(${v.x} ${v.y}) scale(${v.k})`);
  let svg = $('topologyGraph');
  if (svg && svg.clientWidth > 0 && svg.clientHeight > 0) {
    let s = Math.min(svg.clientWidth / VIEW_W, svg.clientHeight / VIEW_H),
      ox = (svg.clientWidth - VIEW_W * s) / 2,
      oy = (svg.clientHeight - VIEW_H * s) / 2;
    svg.style.backgroundSize = `${GRID_STEP * v.k * s}px ${GRID_STEP * v.k * s}px, 100% 100%`;
    svg.style.backgroundPosition = `${ox + v.x * s}px ${oy + v.y * s}px, 0 0`;
  }
  let level = $('zoomLevel');
  if (level) level.textContent = Math.round(v.k * 100) + '%';
  clearTimeout(graphUI.viewSaveTimer);
  graphUI.viewSaveTimer = setTimeout(saveView, 300);
}

// fitView centers and scales the viewport so every current peer is visible.
function fitView() {
  let pts = (state.topology.nodes || []).map(n => graphUI.positions[n.node_id]).filter(Boolean);
  if (!pts.length) {
    graphUI.view = {
      k: 1,
      x: 0,
      y: 0
    };
  } else {
    let minX = Math.min(...pts.map(p => p.x)),
      maxX = Math.max(...pts.map(p => p.x)),
      minY = Math.min(...pts.map(p => p.y)),
      maxY = Math.max(...pts.map(p => p.y));
    let k = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, Math.min(VIEW_W / (maxX - minX + 180), VIEW_H / (maxY - minY + 160), 1.5)));
    graphUI.view = {
      k,
      x: VIEW_W / 2 - (minX + maxX) / 2 * k,
      y: VIEW_H / 2 - (minY + maxY) / 2 * k
    };
  }
  applyView();
}

// zoomAt scales the view while keeping the point (px,py) under the cursor.
function zoomAt(px, py, factor) {
  let v = graphUI.view || (graphUI.view = {
    k: 1,
    x: 0,
    y: 0
  });
  let k = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, v.k * factor));
  if (k === v.k) return;
  v.x = px - (px - v.x) * k / v.k;
  v.y = py - (py - v.y) * k / v.k;
  v.k = k;
  applyView();
}

// worldPoint converts a pointer event to graph coordinates: screen → viewBox →
// viewport transform. Peer dragging and background panning both work at any
// zoom level through this.
function worldPoint(svg, e) {
  let p = svgPoint(svg, e);
  let v = graphUI.view || {
    k: 1,
    x: 0,
    y: 0
  };
  return {
    x: (p.x - v.x) / v.k,
    y: (p.y - v.y) / v.k
  };
}
const titles = {
  overview: ['Network overview', 'Health and connectivity at a glance'],
  peers: ['Peers', 'Inventory, roles and endpoints'],
  topology: ['Topology', 'Edit routes and roles directly on the graph'],
  forwards: ['Reverse ports', 'Forward a local source port to another peer’s LAN'],
  access: ['Setup keys', 'Enroll new devices securely'],
  events: ['Events', 'Administrative audit trail'],
  settings: ['Settings', 'Topology policy and device administration']
};
const edgeKey = (a, b) => a < b ? a + '|' + b : b + '|' + a;
const esc = value => {
  let x = document.createElement('span');
  x.textContent = value ?? '';
  return x.innerHTML
};
// esc() does not escape quotes; attribute values need this.
const escAttr = value => esc(value).replace(/"/g, '&quot;');
const peerLabel = n => n.name || n.node_id.slice(0, 8);
const peerID = n => n.node_id.slice(0, 8);
const peerSub = n => duration(n.uptime_seconds) + ' up';

function duration(seconds) {
  seconds = Number(seconds) || 0;
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds/60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds/3600)}h`;
  return `${Math.floor(seconds/86400)}d`
}

function toast(text) {
  let x = $('toast');
  x.textContent = text;
  x.classList.add('show');
  setTimeout(() => x.classList.remove('show'), 2500)
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text)
  } catch (e) {
    // The clipboard API needs a secure context; fall back for plain HTTP.
    let x = document.createElement('textarea');
    x.value = text;
    x.style.position = 'fixed';
    x.style.opacity = '0';
    document.body.appendChild(x);
    x.select();
    try {
      document.execCommand('copy')
    } catch (e2) {}
    x.remove()
  }
  toast('Copied to clipboard')
}
async function api(path, options = {}) {
  options.headers = {
    ...(options.headers || {}),
    'X-Mesh-Token': $('token').value
  };
  let r = await fetch(path, options),
    body = await r.json();
  if (!r.ok) throw Error(body.error || r.statusText);
  return body
}

function activeTopology() {
  return state.topology
}

function setScope(scope) {
  if (!state.topologies[scope]) return;
  state.scope = scope;
  state.topology = state.topologies[scope];
  $('topologyScope').value = scope;
  graphUI.source = null;
  graphUI.selectedNode = null;
  graphUI.selectedEdge = null;
  render()
}

function page(name) {
  document.querySelectorAll('.page').forEach(x => x.classList.toggle('active', x.id === name));
  document.querySelectorAll('nav button').forEach(x => x.classList.toggle('active', x.dataset.page === name));
  $('pageTitle').textContent = titles[name][0];
  $('subtitle').textContent = titles[name][1]
}
document.querySelectorAll('nav button').forEach(x => x.onclick = () => page(x.dataset.page));

function layout(force = false) {
  let nodes = state.topology.nodes || [];
  // New peers join on a ring around the current cloud instead of a fixed
  // center, so an unbounded canvas keeps the graph compact as it grows.
  // Only currently registered peers count: stale positions of removed nodes
  // must not pull the ring off-center.
  let ids = new Set(nodes.map(n => n.node_id)),
    placed = Object.entries(graphUI.positions).filter(([id]) => ids.has(id)).map(([, p]) => p),
    cx = placed.length ? placed.reduce((s, p) => s + p.x, 0) / placed.length : 550,
    cy = placed.length ? placed.reduce((s, p) => s + p.y, 0) / placed.length : 300,
    R = Math.min(225, 95 + nodes.length * 13);
  nodes.forEach((n, i) => {
    if (force || !graphUI.positions[n.node_id]) {
      let a = i * Math.PI * 2 / Math.max(1, nodes.length) - Math.PI / 2;
      graphUI.positions[n.node_id] = {
        x: cx + R * Math.cos(a),
        y: cy + R * Math.sin(a)
      };
    }
  });
}

function overviewGraph() {
  let svg = $('overviewGraph'),
    nodes = state.topology.nodes || [],
    links = state.topology.links || [],
    p = {},
    cx = 500,
    cy = 260,
    R = Math.min(205, 80 + nodes.length * 12);
  nodes.forEach((n, i) => {
    let a = i * Math.PI * 2 / Math.max(1, nodes.length) - Math.PI / 2;
    p[n.node_id] = {
      x: cx + R * Math.cos(a),
      y: cy + R * Math.sin(a)
    }
  });
  svg.innerHTML = links.map(e => {
    let a = p[e.a],
      b = p[e.b];
    return a && b ? `<line class="edge ${esc(e.status||'unknown')}${e.via_lan?' lan':''}" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"/>` : ''
  }).join('') + nodes.map(n => {
    let q = p[n.node_id];
    return `<g data-peer="${esc(n.node_id)}"><circle class="node ${esc(n.role)}" cx="${q.x}" cy="${q.y}" r="19"/><text class="svgLabel" text-anchor="middle" x="${q.x}" y="${q.y+38}">${esc(peerLabel(n))}</text><text class="svgLabel nodeID" text-anchor="middle" x="${q.x}" y="${q.y+51}">${esc(peerID(n))}</text><text class="svgLabel nodeUptime" text-anchor="middle" x="${q.x}" y="${q.y+64}">${esc(peerSub(n))}</text></g>`
  }).join('');
  svg.querySelectorAll('[data-peer]').forEach(g => g.onclick = () => {
    page('topology');
    selectNode(g.dataset.peer)
  })
}

// graphSignature fingerprints everything drawInteractive renders. The live
// refresh re-renders the admin UI every few seconds; skipping identical
// rebuilds removes flicker and stops topology updates from interrupting
// hover states or an in-progress peer drag.
function graphSignature() {
  let nodes = (state.topology.nodes || []).map(n => {
      let p = graphUI.positions[n.node_id] || {};
      return [n.node_id, Math.round((p.x || 0) * 10) / 10, Math.round((p.y || 0) * 10) / 10, n.role, n.nat_type, peerLabel(n), peerSub(n)].join('~');
    }).sort().join(';'),
    links = (state.topology.links || []).map(e => [edgeKey(e.a, e.b), e.status, e.via_lan ? 1 : 0, Math.round(e.rtt_ms || 0), Math.round((e.cost || 0) * 100)].join('~')).sort().join(';');
  return [nodes, links, graphUI.source, graphUI.selectedNode, graphUI.selectedEdge].join('|');
}

function drawInteractive(force = false) {
  layout();
  if (!graphUI.view && (state.topology.nodes || []).length) fitView();
  if (graphUI.dragging) {
    updateMode();
    return
  }
  let sig = graphSignature();
  if (!force && sig === graphUI.lastSig) {
    updateMode();
    return
  }
  graphUI.lastSig = sig;
  let svg = $('topologyGraph'),
    nodes = state.topology.nodes || [],
    links = state.topology.links || [],
    manual = new Map((state.manualLinks || []).map(e => [edgeKey(e.a, e.b), e]));
  let edges = links.map(e => {
    let a = graphUI.positions[e.a],
      b = graphUI.positions[e.b],
      key = edgeKey(e.a, e.b);
    if (!a || !b) return '';
    let m = manual.get(key),
      cost = e.cost ? `cost ${Number(e.cost).toFixed(2)}` : 'cost —',
      rtt = e.rtt_ms ? `ping ${Math.round(e.rtt_ms)} ms` : 'ping —',
      path = e.via_lan ? 'LAN' : 'internet',
      label = `${path} · ${rtt} · ${cost}`,
      classes = ['edgeGroup'];
    if (graphUI.selectedEdge === key) classes.push('selected');
    if (graphUI.selectedNode && (e.a === graphUI.selectedNode || e.b === graphUI.selectedNode)) classes.push('adjacent');
    return `<g class="${classes.join(' ')}" data-edge="${esc(key)}"><line class="edge ${esc(e.status||'unknown')}${e.via_lan?' lan':''}" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"/><line class="edgeHit" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"/><text class="svgLabel" text-anchor="middle" x="${(a.x+b.x)/2}" y="${(a.y+b.y)/2-8}">${esc(label)}</text></g>`
  }).join('');
  let peerMarkup = nodes.map(n => {
    let q = graphUI.positions[n.node_id],
      classes = ['peerGroup'];
    if (graphUI.selectedNode === n.node_id) classes.push('selected');
    if (graphUI.source === n.node_id) classes.push('linkSource');
    let ring = n.nat_type === 'symmetric' ? '<circle class="sym" r="26"/>' : '';
    return `<g class="${classes.join(' ')}" data-peer="${esc(n.node_id)}" transform="translate(${q.x} ${q.y})">${ring}<circle class="node ${esc(n.role)}" r="20"/><text class="svgLabel" text-anchor="middle" y="40">${esc(peerLabel(n))}</text><text class="svgLabel nodeID" text-anchor="middle" y="53">${esc(peerID(n))}</text><text class="svgLabel nodeUptime" text-anchor="middle" y="66">${esc(peerSub(n))}</text></g>`
  }).join('');
  svg.innerHTML = `<g id="graphViewport">${edges}${peerMarkup}</g>`;
  svg.querySelectorAll('[data-edge]').forEach(g => g.onclick = e => {
    e.stopPropagation();
    selectEdge(g.dataset.edge)
  });
  svg.querySelectorAll('[data-peer]').forEach(bindPeerDrag);
  applyView();
  updateMode()
}

function svgPoint(svg, e) {
  let p = new DOMPoint(e.clientX, e.clientY);
  return p.matrixTransform(svg.getScreenCTM().inverse())
}

function bindPeerDrag(g) {
  let start, last, moved = false,
    svg = $('topologyGraph');
  g.onclick = e => e.stopPropagation();
  g.onpointerdown = e => {
    e.stopPropagation();
    start = last = worldPoint(svg, e);
    moved = false;
    graphUI.dragging = g.dataset.peer;
    g.setPointerCapture(e.pointerId);
    g.classList.add('dragging')
  };
  g.onpointermove = e => {
    if (!start) return;
    last = worldPoint(svg, e);
    let dx = last.x - start.x,
      dy = last.y - start.y;
    if (Math.hypot(dx, dy) > 4) moved = true;
    let q = graphUI.positions[g.dataset.peer];
    g.setAttribute('transform', `translate(${q.x+dx} ${q.y+dy})`)
  };
  g.onpointerup = e => {
    if (!start) return;
    g.classList.remove('dragging');
    graphUI.dragging = null;
    if (moved) {
      // The canvas is unbounded: peers may live anywhere on the plane.
      let q = graphUI.positions[g.dataset.peer];
      q.x += last.x - start.x;
      q.y += last.y - start.y;
      saveGraphPositions();
      drawInteractive()
    } else selectNode(g.dataset.peer);
    start = null
  }
}

function updateMode() {
  let x = $('graphMode');
  if (graphUI.source) {
    x.textContent = `Select a second peer to connect with ${graphUI.source.slice(0,8)}`;
    x.classList.add('active')
  } else {
    x.textContent = state.manualLinks.length ? 'Manual backbone + automatic client attachments · click a peer to start' : 'Automatic topology · click a peer to start';
    x.classList.remove('active')
  }
}

function cancelSelection(redraw = true) {
  graphUI.source = null;
  graphUI.selectedNode = null;
  graphUI.selectedEdge = null;
  $('nodeDetail').textContent = 'Select a peer or link to edit it directly.';
  if (redraw) drawInteractive();
  else updateMode()
}

function selectNode(id) {
  let node = (state.topology.nodes || []).find(n => n.node_id === id);
  if (!node) return;
  if (graphUI.source && graphUI.source !== id) {
    addDirectEdge(graphUI.source, id);
    return
  }
  graphUI.source = id;
  graphUI.selectedNode = id;
  graphUI.selectedEdge = null;
  drawInteractive();
  renderNodeInspector(node)
}

function renderNodeInspector(n) {
  let box = $('nodeDetail'),
    routes = n.routes || [],
    records = n.dns_records || [];
  box.innerHTML = `<b class="copyable" data-copy="${escAttr(n.node_id)}" title="Click to copy the full node ID">${esc(n.node_id.slice(0,12))}</b><span><code class="copyable" data-copy="${escAttr(n.mesh_ip)}" title="Click to copy">${esc(n.mesh_ip)}</code> · ${esc(n.nat_type)} NAT<br>${esc(routes.map(r=>r.lan_cidr+' → '+r.virtual_cidr).join(', '))}</span><label>Node DNS name <input id="directName" value="${esc(n.name||'')}" placeholder="office"></label><label>Physical LAN CIDRs <input id="directRoutes" value="${esc(routes.map(r=>r.lan_cidr).join(', '))}" placeholder="192.168.1.0/24, 192.168.2.0/24"></label><small class="muted">Multiple CIDRs are comma-separated. Saving replaces the complete list.</small><div id="directRouteList">${routes.map(r=>`<div class="routeRow"><code>${esc(r.lan_cidr)} → ${esc(r.virtual_cidr)}</code><button class="ghost" data-remove-route="${esc(r.lan_cidr)}">Revoke</button></div>`).join('')||'<span class="muted">No advertised subnets</span>'}</div><div class="toolbar"><input id="directRouteAdd" placeholder="192.168.10.0/24"><button id="directRouteAddButton">Add subnet</button></div><label>LAN objects (one name=IP per line)<textarea id="directDNSRecords" rows="3" placeholder="printer=192.168.1.20">${esc(records.map(r=>r.name+'='+r.ip).join('\n'))}</textarea></label><button id="directNetworkSave">Allocate addresses and save</button><button id="directRoutesClear" class="dangerButton">Revoke all subnets</button><span class="spacer"></span><label>Role <select id="directRole"><option value="auto">Automatic</option><option value="client">Client</option><option value="superpeer">Superpeer</option></select></label><button id="directRoleSave">Apply role</button><button id="directRemove" class="dangerButton">Remove peer</button>`;
  $('directRole').value = n.requested_role || 'auto';
  $('directRoleSave').onclick = () => setRole(n.node_id, $('directRole').value);
  $('directNetworkSave').onclick = () => setNetwork(n.node_id);
  $('directRoutesClear').onclick = () => clearNetwork(n.node_id);
  $('directRouteAddButton').onclick = () => addRoute(n.node_id);
  $('directRouteList').querySelectorAll('[data-remove-route]').forEach(b => b.onclick = () => removeRoute(n.node_id, b.dataset.removeRoute));
  $('directRemove').onclick = () => removePeer(n.node_id)
}

function selectEdge(key) {
  graphUI.source = null;
  graphUI.selectedNode = null;
  graphUI.selectedEdge = key;
  drawInteractive();
  let live = (state.topology.links || []).find(e => edgeKey(e.a, e.b) === key),
    manual = (state.manualLinks || []).find(e => edgeKey(e.a, e.b) === key);
  if (!live) return;
  let box = $('nodeDetail');
  box.innerHTML = `<b>${esc(live.a.slice(0,8))} ↔ ${esc(live.b.slice(0,8))}</b><span>${live.rtt_ms?Math.round(live.rtt_ms)+' ms':'No RTT'} · ${esc(live.status||'unknown')} · ${live.via_lan?'LAN path':'internet path'}</span><span class="spacer"></span><label>Route cost <input id="directCost" type="number" min="0.1" max="1000" step="0.1" value="${manual?.cost||live.cost||1}"></label><button id="directCostSave">Save cost</button><button id="directEdgeRemove" class="dangerButton">Remove link</button>`;
  $('directCostSave').onclick = () => saveDirectEdge(live.a, live.b, Number($('directCost').value));
  $('directEdgeRemove').onclick = e => {
    e.preventDefault();
    e.stopPropagation();
    removeDirectEdge(key, e.currentTarget)
  }
}

function seedManual() {
  // Automatic links must not be copied into the manual graph. Otherwise
  // deleting one causes the automatic client attachment logic to recreate it.
}
async function publishEdges(message) {
  await api('/v1/admin/graph', {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      links: state.manualLinks,
      blocked_links: state.blockedLinks
    })
  });
  toast(message || (state.manualLinks.length ? 'Manual topology published' : 'Automatic topology restored'));
  await load()
}
async function addDirectEdge(a, b) {
  let cost = Number($('quickCost').value);
  if (!(cost > 0 && cost <= 1000)) return toast('Cost must be between 0.1 and 1000');
  try {
    seedManual();
    let key = edgeKey(a, b),
      e = state.manualLinks.find(x => edgeKey(x.a, x.b) === key);
    if (e) e.cost = cost;
    else state.manualLinks.push({
      a,
      b,
      cost
    });
    state.blockedLinks = state.blockedLinks.filter(e => edgeKey(e.a, e.b) !== key);
    cancelSelection();
    await publishEdges('Link saved and pushed')
  } catch (e) {
    toast(e.message)
  }
}
async function saveDirectEdge(a, b, cost) {
  if (!(cost > 0 && cost <= 1000)) return toast('Cost must be between 0.1 and 1000');
  try {
    seedManual();
    let key = edgeKey(a, b),
      e = state.manualLinks.find(x => edgeKey(x.a, x.b) === key);
    if (e) e.cost = cost;
    else state.manualLinks.push({
      a,
      b,
      cost
    });
    state.blockedLinks = state.blockedLinks.filter(e => edgeKey(e.a, e.b) !== key);
    await publishEdges('Link cost updated')
  } catch (e) {
    toast(e.message)
  }
}
async function removeDirectEdge(key, button) {
  try {
    if (button) button.disabled = true;
    seedManual();
    state.manualLinks = state.manualLinks.filter(e => edgeKey(e.a, e.b) !== key);
    // A deleted manual edge must also stay deleted when automatic topology
    // would otherwise select the same client-superpeer pair again.
    if (!state.blockedLinks.some(e => edgeKey(e.a, e.b) === key)) {
      let [a, b] = key.split('|');
      state.blockedLinks.push({a, b, cost: 1});
    }
    cancelSelection();
    await publishEdges('Link removed and topology pushed')
  } catch (e) {
    toast(e.message)
  }
}
async function setRole(id, role) {
  try {
    await api('/v1/admin/nodes/' + encodeURIComponent(id) + '/role', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        role
      })
    });
    toast('Role applied and topology pushed');
    await load()
  } catch (e) {
    toast(e.message)
  }
}
async function setNetwork(id) {
  try {
    let routes = $('directRoutes').value.split(',').map(x => x.trim()).filter(Boolean),
      dns_records = $('directDNSRecords').value.split(/\n+/).map(x => x.trim()).filter(Boolean).map(x => {
        let at = x.indexOf('=');
        if (at < 1) throw Error('Use name=IP for every LAN object');
        return {
          name: x.slice(0, at).trim(),
          ip: x.slice(at + 1).trim()
        }
      });
    await api('/v1/admin/nodes/' + encodeURIComponent(id) + '/network', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        name: $('directName').value.trim(),
        routes,
        dns_records
      })
    });
    graphUI.source = null;
    toast('Virtual addresses and DNS names pushed');
    await load();
    drawInteractive()
  } catch (e) {
    toast(e.message)
  }
}
async function clearNetwork(id) {
  if (!confirm('Revoke all advertised subnets and LAN DNS records?')) return;
  try {
    await api('/v1/admin/nodes/' + encodeURIComponent(id) + '/network', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        name: $('directName').value.trim(),
        routes: [],
        dns_records: []
      })
    });
    toast('All advertised subnets revoked');
    await load();
    drawInteractive()
  } catch (e) {
    toast(e.message)
  }
}
async function addRoute(id) {
  let route = $('directRouteAdd').value.trim();
  if (!route) return;
  try {
    await api('/v1/admin/nodes/' + encodeURIComponent(id) + '/network/routes', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        route
      })
    });
    toast('Subnet added');
    await load();
    drawInteractive()
  } catch (e) {
    toast(e.message)
  }
}
async function removeRoute(id, route) {
  if (!confirm(`Revoke subnet ${route}?`)) return;
  try {
    await api('/v1/admin/nodes/' + encodeURIComponent(id) + '/network/routes', {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        route
      })
    });
    toast('Subnet revoked');
    await load();
    drawInteractive()
  } catch (e) {
    toast(e.message)
  }
}
async function removePeer(id) {
  if (!confirm(`Remove peer ${id.slice(0,12)}?`)) return;
  try {
    await api('/v1/admin/nodes/' + encodeURIComponent(id), {
      method: 'DELETE'
    });
    delete graphUI.positions[id];
    saveGraphPositions();
    cancelSelection();
    toast('Peer removed');
    await load()
  } catch (e) {
    toast(e.message)
  }
}

function render() {
  let t = state.topology,
    n = t.nodes || [],
    links = t.links || [],
    rtts = links.filter(x => x.rtt_ms).map(x => x.rtt_ms),
    up = links.filter(x => x.status === 'up').length;
  $('nodesN').textContent = n.length;
  $('superN').textContent = n.filter(x => x.role === 'superpeer').length;
  $('upN').textContent = up;
  $('rttN').textContent = rtts.length ? Math.round(rtts.reduce((a, b) => a + b, 0) / rtts.length) + ' ms' : '—';
  $('healthPct').textContent = (links.length ? Math.round(up * 100 / links.length) : 0) + '% available';
  $('peerBadge').textContent = n.length;
  overviewGraph();
  drawInteractive();
  $('healthList').innerHTML = links.slice(0, 8).map(x => `<p><span class="statusDot" style="background:${x.status==='up'?'#22c55e':'#ef4444'}"></span> ${esc(x.a.slice(0,6))} → ${esc(x.b.slice(0,6))} <b>${x.rtt_ms?Math.round(x.rtt_ms)+'ms':esc(x.status)}</b></p>`).join('') || '<p class="muted">No links yet</p>';
  $('eventPreview').innerHTML = state.audit.slice(0, 5).map(x => `<p><b>${esc(x.event)}</b><br><span class="muted">${new Date(x.created_at*1000).toLocaleString()}</span></p>`).join('');
  renderPeers();
  renderEditor();
  renderAudit();
  $('inviteRows').innerHTML = state.invites.map(x => `<tr><td><code>${esc(x.token)}</code></td><td>${new Date(x.expires_at*1000).toLocaleTimeString()}</td><td><span class="chip">${x.used?'used':'active'}</span></td></tr>`).join('') || '<tr><td colspan="3" class="muted">No active setup keys.</td></tr>';
  for (let k in state.config) {
    let f = $('settingsForm').elements[k];
    if (f && !isDirtySetting(f)) f.value = state.config[k] || ''
  }
  $('removePeer').innerHTML = n.map(x => `<option value="${esc(x.node_id)}">${esc(x.node_id.slice(0,12))} · ${esc(x.mesh_ip)}</option>`).join('')
}

function renderAudit() {
  let q = ($('eventSearch').value || '').toLowerCase(),
    items = state.audit.filter(x => !q || ((x.event || '') + ' ' + (x.detail || '')).toLowerCase().includes(q));
  $('auditRows').innerHTML = items.map(x => `<tr><td>${new Date(x.created_at*1000).toLocaleString()}</td><td>${esc(x.event)}</td><td>${esc(x.detail)}</td></tr>`).join('') || `<tr><td colspan="3" class="muted">${state.audit.length ? 'Nothing matches the filter.' : 'No events recorded yet.'}</td></tr>`
}

function renderEditor() {
  let n = state.topology.nodes || [],
    options = n.map(x => `<option value="${esc(x.node_id)}">${esc(x.node_id.slice(0,10))} · ${esc(x.mesh_ip)}</option>`).join('');
  for (let id of ['edgeA', 'edgeB', 'rolePeer']) $(id).innerHTML = options;
  let telemetry = new Map((state.topology.links || []).map(x => [edgeKey(x.a, x.b), x]));
  $('edgeRows').innerHTML = (state.manualLinks || []).map((x, i) => {
    let live = telemetry.get(edgeKey(x.a, x.b));
    return `<tr><td>${esc(x.a.slice(0,10))}</td><td>${esc(x.b.slice(0,10))}</td><td>${x.cost}</td><td>${live?.rtt_ms?Math.round(live.rtt_ms)+' ms':'—'}</td><td><button class="ghost" data-delete-edge="${i}">Remove</button></td></tr>`
  }).join('') || '<tr><td colspan="5" class="muted">Automatic topology is active.</td></tr>';
  $('edgeRows').querySelectorAll('[data-delete-edge]').forEach(b => b.onclick = () => deleteEdge(Number(b.dataset.deleteEdge)))
}
async function load() {
  try {
    let [config, topology, audit, invites, graphData] = await Promise.all([api('/v1/admin/config'), api('/v1/admin/topology'), api('/v1/admin/audit'), api('/v1/admin/invites'), api('/v1/admin/graph')]);
    state = {
      config,
      topology,
      audit: audit || [],
      invites: invites || [],
      manualLinks: graphData.links || [],
      blockedLinks: graphData.blocked_links || []
    };
    applySettingsFromServer();
    $('inviteRows').innerHTML = state.invites.map(x => `<tr><td><code>${esc(x.token)}</code></td><td>${new Date(x.expires_at*1000).toLocaleTimeString()}</td><td><span class="chip">${x.used?'used':'active'}</span></td></tr>`).join('') || '<tr><td colspan="3" class="muted">No active setup keys.</td></tr>';
    $('liveDot').classList.add('live');
    $('liveText').textContent = 'Live · ' + new Date().toLocaleTimeString();
    renderDNSNodeChoice(topology.nodes || []);
    render()
  } catch (e) {
    $('liveDot').classList.remove('live');
    $('liveText').textContent = 'Disconnected';
    toast(e.message)
  }
}
async function deleteEdge(i) {
  try {
    let edge = state.manualLinks[i];
    state.manualLinks.splice(i, 1);
    if (edge && !state.blockedLinks.some(x => edgeKey(x.a, x.b) === edgeKey(edge.a, edge.b))) {
      state.blockedLinks.push({a: edge.a, b: edge.b, cost: 1});
    }
    await publishEdges('Link removed')
  } catch (e) {
    toast(e.message)
  }
}
$('peerSearch').oninput = renderPeers;
$('roleFilter').onchange = renderPeers;
$('natFilter').onchange = renderPeers;
$('eventSearch').oninput = renderAudit;
$('fitGraph').onclick = () => {
  layout(true);
  saveGraphPositions();
  drawInteractive(true);
  fitView()
};
$('cancelGraph').onclick = () => cancelSelection();
$('settingsForm').onsubmit = async e => {
  e.preventDefault();
  try {
    let body = {};
    for (let x of new FormData(e.target)) body[x[0]] = x[0] === 'dns_upstream' ? x[1].trim() : Number(x[1]);
    await api('/v1/admin/config', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    });
    toast('Policy saved and pushed');
    for (const field of e.target.elements) if (field.name) field.dataset.dirty = '0';
    load()
  } catch (x) {
    toast(x.message)
  }
};
$('addEdge').onclick = () => {
  $('quickCost').value = $('edgeCost').value;
  addDirectEdge($('edgeA').value, $('edgeB').value)
};
$('edgeCost').oninput = () => $('quickCost').value = $('edgeCost').value;
$('autoGraph').onclick = async () => {
  if (confirm('Discard manual links and restore automatic topology?')) {
    try {
      state.manualLinks = [];
      state.blockedLinks = [];
      cancelSelection();
      await publishEdges('Automatic topology restored')
    } catch (e) {
      toast(e.message)
    }
  }
};
$('createInvite').onclick = async () => {
  try {
    let x = await api('/v1/admin/invites', {
      method: 'POST'
    });
    $('newInvite').textContent = x.invite_token;
    toast('Setup key created');
    load()
  } catch (e) {
    toast(e.message)
  }
};
$('loadGraph').onclick = async () => {
  try {
    let x = await api('/v1/admin/graph');
    $('graphText').value = (x.links || []).map(e => `${e.a} ${e.b} ${e.cost}`).join('\n')
  } catch (e) {
    toast(e.message)
  }
};
$('saveGraph').onclick = async () => {
  try {
    let text = $('graphText').value.trim();
    state.manualLinks = text ? text.split(/\n+/).map(x => {
      let p = x.trim().split(/\s+/);
      return {
        a: p[0],
        b: p[1],
        cost: Number(p[2])
      }
    }) : [];
    await publishEdges('Raw graph published')
  } catch (e) {
    toast(e.message)
  }
};
$('removeButton').onclick = () => removePeer($('removePeer').value);
$('token').value = sessionStorage.getItem('meshToken') || '';

function renderAllRemoveList() {
  let n = state.topologies.all?.nodes || state.topology.nodes || [];
  $('removePeer').innerHTML = n.map(x => `<option value="${esc(x.node_id)}">${esc(x.node_id.slice(0,12))} · ${esc(x.mesh_ip)} · ${x.online===false?'offline':'online'}</option>`).join('')
}
async function loadScopes() {
  try {
    let [config, online, all, audit, invites, graphData, updates] = await Promise.all([api('/v1/admin/config'), api('/v1/admin/topology?scope=online'), api('/v1/admin/topology?scope=all'), api('/v1/admin/audit'), api('/v1/admin/invites'), api('/v1/admin/graph'), api('/v1/admin/updates')]);
    state = {
      config,
      topology: (state.scope === 'all' ? all : online),
      topologies: {
        online,
        all
      },
      scope: state.scope,
      audit: audit || [],
      invites: invites || [],
      manualLinks: graphData.links || [],
      blockedLinks: graphData.blocked_links || [],
      updates: updates || {
        urls: {},
        binaries: [],
        results: {}
      }
    };
    $('inviteRows').innerHTML = state.invites.map(x => `<tr><td><code>${esc(x.token)}</code></td><td>${new Date(x.expires_at*1000).toLocaleTimeString()}</td><td><span class="chip">${x.used?'used':'active'}</span></td></tr>`).join('') || '<tr><td colspan="3" class="muted">No active setup keys.</td></tr>';
    applySettingsFromServer();
    renderDNSNodeChoice(all.nodes || []);
    $('liveDot').classList.add('live');
    $('liveText').textContent = 'Live · ' + new Date().toLocaleTimeString();
    // Refresh every view derived from the new scoped snapshot together.
    render();
    renderAllRemoveList();
    renderUpdates()
  } catch (e) {
    $('liveDot').classList.remove('live');
    $('liveText').textContent = 'Disconnected';
    toast(e.message)
  }
}

function load() {
  return loadScopes()
}

function isDirtySetting(field) {
  return field.dataset.dirty === '1' || document.activeElement === field;
}

function applySettingsFromServer() {
  for (let k in state.config) {
    const field = $('settingsForm').elements[k];
    if (field && !isDirtySetting(field)) field.value = state.config[k] || '';
  }
}

function renderDNSNodeChoice(nodes) {
  const select = $('dnsNodeChoice');
  if (!select) return;
  const field = $('settingsForm').elements.dns_upstream;
  const current = field ? field.value : '';
  select.innerHTML = '<option value="">Select a Mesh node...</option>' + (nodes || [])
    .filter(node => node.mesh_ip)
    .map(node => `<option value="${esc(node.mesh_ip)}:53">${esc(node.name || node.node_id.slice(0, 12))} · ${esc(node.mesh_ip)}${node.online === false ? ' · offline' : ''}</option>`)
    .join('');
  if ([...select.options].some(option => option.value === current)) {
    select.value = current;
  }
}

// Keep the visualization responsive to registrations, disconnects and
// telemetry changes without waiting for the slower full admin refresh.
async function refreshGraph() {
  try {
    let [online, all] = await Promise.all([
      api('/v1/admin/topology?scope=online'),
      api('/v1/admin/topology?scope=all')
    ]);
    state.topologies = {online, all};
    state.topology = state.scope === 'all' ? all : online;
    renderDNSNodeChoice(all.nodes || []);
    render();
    renderAllRemoveList();
  } catch (e) {
    // The normal refresh reports authentication/network errors to the user.
  }
}
function startLiveRefresh() {
  clearInterval(timer);
  clearInterval(graphTimer);
  timer = setInterval(loadScopes, 10000);
  graphTimer = setInterval(refreshGraph, 3000);
}
$('connect').onclick = () => {
  sessionStorage.setItem('meshToken', $('token').value);
  loadScopes();
  startLiveRefresh()
};
$('refresh').onclick = loadScopes;
$('topologyScope').onchange = e => {
  setScope(e.target.value)
};

// One delegated listener powers every copy affordance: explicit [data-copy]
// values, buttons pointing at a [data-copy-target] box, and the one-time codes
// shown in .inviteCode boxes (setup key lives only 60 seconds — copying must
// be one click).
document.body.addEventListener('click', e => {
  let box = e.target.closest('[data-copy-target]');
  if (box) {
    let el = $(box.dataset.copyTarget),
      v = el ? el.textContent.trim() : '';
    if (!v || v === '—') return toast('Generate a code first');
    return copyText(v)
  }
  let c = e.target.closest('[data-copy]');
  if (c) return copyText(c.dataset.copy);
  let code = e.target.closest('.inviteCode');
  if (code) {
    let v = code.textContent.trim();
    if (v && v !== '—') copyText(v)
  }
});

// Keyboard: Enter submits the bare inputs that are not wrapped in a form
// (network token, account login), Escape leaves graph linking/selection mode.
$('token').addEventListener('keydown', e => {
  if (e.key === 'Enter') $('connect').click()
});
$('accountUsername').addEventListener('keydown', e => {
  if (e.key === 'Enter') accountLogin()
});
$('accountPassword').addEventListener('keydown', e => {
  if (e.key === 'Enter') accountLogin()
});
$('accountRegistrationInvite').addEventListener('keydown', e => {
  if (e.key === 'Enter') accountRegister()
});
document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  if (graphUI.source || graphUI.selectedNode || graphUI.selectedEdge) cancelSelection()
});

// Infinite graph canvas: wheel zooms around the cursor, dragging the
// background pans, double-click fits the graph, and the floating controls
// offer zoom in/out/fit/reset. View state persists across sessions.
(function bindGraphCanvas() {
  graphUI.view = loadView();
  let svg = $('topologyGraph');
  if (!svg) return;
  svg.addEventListener('wheel', e => {
    e.preventDefault();
    let p = svgPoint(svg, e);
    zoomAt(p.x, p.y, e.deltaY < 0 ? 1.12 : 1 / 1.12)
  }, {
    passive: false
  });
  let pan = null;
  svg.addEventListener('pointerdown', e => {
    if (e.pointerType === 'mouse' && e.button !== 0) return;
    if (e.target.closest('.peerGroup, .edgeGroup')) return;
    pan = {
      start: svgPoint(svg, e),
      view: {
        ...(graphUI.view || {
          k: 1,
          x: 0,
          y: 0
        })
      },
      moved: false
    };
    svg.setPointerCapture(e.pointerId);
    svg.classList.add('panning')
  });
  svg.addEventListener('pointermove', e => {
    if (!pan) return;
    let p = svgPoint(svg, e),
      dx = p.x - pan.start.x,
      dy = p.y - pan.start.y;
    if (Math.hypot(dx, dy) > 4) pan.moved = true;
    graphUI.view = {
      k: pan.view.k,
      x: pan.view.x + dx,
      y: pan.view.y + dy
    };
    applyView()
  });
  svg.addEventListener('pointerup', () => {
    if (!pan) return;
    let moved = pan.moved;
    pan = null;
    svg.classList.remove('panning');
    // A click without movement on empty space clears the selection.
    if (!moved) cancelSelection()
  });
  svg.addEventListener('pointercancel', () => {
    pan = null;
    svg.classList.remove('panning')
  });
  svg.addEventListener('dblclick', e => {
    if (e.target.closest('.peerGroup, .edgeGroup')) return;
    fitView()
  });
  $('zoomIn').onclick = () => zoomAt(VIEW_W / 2, VIEW_H / 2, 1.25);
  $('zoomOut').onclick = () => zoomAt(VIEW_W / 2, VIEW_H / 2, 1 / 1.25);
  $('zoomFit').onclick = () => fitView();
  $('zoomReset').onclick = () => {
    graphUI.view = {
      k: 1,
      x: 0,
      y: 0
    };
    applyView()
  }
})();

function renderPeers() {
  // The scoped/live loader refreshes the table directly without calling the
  // full render(), so keep the navigation badge in sync with the same data.
  $('peerBadge').textContent = (state.topology.nodes || []).length;
  let q = $('peerSearch').value.toLowerCase(),
    role = $('roleFilter').value,
    nat = $('natFilter').value,
    n = (state.topology.nodes || []).filter(x => (!role || x.role === role) && (!nat || x.nat_type === nat) && (!q || JSON.stringify(x).toLowerCase().includes(q)));
  // Online peers first so offline devices cannot bury the live fleet;
  // alphabetical inside each group.
  n = [...n].sort((a, b) => (a.online === false) - (b.online === false) || String(a.name || a.node_id).localeCompare(String(b.name || b.node_id)));
  $('peerRows').innerHTML = n.map(x => {
    let online = x.online !== false;
    return `<tr${online ? '' : ' class="offlineRow"'}><td><span class="statusDot ${online?'online':'offline'}"></span> ${online?'online':'offline'} · ${esc(peerSub(x))}</td><td title="${escAttr(x.node_id)}"><b>${esc(x.name||x.node_id.slice(0,12))}</b><br><small>${esc((x.routes||[]).map(r=>r.lan_cidr+' → '+r.virtual_cidr).join(', '))}</small></td><td><span class="chip">${esc(x.role)}</span></td><td>${esc(x.nat_type)}</td><td><code class="copyable" data-copy="${escAttr(x.mesh_ip)}" title="Click to copy">${esc(x.mesh_ip)}</code></td><td title="${escAttr(x.endpoint)}">${esc(x.endpoint)}</td><td>${x.capacity}</td><td><button class="ghost" data-inspect="${esc(x.node_id)}" title="${escAttr(x.node_id)}">Inspect</button></td></tr>`
  }).join('');
  $('peerRows').querySelectorAll('[data-inspect]').forEach(b => b.onclick = () => {
    page('topology');
    selectNode(b.dataset.inspect)
  })
}
if ($('token').value) $('connect').click();

function cookieValue(name) {
  let prefix = name + '=';
  return document.cookie.split(';').map(x => x.trim()).find(x => x.startsWith(prefix))?.slice(prefix.length) || ''
}

function sessionCredential() {
  let token = cookieValue('mesh_csrf');
  if (token) $('token').value = token;
  return token
}
async function authJSON(path, options = {}) {
  options.credentials = 'same-origin';
  options.headers = {
    ...(options.headers || {}),
    'Content-Type': 'application/json'
  };
  let r = await fetch(path, options),
    body = await r.json();
  if (!r.ok) throw Error(body.error || r.statusText);
  return body
}

function accountError(e) {
  toast(e.message || String(e))
}
async function accountLogin() {
  try {
    let u = $('accountUsername').value.trim().toLowerCase(),
      p = $('accountPassword').value;
    if (!u || !p) throw Error('Enter account and password');
    await authJSON('/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        username: u,
        password: p
      })
    });
    sessionCredential();
    $('accountLogin').hidden = true;
    $('accountRegister').hidden = true;
    $('accountLogout').hidden = false;
    $('accountPassword').value = '';
    $('accountRegistrationInvite').value = '';
    toast('Signed in');
    await loadScopes();
    startLiveRefresh()
  } catch (e) {
    accountError(e)
  }
}
async function accountRegister() {
  try {
    let u = $('accountUsername').value.trim().toLowerCase(),
      p = $('accountPassword').value,
      invite = $('accountRegistrationInvite').value.trim();
    if (!u || !p) throw Error('Enter account and password');
    let created = await authJSON('/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        username: u,
        password: p,
        invite_token: invite
      })
    });
    if (created.network_token) $('accountNetworkToken').textContent = created.network_token;
    toast('Account created; copy the network token and sign in');
  } catch (e) {
    accountError(e)
  }
}
async function accountLogout() {
  try {
    await authJSON('/v1/auth/logout', {
      method: 'POST',
      headers: {
        'X-CSRF-Token': sessionCredential()
      }
    })
  } catch (e) {}
  sessionStorage.removeItem('meshToken');
  location.reload()
}

function renderAccountInvites(items) {
  let body = $('accountInviteRows');
  if (!body) return;
  body.innerHTML = (items || []).map(x => `<tr><td>${new Date(x.created_at*1000).toLocaleString()}</td><td>${new Date(x.expires_at*1000).toLocaleString()}</td><td><span class="chip">${x.used?'used':'active'}</span></td></tr>`).join('') || '<tr><td colspan="3" class="muted">No account invitations.</td></tr>'
}
async function loadAccountInvites() {
  let items = await api('/v1/admin/account-invites');
  renderAccountInvites(items)
}
const meshLoadScopes = loadScopes;
loadScopes = async function() {
  await meshLoadScopes();
  try {
    await loadAccountInvites()
  } catch (e) {}
}
$('accountLogin').onclick = accountLogin;
$('accountRegister').onclick = accountRegister;
$('accountLogout').onclick = accountLogout;
$('rotateAccountToken').onclick = async () => {
  if (!confirm('Rotate the network token? All devices using the current token will lose access and must be updated.')) return;
  let button = $('rotateAccountToken');
  button.disabled = true;
  try {
    let x = await authJSON('/v1/auth/token/rotate', {
      method: 'POST',
      headers: {
        'X-CSRF-Token': sessionCredential()
      }
    });
    $('accountNetworkToken').textContent = x.network_token;
    toast('Network token rotated; reconnect your devices with the new token')
  } catch (e) {
    accountError(e)
  } finally {
    button.disabled = false
  }
};
$('createAccountInvite').onclick = async () => {
  try {
    let x = await api('/v1/admin/account-invites', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: '{}'
    });
    $('newAccountInvite').textContent = x.invite_token;
    toast('Account invitation created; copy it now');
    await loadAccountInvites()
  } catch (e) {
    accountError(e)
  }
};
(async () => {
  try {
    let me = await authJSON('/v1/auth/me');
    if (me.authenticated && me.auth_type !== 'network_token') {
      sessionCredential();
      $('accountLogin').hidden = true;
      $('accountRegister').hidden = true;
      $('accountLogout').hidden = false;
      await loadScopes();
      startLiveRefresh()
    }
  } catch (e) {}
})();

// Reverse port forwarding is deliberately exposed as a separate page because
// the listener is created on a peer, not on the coordinator.
(() => {
  let nav = document.querySelector('nav'),
    button = document.createElement('button');
  button.dataset.page = 'forwards';
  button.textContent = 'Reverse ports';
  nav.insertBefore(button, nav.querySelector('[data-page="access"]'));
  button.onclick = () => {
    page('forwards');
    options();
    forwards();
  };

  function options() {
    // Keep this working with both the scoped and legacy topology loaders.
    let nodes = [
      ...(state.topologies?.all?.nodes || []),
      ...(state.topologies?.online?.nodes || []),
      ...(state.topology?.nodes || [])
    ],
      seen = new Set();
    nodes = nodes.filter(n => n?.node_id && !seen.has(n.node_id) && seen.add(n.node_id));
    let text = nodes.map(n => `<option value="${esc(n.node_id)}">${esc(n.name||n.node_id.slice(0,12))} · ${esc(n.mesh_ip)}</option>`).join('');
    $('forwardSource').innerHTML = text;
    $('forwardTarget').innerHTML = text
  }
  async function forwards() {
    try {
      // Loading existing rules must not be a prerequisite for peer options.
      options();
      let rows = await api('/v1/admin/forwards');
      $('forwardRows').innerHTML = rows.map(f => `<tr><td>${esc(f.source_node_id.slice(0,12))}</td><td><code>${esc(f.listen_host)}:${f.listen_port}</code></td><td>${esc(f.target_node_id.slice(0,12))} → <code>${esc(f.target_host)}:${f.target_port}</code></td><td><button class="ghost" data-forward-delete="${f.id}">Remove</button></td></tr>`).join('') || '<tr><td colspan="4" class="muted">No reverse ports configured.</td></tr>';
      $('forwardRows').querySelectorAll('[data-forward-delete]').forEach(b => b.onclick = async () => {
        if (!confirm('Remove this forwarding?')) return;
        try {
          await api('/v1/admin/forwards/' + b.dataset.forwardDelete, {
            method: 'DELETE'
          });
          toast('Forwarding removed');
          forwards()
        } catch (e) {
          toast(e.message)
        }
      })
    } catch (e) {}
  };
  $('forwardForm').onsubmit = async e => {
    e.preventDefault();
    try {
      await api('/v1/admin/forwards', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          source_node_id: $('forwardSource').value,
          listen_host: $('forwardListenHost').value.trim(),
          listen_port: Number($('forwardListenPort').value),
          target_node_id: $('forwardTarget').value,
          target_host: $('forwardHost').value.trim(),
          target_port: Number($('forwardTargetPort').value)
        })
      });
      toast('Forwarding created and pushed');
      e.target.reset();
      $('forwardListenHost').value = '127.0.0.1';
      await forwards()
    } catch (x) {
      toast(x.message)
    }
  };
  let original = loadScopes;
  loadScopes = async () => {
    await original();
    await forwards()
  };
  forwards();
})();

for (const field of $('settingsForm').elements) {
  if (field.name) field.oninput = () => { field.dataset.dirty = '1'; };
}
$('dnsNodeChoice').onchange = e => {
  if (e.target.value) {
    const field = $('settingsForm').elements.dns_upstream;
    field.value = e.target.value;
    field.dataset.dirty = '1';
  }
};


// ---------------------------------------------------------------------------
// Client updates: per-architecture links / stored binaries, dispatch and
// per-node status. Binaries live on the coordinator; links point anywhere
// (GitHub releases, for example). Nodes pick the entry matching their
// runtime.GOOS/GOARCH — binaries win over links — download in the
// background, replace their executable at the same path and restart.
// ---------------------------------------------------------------------------

const updateArchs = [
  {arch: 'linux/amd64', label: 'Linux x86_64 · mesh-node'},
  {arch: 'linux/arm64', label: 'Linux ARM64 · mesh-node-linux-arm64'},
  {arch: 'linux/mipsle', label: 'Linux MIPSle (OpenWrt) · mesh-node-linux-mipsle'},
  {arch: 'windows/amd64', label: 'Windows x86_64 · mesh-node.exe'}
];

function fmtUpdateSize(n) {
  return n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.round(n / 1024) + ' KB';
}

function renderUpdates() {
  let u = state.updates || {urls: {}, binaries: [], results: {}};
  let urls = u.urls || {};
  let binByArch = {};
  for (let b of u.binaries || []) binByArch[b.arch] = b;
  // Known architectures first, then anything the server reports beyond them.
  let archs = updateArchs.map(a => a.arch);
  for (let b of u.binaries || []) if (!archs.includes(b.arch)) archs.push(b.arch);
  for (let a of Object.keys(urls)) if (urls[a] && !archs.includes(a)) archs.push(a);
  $('updateRows').innerHTML = archs.map(arch => {
    let known = updateArchs.find(x => x.arch === arch);
    let b = binByArch[arch];
    let stored = b
      ? `<span class="chip">stored</span> ${esc(fmtUpdateSize(b.size))} · ${new Date(b.updated_at * 1000).toLocaleString()} <button class="ghost" data-del-binary="${esc(arch)}">Remove</button>`
      : '<input type="file" data-upload="' + esc(arch) + '" />';
    return `<tr><td>${esc(known ? known.label : 'Custom')}<br><code>${esc(arch)}</code></td>` +
      `<td><input type="text" data-url-arch="${esc(arch)}" value="${esc(urls[arch] || '')}" placeholder="https://github.com/owner/repo/releases/.."/></td>` +
      `<td>${stored}</td></tr>`;
  }).join('');
  let nodes = (state.topologies ? (state.topologies.online?.nodes || state.topologies.all?.nodes) : state.topology.nodes) || [];
  let current = $('updateTarget').value;
  $('updateTarget').innerHTML = '<option value="">All connected nodes</option>' + nodes
    .filter(n => n.online !== false)
    .map(n => `<option value="${esc(n.node_id)}">${esc(n.node_id.slice(0, 12))} · ${esc(n.mesh_ip || '?')}${n.goarch ? ' · ' + esc(n.goarch) : ''}</option>`)
    .join('');
  if ([...$('updateTarget').options].some(o => o.value === current)) $('updateTarget').value = current;
  let entries = Object.entries(u.results || {}).sort((a, b) => (b[1].at || 0) - (a[1].at || 0));
  $('updateStatusRows').innerHTML = entries.map(([id, r]) =>
    `<tr><td><code>${esc(id.slice(0, 12))}</code></td><td>${esc(r.goarch || '')}</td>` +
    `<td><span class="chip">${esc(r.status)}</span></td><td>${esc(r.detail || '')}</td>` +
    `<td>${r.at ? new Date(r.at * 1000).toLocaleTimeString() : ''}</td></tr>`
  ).join('') || '<tr><td colspan="5" class="muted">No update attempts yet.</td></tr>';
}

$('saveUpdateLinks').onclick = async () => {
  try {
    let urls = {};
    document.querySelectorAll('[data-url-arch]').forEach(x => {
      urls[x.dataset.urlArch] = x.value.trim();
    });
    await api('/v1/admin/updates', {method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({urls})});
    toast('Update links saved');
    load()
  } catch (e) {
    toast(e.message)
  }
};

$('updateDispatchForm').onsubmit = async e => {
  e.preventDefault();
  let id = $('updateTarget').value;
  let question = id
    ? 'Send the update command to the selected node? It will download the new binary and restart itself.'
    : 'Send the update command to ALL connected nodes? They will download the new binary and restart themselves.';
  if (!confirm(question)) return;
  try {
    let body = id ? {node_id: id} : {all: true};
    let x = await api('/v1/admin/updates/dispatch', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    let skipped = (x.results || []).filter(r => !r.ok);
    toast(skipped.length ? `Update sent; ${skipped.length} node(s) skipped (${skipped[0].detail || 'no source'})` : 'Update command delivered');
    load()
  } catch (e2) {
    toast(e2.message)
  }
};

document.body.addEventListener('change', e => {
  let input = e.target.closest('[data-upload]');
  if (input && input.files && input.files[0]) uploadUpdateBinary(input.dataset.upload, input.files[0]);
});

document.body.addEventListener('click', e => {
  let b = e.target.closest('[data-del-binary]');
  if (b) removeUpdateBinary(b.dataset.delBinary);
});

async function uploadUpdateBinary(arch, file) {
  if (!confirm(`Upload ${file.name} (${fmtUpdateSize(file.size)}) for ${arch}? Nodes on this architecture will update from the coordinator.`)) return;
  try {
    await api('/v1/admin/updates/binaries/' + encodeURIComponent(arch), {method: 'PUT', body: file});
    toast('Binary stored on the coordinator');
    load()
  } catch (e) {
    toast(e.message)
  }
}

async function removeUpdateBinary(arch) {
  if (!confirm(`Remove the stored ${arch} binary from the coordinator?`)) return;
  try {
    await api('/v1/admin/updates/binaries/' + encodeURIComponent(arch), {method: 'DELETE'});
    toast('Stored binary removed');
    load()
  } catch (e) {
    toast(e.message)
  }
}
