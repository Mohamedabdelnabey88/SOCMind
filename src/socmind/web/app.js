let payload = null;
let commandPayload = null;

const q = s => document.querySelector(s);
const qa = s => [...document.querySelectorAll(s)];
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

qa(".nav").forEach(btn => btn.addEventListener("click", () => {
  qa(".nav").forEach(x => x.classList.remove("active"));
  qa(".page").forEach(x => x.classList.remove("active"));
  btn.classList.add("active");
  q("#" + btn.dataset.target).classList.add("active");
  if (btn.dataset.target === "graph" && payload) drawGraph(payload.graph);
  if (btn.dataset.target === "command") loadCommandCenter();
}));

q("#refresh").addEventListener("click", () => { load(); loadCommandCenter(); });

function findingCard(f) {
  const reasons = f.rationale.map(x => "<li>" + esc(x) + "</li>").join("");
  return '<div class="finding">' +
    '<div class="finding-top"><h3>' + esc(f.title) + '</h3><div>' +
    '<span class="sev sev-' + esc(f.severity) + '">' + esc(f.severity.toUpperCase()) + '</span> ' +
    '<span class="score">' + f.score + '/100</span></div></div>' +
    '<div class="score">' + esc(f.triage.priority) + ' · ' + esc(f.triage.escalation) + '</div>' +
    '<ul>' + reasons + '</ul></div>';
}

async function load() {
  q("#health").textContent = "Loading";
  try {
    const res = await fetch("/api/case", {cache:"no-store"});
    if (!res.ok) throw new Error("HTTP " + res.status);
    payload = await res.json();
    q("#health").textContent = "Local · Ready";
    q("#caseTitle").textContent = payload.case_id;

    const metrics = [
      ["Events", payload.summary.events],
      ["Findings", payload.summary.findings],
      ["High Priority", payload.summary.critical_or_high],
      ["Highest Risk", payload.summary.highest_score],
      ["ATT&CK", payload.summary.techniques]
    ];
    q("#cards").innerHTML = metrics.map(m =>
      '<div class="metric"><span>' + esc(m[0]) + '</span><b>' + esc(m[1]) + '</b></div>'
    ).join("");

    q("#findingPreview").innerHTML = payload.findings.slice(0,4).map(findingCard).join("") || "<p>No findings.</p>";
    q("#findingList").innerHTML = payload.findings.map(findingCard).join("") || "<p>No findings.</p>";
    q("#findingCount").textContent = payload.findings.length + " findings";

    q("#hypotheses").innerHTML = payload.hypotheses.map(h =>
      '<div class="hypothesis"><strong>' + esc(h.name) + '</strong>' +
      '<span class="score"> · ' + h.confidence + '% confidence</span>' +
      '<div class="confidence"><i style="width:' + h.confidence + '%"></i></div></div>'
    ).join("") || "<p>No hypotheses generated.</p>";

    q("#timelineList").innerHTML = payload.timeline.map(e =>
      '<div class="event"><time>' + esc(e.timestamp) + '</time>' +
      '<strong>' + esc(e.host) + ' · ' + esc(e.source) + ' · ' + esc(e.event_id) + '</strong>' +
      '<p>' + esc(e.user || "—") + ' ' + esc(e.process || "") + ' ' +
      esc(e.command_line || e.dst_ip || e.src_ip || "") + '</p></div>'
    ).join("");

    q("#techniques").innerHTML = payload.techniques.map(t =>
      '<span class="chip">' + esc(t) + '</span>'
    ).join("") || '<span class="score">No techniques observed.</span>';

    q("#iocs").innerHTML = payload.iocs.map(i =>
      '<div><b>' + esc(i.type.toUpperCase()) + '</b> · ' + esc(i.value) +
      ' <span>(' + esc(i.scope) + ')</span></div>'
    ).join("") || "<div>No IOCs extracted.</div>";
  } catch (err) {
    q("#health").textContent = "Error";
    q("#caseTitle").textContent = "Dashboard failed to load";
  }
}

function drawGraph(graph) {
  const svg = q("#evidenceGraph");
  svg.innerHTML = "";
  const ns = "http://www.w3.org/2000/svg";
  const nodes = graph.nodes.map((n, i) => ({
    ...n,
    x: 140 + (i % 5) * 220,
    y: 100 + Math.floor(i / 5) * 180
  }));
  const map = new Map(nodes.map(n => [n.id, n]));
  const colors = {
    user:"#6da8ff", host:"#51d7c7", process:"#f4b860",
    ip:"#ff6b7a", persistence:"#b993ff", service:"#81d681"
  };

  for (const e of graph.edges) {
    const a = map.get(e.source), b = map.get(e.target);
    if (!a || !b) continue;
    const line = document.createElementNS(ns, "line");
    line.setAttribute("class", "edge");
    line.dataset.a = e.source; line.dataset.b = e.target;
    svg.appendChild(line);

    const text = document.createElementNS(ns, "text");
    text.setAttribute("class", "edge-label");
    text.textContent = e.relation;
    text.dataset.a = e.source; text.dataset.b = e.target;
    svg.appendChild(text);
  }

  for (const n of nodes) {
    const g = document.createElementNS(ns, "g");
    g.setAttribute("class", "node");
    g.dataset.id = n.id;

    const c = document.createElementNS(ns, "circle");
    c.setAttribute("r", "24");
    c.setAttribute("fill", colors[n.kind] || "#8fa5b2");
    c.setAttribute("stroke", "#d9edf3");

    const t = document.createElementNS(ns, "text");
    t.setAttribute("text-anchor", "middle");
    t.setAttribute("dy", "40");
    t.textContent = n.label.length > 22 ? n.label.slice(0,20) + "…" : n.label;

    g.append(c, t);
    svg.appendChild(g);

    g.addEventListener("click", () => {
      const rels = graph.edges.filter(e => e.source === n.id || e.target === n.id).length;
      q("#nodeDetail").innerHTML = "<strong>" + esc(n.kind.toUpperCase()) + "</strong><br>" +
        esc(n.label) + "<br><span>" + rels + " relationships</span>";
    });

    let drag = false, ox = 0, oy = 0;
    g.addEventListener("pointerdown", ev => {
      drag = true;
      g.setPointerCapture(ev.pointerId);
      ox = ev.offsetX - n.x;
      oy = ev.offsetY - n.y;
    });
    g.addEventListener("pointermove", ev => {
      if (!drag) return;
      n.x = ev.offsetX - ox;
      n.y = ev.offsetY - oy;
      render();
    });
    g.addEventListener("pointerup", () => { drag = false; });
  }

  function render() {
    [...svg.querySelectorAll(".node")].forEach(g => {
      const n = map.get(g.dataset.id);
      g.setAttribute("transform", "translate(" + n.x + " " + n.y + ")");
    });
    [...svg.querySelectorAll(".edge")].forEach(l => {
      const a = map.get(l.dataset.a), b = map.get(l.dataset.b);
      l.setAttribute("x1", a.x); l.setAttribute("y1", a.y);
      l.setAttribute("x2", b.x); l.setAttribute("y2", b.y);
    });
    [...svg.querySelectorAll(".edge-label")].forEach(t => {
      const a = map.get(t.dataset.a), b = map.get(t.dataset.b);
      t.setAttribute("x", (a.x + b.x) / 2);
      t.setAttribute("y", (a.y + b.y) / 2);
    });
  }
  render();
}

load();
loadCommandCenter();


async function loadCommandCenter() {
  try {
    const res = await fetch("/api/command-center", {cache:"no-store"});
    if (!res.ok) throw new Error("HTTP " + res.status);
    commandPayload = await res.json();
    if (!commandPayload.enabled) {
      q("#commandState").textContent = "Database not configured";
      q("#commandCards").innerHTML = "";
      q("#caseQueue").innerHTML = '<tr><td colspan="5">Start the dashboard with --command-db to enable multi-case operations.</td></tr>';
      q("#workload").innerHTML = "<div>No workload data.</div>";
      return;
    }

    q("#commandState").textContent = "Live local queue";
    const s = commandPayload.summary;
    const metrics = [
      ["Active Cases", s.active],
      ["P1 Active", s.p1_active],
      ["SLA Breaches", s.sla_breached],
      ["Unassigned", s.unassigned],
      ["MTTR", s.mttr_minutes == null ? "—" : s.mttr_minutes + "m"]
    ];
    q("#commandCards").innerHTML = metrics.map(m =>
      '<div class="metric"><span>' + esc(m[0]) + '</span><b>' + esc(m[1]) + '</b></div>'
    ).join("");

    q("#caseQueue").innerHTML = commandPayload.queue.map(item => {
      let sla = "Closed";
      if (item.sla) sla = item.sla.breached ? '<span class="sla-breach">BREACHED</span>' : esc(item.sla.remaining_minutes + "m");
      return '<tr><td><strong>' + esc(item.case_id) + '</strong><br><span>' + esc(item.title || "") + '</span></td>' +
        '<td><span class="priority ' + esc(item.priority.toLowerCase()) + '">' + esc(item.priority) + '</span></td>' +
        '<td>' + esc(item.state) + '</td><td>' + esc(item.owner || "Unassigned") + '</td><td>' + sla + '</td></tr>';
    }).join("") || '<tr><td colspan="5">No cases registered.</td></tr>';

    q("#workload").innerHTML = commandPayload.workload.map(item =>
      '<div><b>' + esc(item.owner) + '</b><span>' + esc(item.active_cases) + ' active case(s)</span></div>'
    ).join("") || "<div>No active analyst assignments.</div>";
  } catch (err) {
    q("#commandState").textContent = "Unavailable";
  }
}
