let payload=null,commandPayload=null,leadPayload=null,currentCaseId=null;
const q=s=>document.querySelector(s);
const qa=s=>[...document.querySelectorAll(s)];
const esc=v=>String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let apiToken=sessionStorage.getItem("socmindToken")||"";

async function apiFetch(url,options={}){
  const headers=new Headers(options.headers||{});
  if(apiToken) headers.set("X-SOCMind-Token",apiToken);
  const res=await fetch(url,{...options,headers,cache:"no-store"});
  if(res.status===401) q("#health").textContent="Auth required";
  return res;
}

q("#setToken").addEventListener("click",()=>{
  const value=prompt("SOCMind API token (leave blank to clear)",apiToken);
  if(value===null)return;
  apiToken=value.trim();
  if(apiToken)sessionStorage.setItem("socmindToken",apiToken);else sessionStorage.removeItem("socmindToken");
  load();loadCommandCenter();loadLeadHealth();loadIRE();
});
q("#refresh").addEventListener("click",()=>{load();loadCommandCenter();loadLeadHealth();loadIRE();});
q("#applyFilters").addEventListener("click",loadCommandCenter);
q("#closeDetail").addEventListener("click",()=>q("#caseDetailPanel").classList.add("hidden"));

qa(".nav").forEach(btn=>btn.addEventListener("click",()=>{
  qa(".nav").forEach(x=>x.classList.remove("active"));
  qa(".page").forEach(x=>x.classList.remove("active"));
  btn.classList.add("active");q("#"+btn.dataset.target).classList.add("active");
  if(btn.dataset.target==="graph"&&payload)drawGraph(payload.graph);
  if(btn.dataset.target==="command")loadCommandCenter();
  if(btn.dataset.target==="lead")loadLeadHealth();
  if(btn.dataset.target==="ire")loadIRE();
}));

function findingCard(f){
  const reasons=f.rationale.map(x=>"<li>"+esc(x)+"</li>").join("");
  return '<div class="finding"><div class="finding-top"><h3>'+esc(f.title)+'</h3><div><span class="sev sev-'+esc(f.severity)+'">'+esc(f.severity.toUpperCase())+'</span> <span class="score">'+f.score+'/100</span></div></div><div class="score">'+esc(f.triage.priority)+' · '+esc(f.triage.escalation)+'</div><ul>'+reasons+'</ul></div>';
}

async function load(){
  q("#health").textContent="Loading";
  try{
    const res=await apiFetch("/api/case");
    if(!res.ok)throw new Error("HTTP "+res.status);
    payload=await res.json();q("#health").textContent="Local · Ready";q("#caseTitle").textContent=payload.case_id;
    const metrics=[["Events",payload.summary.events],["Findings",payload.summary.findings],["High Priority",payload.summary.critical_or_high],["Highest Risk",payload.summary.highest_score],["ATT&CK",payload.summary.techniques]];
    q("#cards").innerHTML=metrics.map(m=>'<div class="metric"><span>'+esc(m[0])+'</span><b>'+esc(m[1])+'</b></div>').join("");
    q("#findingPreview").innerHTML=payload.findings.slice(0,4).map(findingCard).join("")||"<p>No findings.</p>";
    q("#findingList").innerHTML=payload.findings.map(findingCard).join("")||"<p>No findings.</p>";
    q("#findingCount").textContent=payload.findings.length+" findings";
    q("#hypotheses").innerHTML=payload.hypotheses.map(h=>'<div class="hypothesis"><strong>'+esc(h.name)+'</strong><span class="score"> · '+h.confidence+'% confidence</span><div class="confidence"><i style="width:'+h.confidence+'%"></i></div></div>').join("")||"<p>No hypotheses generated.</p>";
    q("#timelineList").innerHTML=payload.timeline.map(e=>'<div class="event"><time>'+esc(e.timestamp)+'</time><strong>'+esc(e.host)+' · '+esc(e.source)+' · '+esc(e.event_id)+'</strong><p>'+esc(e.user||"—")+' '+esc(e.process||"")+' '+esc(e.command_line||e.dst_ip||e.src_ip||"")+'</p></div>').join("");
    q("#techniques").innerHTML=payload.techniques.map(t=>'<span class="chip">'+esc(t)+'</span>').join("")||'<span class="score">No techniques observed.</span>';
    q("#iocs").innerHTML=payload.iocs.map(i=>'<div><b>'+esc(i.type.toUpperCase())+'</b> · '+esc(i.value)+' <span>('+esc(i.scope)+')</span></div>').join("")||"<div>No IOCs extracted.</div>";
  }catch(err){q("#health").textContent="Error";q("#caseTitle").textContent="Dashboard unavailable";}
}

async function loadCommandCenter(){
  try{
    const params=new URLSearchParams();
    if(q("#caseSearch").value.trim())params.set("q",q("#caseSearch").value.trim());
    if(q("#priorityFilter").value)params.set("priority",q("#priorityFilter").value);
    if(q("#stateFilter").value)params.set("state",q("#stateFilter").value);
    const res=await apiFetch("/api/command-center?"+params.toString());
    if(!res.ok)throw new Error("HTTP "+res.status);
    commandPayload=await res.json();
    if(!commandPayload.enabled){
      q("#commandState").textContent="Database not configured";
      q("#caseQueue").innerHTML='<tr><td colspan="5">Start with --command-db to enable operations.</td></tr>';return;
    }
    q("#commandState").textContent="Live local queue";
    const s=commandPayload.summary;
    const metrics=[["Active Cases",s.active],["P1 Active",s.p1_active],["SLA Breaches",s.sla_breached],["Unassigned",s.unassigned],["MTTA",s.mtta_minutes==null?"—":s.mtta_minutes+"m"],["MTTR",s.mttr_minutes==null?"—":s.mttr_minutes+"m"]];
    q("#commandCards").innerHTML=metrics.map(m=>'<div class="metric"><span>'+esc(m[0])+'</span><b>'+esc(m[1])+'</b></div>').join("");
    q("#caseQueue").innerHTML=commandPayload.queue.map(item=>{
      let sla="Closed";if(item.sla)sla=item.sla.breached?'<span class="sla-breach">BREACHED</span>':esc(item.sla.remaining_minutes+"m");
      return '<tr class="case-row" data-case="'+esc(item.case_id)+'"><td><strong>'+esc(item.case_id)+'</strong><br><span>'+esc(item.title||"")+'</span></td><td><span class="priority '+esc(item.priority.toLowerCase())+'">'+esc(item.priority)+'</span></td><td>'+esc(item.state)+'</td><td>'+esc(item.owner||"Unassigned")+'</td><td>'+sla+'</td></tr>';
    }).join("")||'<tr><td colspan="5">No matching cases.</td></tr>';
    qa(".case-row").forEach(row=>row.addEventListener("click",()=>openCase(row.dataset.case)));
    q("#workload").innerHTML=commandPayload.workload.map(item=>'<div><b>'+esc(item.owner)+'</b><span>'+esc(item.active_cases)+' active case(s)</span></div>').join("")||"<div>No active assignments.</div>";
  }catch(err){q("#commandState").textContent="Unavailable";}
}

async function openCase(caseId){
  currentCaseId=caseId;
  const res=await apiFetch("/api/cases/"+encodeURIComponent(caseId));
  if(!res.ok)return;
  const data=await res.json(),c=data.case;
  q("#caseDetailPanel").classList.remove("hidden");q("#detailTitle").textContent=(c.title||c.case_id)+" · "+c.case_id;
  q("#detailMeta").innerHTML='<span class="priority '+esc(c.priority.toLowerCase())+'">'+esc(c.priority)+'</span><span>'+esc(c.state)+'</span><span>Owner: '+esc(c.owner||"Unassigned")+'</span><span>Source: '+esc(c.source||"—")+'</span><span>Acknowledged: '+esc(c.acknowledged_at||"No")+'</span>';
  q("#assignOwner").value=c.owner||"";
  q("#caseNotes").innerHTML=data.notes.map(n=>'<div><b>'+esc(n.author)+'</b><span>'+esc(n.created_at)+'</span><p>'+esc(n.text)+'</p></div>').join("")||"<div>No notes yet.</div>";
  q("#caseAudit").innerHTML=data.audit.map(a=>'<div><b>'+esc(a.action)+'</b><span>'+esc(a.actor)+' · '+esc(a.timestamp)+'</span><p>'+esc(a.detail)+'</p></div>').join("")||"<div>No audit entries yet.</div>";
  q("#caseAlerts").innerHTML=(data.alerts||[]).map(a=>{
    const reasons=(a.correlation_reasons||[]).map(r=>'<li>'+esc(r.detail)+' <span>+'+esc(r.weight)+'</span></li>').join("");
    const rule=a.rule_id?(' · rule '+esc(a.rule_id)):"";
    const technique=a.technique?(' · '+esc(a.technique)):"";
    return '<div><b>'+esc(a.alert_id)+' · '+esc(a.source)+'</b><span>'+esc(a.timestamp)+' · severity '+esc(a.severity)+' · correlation '+esc(a.correlation_score)+rule+technique+'</span><p>'+esc(a.title)+'</p>'+(reasons?'<ul>'+reasons+'</ul>':'<p class="score">Root alert / no correlation reason required.</p>')+'</div>';
  }).join("")||"<div>No orchestrated alerts linked to this case.</div>";
  q("#caseEvidenceCollections").innerHTML=(data.evidence_collections||[]).map(item=>{
    const status=item.status==="completed"?"✓ completed":"⚠ "+esc(item.status||"unknown");
    return '<div><b>'+status+' · '+esc(item.provider||"unknown")+'</b><span>'+esc(item.source_ref||"—")+' · '+esc(item.event_count||0)+' event(s) · '+esc(item.started_at||"—")+'</span><p>'+esc(item.window_start||"—")+' → '+esc(item.window_end||"—")+(item.error?' · '+esc(item.error):'')+'</p></div>';
  }).join("")||"<div>No live evidence collection has been recorded for this case.</div>";
  q("#caseTimeline").innerHTML=(data.case_timeline||[]).map(item=>
    '<div class="event"><time>'+esc(item.timestamp||"—")+'</time><strong>'+esc(item.kind)+' · '+esc(item.title)+'</strong><p>'+esc(item.detail||"")+'</p></div>'
  ).join("")||"<div>No operational timeline entries yet.</div>";
  if(data.investigation&& !data.investigation.error){
    q("#linkedInvestigation").innerHTML='<h3>Linked Evidence</h3><div class="chips"><span class="chip">'+esc(data.investigation.summary.events)+' events</span><span class="chip">'+esc(data.investigation.summary.findings)+' findings</span><span class="chip">risk '+esc(data.investigation.summary.highest_score)+'</span></div>';
  }else q("#linkedInvestigation").innerHTML='<h3>Linked Evidence</h3><p class="score">'+(c.evidence_path?"Evidence could not be parsed.":"No evidence file linked to this case.")+'</p>';
  q("#caseDetailPanel").scrollIntoView({behavior:"smooth",block:"start"});
}

async function mutateCase(path,body=null){
  if(!currentCaseId)return;
  const opts={method:"POST",headers:{"Content-Type":"application/json"}};
  if(body!==null)opts.body=JSON.stringify(body);
  const res=await apiFetch("/api/cases/"+encodeURIComponent(currentCaseId)+path,opts);
  if(!res.ok){const e=await res.json().catch(()=>({detail:"Request failed"}));alert(e.detail||"Request failed");return;}
  await openCase(currentCaseId);await loadCommandCenter();
}
q("#ackCase").addEventListener("click",()=>mutateCase("/acknowledge"));
q("#assignCase").addEventListener("click",()=>{const owner=q("#assignOwner").value.trim();if(owner)mutateCase("/assign",{owner});});
q("#transitionCase").addEventListener("click",()=>{const state=q("#transitionState").value;if(state)mutateCase("/transition",{state});});
q("#addNote").addEventListener("click",()=>{const text=q("#noteText").value.trim();if(!text)return;mutateCase("/notes",{text}).then(()=>q("#noteText").value="");});

async function loadLeadHealth(){
  try{
    const res=await apiFetch("/api/lead-health");if(!res.ok)throw new Error();
    leadPayload=await res.json();q("#leadState").textContent="Detection telemetry ready";const s=leadPayload.summary;
    const metrics=[["Rules",s.rules],["Coverage",s.coverage_percent==null?"—":s.coverage_percent+"%"],["Noisy Rules",s.noisy_rules],["Watch Rules",s.watch_rules],["Insufficient Data",s.insufficient_data_rules],["Dispositions",s.dispositions],["Findings",s.findings]];
    q("#leadCards").innerHTML=metrics.map(m=>'<div class="metric"><span>'+esc(m[0])+'</span><b>'+esc(m[1])+'</b></div>').join("");
    q("#detectionHealth").innerHTML=leadPayload.detection_health.map(item=>{
      const fp=item.false_positive_rate==null?"—":Math.round(item.false_positive_rate*100)+"% FP";
      const tp=item.true_positive_rate==null?"—":Math.round(item.true_positive_rate*100)+"% TP";
      const interval=(item.false_positive_rate_low==null||item.false_positive_rate_high==null)?"":(" · FP 95% CI "+Math.round(item.false_positive_rate_low*100)+"–"+Math.round(item.false_positive_rate_high*100)+"%");
      return '<div><b>'+esc(item.rule_id)+' · '+esc(item.status)+'</b><span>score '+esc(item.score)+' · '+tp+' · '+fp+interval+' · sample '+esc(item.classified_sample_size)+' ('+esc(item.sample_sufficiency)+')'+(item.unclassified_sample_size?' · '+esc(item.unclassified_sample_size)+' unclassified':'')+'</span></div>';
    }).join("")||"<div>No disposition history.</div>";
    q("#attackCoverage").innerHTML=leadPayload.coverage.filter(x=>x.observed).map(item=>'<div><b>'+esc(item.technique)+'</b><span>'+(item.covered?'Covered · '+esc(item.rule_count)+' rule(s)':'GAP')+'</span></div>').join("")||"<div>No observed ATT&CK techniques.</div>";
    q("#topUsers").innerHTML=leadPayload.top_users.map(item=>'<div><b>'+esc(item.user)+'</b><span>'+esc(item.events)+' events</span></div>').join("")||"<div>No user telemetry.</div>";
    q("#topHosts").innerHTML=leadPayload.top_hosts.map(item=>'<div><b>'+esc(item.host)+'</b><span>'+esc(item.events)+' events</span></div>').join("")||"<div>No host telemetry.</div>";
  }catch(err){q("#leadState").textContent="Unavailable";}
}


async function loadIRE(){
  try{
    const [replayRes,detectionRes,qualityRes,contradictionRes,similarRes]=await Promise.all([
      apiFetch("/api/ire/replay"),
      apiFetch("/api/ire/detection-replay"),
      apiFetch("/api/ire/quality"),
      apiFetch("/api/reasoning/contradictions"),
      apiFetch("/api/reasoning/similar")
    ]);
    if(!replayRes.ok||!detectionRes.ok||!qualityRes.ok||!contradictionRes.ok||!similarRes.ok)throw new Error("IRE API unavailable");
    const replay=await replayRes.json();
    const detection=await detectionRes.json();
    const quality=await qualityRes.json();
    const contradictions=await contradictionRes.json();
    const similar=await similarRes.json();

    q("#ireState").textContent="Replay ready";
    const metrics=[
      ["First Detection",detection.first_detection_step==null?"—":"Step "+detection.first_detection_step],
      ["Blind Before Detect",detection.blind_steps_before_first_detection],
      ["Visibility",detection.visibility_percent+"%"],
      ["Detection Gaps",detection.gap_techniques.length],
      ["Quality",quality.percentage+"%"],
      ["Similar Cases",similar.summary?similar.summary.matches:0]
    ];
    q("#ireCards").innerHTML=metrics.map(m=>'<div class="metric"><span>'+esc(m[0])+'</span><b>'+esc(m[1])+'</b></div>').join("");

    const techniqueRows=(detection.technique_visibility||[]).map(item=>{
      const first=item.first_detected_step==null?"blind":"step "+item.first_detected_step;
      const delay=item.detection_delay_steps==null?"—":item.detection_delay_steps+" step(s)";
      return '<div><b>'+esc(item.technique)+'</b><span>first observed step '+esc(item.first_observed_step)+' · first detection '+esc(first)+' · delay '+esc(delay)+' · visibility '+esc(item.visibility_percent)+'%'+(item.contributing_rules.length?' · rules '+esc(item.contributing_rules.join(", ")):'')+'</span></div>';
    }).join("");
    q("#ireDetection").innerHTML=
      '<div><b>Observed techniques</b><span>'+esc(detection.observed_techniques.join(", ")||"—")+'</span></div>'+
      '<div><b>Covered techniques</b><span>'+esc(detection.covered_techniques.join(", ")||"—")+'</span></div>'+
      '<div><b>Detection gaps</b><span class="'+(detection.gap_techniques.length?"ire-warn":"")+'">'+esc(detection.gap_techniques.join(", ")||"None")+'</span></div>'+
      '<div><b>Blind meaningful steps</b><span>'+esc(detection.blind_steps)+'</span></div>'+
      techniqueRows;

    const whatIfRes=await apiFetch("/api/ire/what-if");
    if(whatIfRes.status===403){
      q("#ireWhatIf").innerHTML='<div>Requires <b>detection.review</b> permission.</div>';
    }else if(whatIfRes.ok){
      const whatif=await whatIfRes.json();
      if(whatif.enabled){
        const early=whatif.first_detection_step_improvement;
        q("#ireWhatIf").innerHTML=
          '<div><b>Earlier detection</b><span>'+(early==null?"—":esc(early)+" step(s)")+'</span></div>'+
          '<div><b>Visibility delta</b><span class="'+(whatif.visibility_delta>0?"ire-good":"")+'">'+esc((whatif.visibility_delta>=0?"+":"")+whatif.visibility_delta)+"%</span></div>"+
          '<div><b>Blind-step reduction</b><span class="'+(whatif.blind_step_delta>0?"ire-good":"")+'">'+esc((whatif.blind_step_delta>=0?"+":"")+whatif.blind_step_delta)+'</span></div>'+
          '<div><b>New coverage</b><span>'+esc(whatif.newly_covered_techniques.join(", ")||"—")+'</span></div>';
      }else{
        q("#ireWhatIf").innerHTML='<div>Launch with <b>--proposed-rules</b> to compare a proposed pack.</div>';
      }
    }else{
      q("#ireWhatIf").innerHTML='<div>What-If comparison unavailable.</div>';
    }

    q("#ireQuality").innerHTML=quality.items.map(item=>{
      const state=item.applicable===false?"N/A":(item.complete?"✓":"○");
      const cls=item.applicable===false?"":(item.complete?"ire-good":"ire-warn");
      return '<div><b class="'+cls+'">'+state+' '+esc(item.label)+'</b><span>'+esc(item.evidence)+(item.analyst_confirmation_required?' · analyst confirmation':'')+'</span></div>';
    }).join("");

    q("#ireReplay").innerHTML=replay.steps.map(step=>{
      const findings=step.new_findings.map(x=>'<span class="chip">+'+esc(x)+'</span>').join("");
      const hypotheses=step.hypotheses.map(h=>'<div class="ire-hyp">'+esc(h.name)+' · '+esc(h.confidence)+'% · '+esc((h.delta>=0?"+":"")+h.delta)+'</div>').join("");
      return '<div class="ire-step"><time>Step '+esc(step.index)+' · '+esc(step.timestamp)+'</time><strong>'+esc(step.source)+' · '+esc(step.event_id)+' · '+esc(step.host)+'</strong><div class="chips">'+findings+'</div>'+hypotheses+'</div>';
    }).join("");

    q("#ireContradictions").innerHTML=contradictions.hypotheses.map(item=>{
      const conflicting=item.contradicting.map(x=>'<div class="ire-warn">- '+esc(x.statement)+'</div>').join("");
      const gaps=item.validation_gaps.map(x=>'<div>! '+esc(x)+'</div>').join("");
      const unresolved=item.unresolved.map(x=>'<div>? '+esc(x)+'</div>').join("");
      return '<div><b>'+esc(item.hypothesis)+' · '+esc(item.confidence)+'%</b><span>'+esc(item.supporting.length)+' supporting · '+esc(item.contradicting.length)+' explicit contradiction/context · '+esc(item.validation_gaps.length)+' validation gap(s)</span>'+conflicting+gaps+unresolved+'</div>';
    }).join("")||"<div>No hypotheses available for contradiction review.</div>";

    if(similar.enabled===false){
      q("#ireSimilar").innerHTML='<div>Configure a case store with evidence-linked historical cases to enable similarity.</div>';
    }else{
      q("#ireSimilar").innerHTML=similar.matches.map(item=>{
        const reasons=item.explanation.map(x=>'<div>'+esc(x)+'</div>').join("");
        return '<div><b>'+esc(item.case_id)+' · '+esc(item.score)+'% · '+esc(item.confidence)+' confidence</b><span>'+esc(item.title)+' · '+esc(item.matched_dimensions)+'/'+esc(item.comparable_dimensions)+' evidence dimensions matched</span>'+reasons+'</div>';
      }).join("")||"<div>No comparable historical cases found.</div>";
    }
  }catch(err){
    q("#ireState").textContent="Unavailable";
  }
}

function drawGraph(graph){
  const svg=q("#evidenceGraph");svg.innerHTML="";const ns="http://www.w3.org/2000/svg";
  const nodes=graph.nodes.map((n,i)=>({...n,x:140+(i%5)*220,y:100+Math.floor(i/5)*180}));
  const map=new Map(nodes.map(n=>[n.id,n]));const colors={user:"#6da8ff",host:"#51d7c7",process:"#f4b860",ip:"#ff6b7a",persistence:"#b993ff",service:"#81d681"};
  for(const e of graph.edges){const a=map.get(e.source),b=map.get(e.target);if(!a||!b)continue;const line=document.createElementNS(ns,"line");line.setAttribute("class","edge");line.dataset.a=e.source;line.dataset.b=e.target;svg.appendChild(line);const text=document.createElementNS(ns,"text");text.setAttribute("class","edge-label");text.textContent=e.relation;text.dataset.a=e.source;text.dataset.b=e.target;svg.appendChild(text);}
  for(const n of nodes){const g=document.createElementNS(ns,"g");g.setAttribute("class","node");g.dataset.id=n.id;const c=document.createElementNS(ns,"circle");c.setAttribute("r","24");c.setAttribute("fill",colors[n.kind]||"#8fa5b2");c.setAttribute("stroke","#d9edf3");const t=document.createElementNS(ns,"text");t.setAttribute("text-anchor","middle");t.setAttribute("dy","40");t.textContent=n.label.length>22?n.label.slice(0,20)+"…":n.label;g.append(c,t);svg.appendChild(g);g.addEventListener("click",()=>{const rels=graph.edges.filter(e=>e.source===n.id||e.target===n.id).length;q("#nodeDetail").innerHTML="<strong>"+esc(n.kind.toUpperCase())+"</strong><br>"+esc(n.label)+"<br><span>"+rels+" relationships</span>";});let drag=false,ox=0,oy=0;g.addEventListener("pointerdown",ev=>{drag=true;g.setPointerCapture(ev.pointerId);ox=ev.offsetX-n.x;oy=ev.offsetY-n.y;});g.addEventListener("pointermove",ev=>{if(!drag)return;n.x=ev.offsetX-ox;n.y=ev.offsetY-oy;render();});g.addEventListener("pointerup",()=>drag=false);}
  function render(){[...svg.querySelectorAll(".node")].forEach(g=>{const n=map.get(g.dataset.id);g.setAttribute("transform","translate("+n.x+" "+n.y+")");});[...svg.querySelectorAll(".edge")].forEach(l=>{const a=map.get(l.dataset.a),b=map.get(l.dataset.b);l.setAttribute("x1",a.x);l.setAttribute("y1",a.y);l.setAttribute("x2",b.x);l.setAttribute("y2",b.y);});[...svg.querySelectorAll(".edge-label")].forEach(t=>{const a=map.get(t.dataset.a),b=map.get(t.dataset.b);t.setAttribute("x",(a.x+b.x)/2);t.setAttribute("y",(a.y+b.y)/2);});}render();
}

load();loadCommandCenter();loadLeadHealth();
