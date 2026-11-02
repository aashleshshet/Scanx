'use strict';
const $ = id => document.getElementById(id);
const levels = ['Critical', 'High', 'Medium', 'Low'];
const colors = ['#a64b59', '#d7635b', '#d69c3d', '#6c8fa5'];
const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const setup = "git clone https://github.com/aashleshshet/Scanx.git\ncd Scanx\npython3.11 -m venv .venv\nsource .venv/bin/activate\npip install -e '.[web]'\nscanx-web --target https://your-api.example/v1";
const state = {report:null, findings:[], history:[], view:'overview', source:'', job:null, targets:[], hosted:true};
let toastTimer, inspectSequence = 0;
function toast(text) { $('toast').textContent=text; $('toast').hidden=false; clearTimeout(toastTimer); toastTimer=setTimeout(()=>$('toast').hidden=true,4000); }
async function copy(text) { try { await navigator.clipboard.writeText(text); toast('Copied to clipboard'); } catch { toast('Clipboard unavailable. Select and copy the displayed commands.'); } }
function date(value) { const d = new Date(value); return Number.isNaN(+d) ? 'Date unavailable' : d.toLocaleDateString(undefined,{month:'short',day:'numeric',year:'numeric'}); }
function validate(report) {
  if (!report || report.schema_version!=='1.0.0' || !Array.isArray(report.checks) || report.checks.length>20000 || !Array.isArray(report.modules) || typeof report.target!=='string' || !['complete','partial'].includes(report.status)) throw Error('Choose a Scanx report with schema version 1.0.0.');
  for (const check of report.checks) {
    if (!check || typeof check.operation!=='string' || typeof check.module!=='string' || !Array.isArray(check.findings) || !['passed','failed','skipped','inconclusive','error'].includes(check.status)) throw Error('The report contains an invalid check result.');
    for (const f of check.findings) if (!f || !levels.includes(f.severity) || typeof f.title!=='string' || typeof f.operation!=='string' || typeof f.remediation!=='string') throw Error('The report contains an invalid finding.');
  }
  if (!report.modules.every(m=>typeof m==='string') || !Array.isArray(report.limitations) || !report.limitations.every(l=>typeof l==='string')) throw Error('Invalid report metadata.');
  for (const f of report.checks.flatMap(c=>c.findings)) if (!Array.isArray(f.owasp) || !Array.isArray(f.cwe) || !['high','medium','low'].includes(f.confidence) || !['confirmed','needs_review'].includes(f.verification)) throw Error('Invalid finding metadata.');
  report.summary = Object.fromEntries(levels.map(l=>[l,report.checks.flatMap(c=>c.findings).filter(f=>f.severity===l).length]));
  return report;
}
function selectReport(report, source, job=null) {
  state.report=validate(report); state.source=source; state.job=job;
  state.findings=report.checks.flatMap(c=>c.findings).sort((a,b)=>levels.indexOf(a.severity)-levels.indexOf(b.severity));
  const key=job || `${source}:${report.scan_id}`;
  if (!state.history.some(h=>h.key===key)) state.history.unshift({key,report,source,job});
  clearFilters(); render();
}
function render() {
  const r=state.report; if(!r)return;
  $('report-name').textContent=state.source==='demo'?'Sample assessment · synthetic':state.source==='import'?'Imported API assessment':'API assessment';
  $('report-target').textContent=r.target;
  $('report-source').textContent=state.source==='demo'?'SYNTHETIC DEMO':state.source==='import'?'IMPORTED REPORT':'LOCAL SCAN';
  $('report-date').textContent=`${date(r.finished_at || r.started_at)} · ${r.status}`;
  $('report-banner').classList.toggle('partial',r.status==='partial');
  $('nav-count').textContent=state.findings.length;
  $('total-findings').textContent=state.findings.length;
  levels.forEach(l=>$(`count-${l}`).textContent=r.summary[l]);
  const confirmed=state.findings.filter(f=>f.verification==='confirmed').length;
  $('confirmed-count').textContent=confirmed; $('review-count').textContent=state.findings.length-confirmed;
  $('posture-title').textContent=confirmed?`${confirmed} authorization issues confirmed`:state.findings.length?'Review the candidate findings':'No findings in this assessment';
  $('posture-description').textContent=r.status==='partial'?'This scan is partial. Review incomplete checks before interpreting the findings.':'Confirmed findings and review candidates stay distinct, so you can act with context.';
  let angle=0;
  const segments=levels.map((l,i)=>{const start=angle;angle+=r.summary[l]/Math.max(state.findings.length,1)*100;return `${colors[i]} ${start}% ${angle}%`;});
  document.querySelector('.ring').style.background=state.findings.length?`conic-gradient(${segments.join(',')})`:'#e5eee0';
  $('operations').textContent=r.operations_scheduled??0; $('requests').textContent=r.requests_sent??0; $('modules').textContent=r.modules.length;
  const passed=r.checks.filter(c=>c.status==='passed').length, failed=r.checks.filter(c=>c.status==='failed').length, gaps=r.checks.length-passed-failed;
  $('passed').textContent=passed; $('failed').textContent=failed; $('gaps').textContent=gaps;
  $('coverage-bar').replaceChildren();
  for (const [count,name] of [[passed,'pass'],[failed,'high'],[gaps,'neutral']]) { if(!count)continue; const span=document.createElement('span');span.className=name;span.style.flex=String(count);$('coverage-bar').append(span); }
  renderFindings(); renderHistory();
}
function renderFindings() {
  const query=$('search').value.toLowerCase(), severity=$('severity-filter').value, verification=$('verification-filter').value;
  const list=state.findings.map((f,index)=>({f,index})).filter(({f})=>(!severity||f.severity===severity)&&(!verification||f.verification===verification)&&`${f.title} ${f.operation} ${f.rule_id} ${f.module}`.toLowerCase().includes(query));
  $('findings-count').textContent=state.findings.length;
  $('findings-body').innerHTML=list.map(({f,index})=>`<tr><td><span class="badge ${escapeHTML(f.severity)}"><i class="severity-dot ${f.severity.toLowerCase()}"></i>${f.severity}</span></td><td><button data-finding="${index}">${escapeHTML(f.title)}</button><code>${escapeHTML(f.operation)}</code></td><td class="category">${escapeHTML((f.owasp||[]).join(', ')||f.module)}</td><td><span class="evidence ${f.verification==='confirmed'?'confirmed':''}">${f.verification==='confirmed'?'✓ Confirmed':'◌ Needs review'}</span></td><td><button class="row-arrow" data-finding="${index}" aria-label="View finding details">↗</button></td></tr>`).join('');
  $('empty-findings').hidden=!!list.length;
  $('table-count').textContent=`Showing ${list.length} of ${state.findings.length} findings`;
}
function clearFilters(){ $('search').value='';$('severity-filter').value='';$('verification-filter').value='';renderFindings(); }
function changeView(view){
  state.view=view;
  const names={overview:['Overview','Your API. A clearer picture.','Move from scan results to the fixes that matter.'],findings:['Findings','Evidence you can act on.','Explore findings, inspect the evidence, and prioritize remediation.'],history:['Scan history','Every assessment, in view.','Revisit the reports you have opened in this session.'],guide:['How to use','From specification to clarity.','A practical workflow for testing APIs you control.']};
  $('breadcrumb').textContent=names[view][0];$('page-title').textContent=names[view][1];$('page-description').textContent=names[view][2];
  document.querySelectorAll('[data-view]').forEach(b=>b.classList.toggle('active',b.dataset.view===view));
  $('overview-view').hidden=view!=='overview';$('findings-view').hidden=!['overview','findings'].includes(view);$('history-view').hidden=view!=='history';$('guide-view').hidden=view!=='guide';$('report-banner').hidden=!['overview','findings'].includes(view);
  if(view==='history')renderHistory();
}
function showFinding(index){
  const f=state.findings[index];if(!f)return;
  $('finding-detail').innerHTML=`<div class="detail-meta"><span class="badge ${escapeHTML(f.severity)}">${escapeHTML(f.severity)}</span><span class="evidence">${escapeHTML(f.confidence)} confidence · ${f.verification==='confirmed'?'Confirmed':'Needs review'}</span></div><h2>${escapeHTML(f.title)}</h2><div class="detail-operation">${escapeHTML(f.operation)}</div><p>${escapeHTML(f.description)}</p><h3>Recommended remediation</h3><p>${escapeHTML(f.remediation)}</p><h3>Observed evidence</h3><pre class="detail-evidence">${escapeHTML(JSON.stringify(f.evidence||{},null,2))}</pre><p class="subtle">${escapeHTML(f.rule_id)} · ${escapeHTML([...(f.owasp||[]),...(f.cwe||[])].join(' / '))}</p>`;
  $('finding-dialog').showModal();
}
function renderHistory(){
  $('history-list').innerHTML=state.history.map((h,i)=>`<div class="history-row"><span class="banner-icon">◷</span><div><strong>${escapeHTML(h.report.target)}</strong><small>${date(h.report.finished_at||h.report.started_at)} · ${h.report.checks.flatMap(c=>c.findings).length} findings · ${escapeHTML(h.report.status)}</small></div><span class="tag">${h.source==='demo'?'SYNTHETIC':h.source==='import'?'IMPORTED':'LOCAL'}</span><button class="text-button" data-history="${i}">Open report ↗</button></div>`).join('')||'<div class="empty-state"><p>No reports opened yet.</p></div>';
}
async function loadDemo(kind='vulnerable') {
  try{const response=await fetch(`./demo-${kind}.json`);if(!response.ok)throw Error('Could not load the sample report.');selectReport(await response.json(),'demo');changeView('overview');}catch(e){toast(e.message);}
}
function download(content, format, type){const blob=new Blob([content],{type});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=`scanx-report.${format}`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
function exportReport(){
  if(!state.report)return;
  const format=$('export-format').value;
  if(state.job&&!state.hosted){const a=document.createElement('a');a.href=`/api/scans/${encodeURIComponent(state.job)}/export/${format}`;a.download=`scanx-report.${format}`;a.click();return;}
  if(format==='json'){download(JSON.stringify(state.report,null,2),'json','application/json');return;}
  const safeMD=value=>escapeHTML(value).replace(/([\\`*_{}\[\]()#+.!|>~-])/g,'\\$1').replace(/[\r\n]+/g,' ');
  const r=state.report;
  let md=`# Scanx API assessment\n\nTarget: ${safeMD(r.target)}\n\nStatus: ${safeMD(r.status)}\n\n`;
  md+=levels.map(l=>`${l}: ${r.summary[l]}`).join(' · ')+'\n\n';
  for(const f of state.findings)md+=`## ${safeMD(f.severity)}: ${safeMD(f.title)}\n\n${safeMD(f.operation)}\n\n${safeMD(f.confidence)} confidence · ${safeMD(f.verification)}\n\n${safeMD(f.description)}\n\nRemediation: ${safeMD(f.remediation)}\n\n${JSON.stringify(f.evidence||{},null,2).split('\n').map(l=>'    '+l).join('\n')}\n\n`;
  md+='## Coverage\n\n'+r.checks.map(c=>`- ${safeMD(c.operation)} · ${safeMD(c.module)} · ${safeMD(c.status)}: ${safeMD(c.reason)}`).join('\n')+'\n\n## Limitations\n\n'+(r.limitations||[]).map(l=>`- ${safeMD(l)}`).join('\n');
  if(format==='md'){download(md,'md','text/markdown');return;}
  const rows=r.checks.map(c=>`<tr><td>${escapeHTML(c.operation)}</td><td>${escapeHTML(c.module)}</td><td>${escapeHTML(c.status)}</td><td>${escapeHTML(c.reason)}</td></tr>`).join('');
  const articles=state.findings.map(f=>`<article><small>${escapeHTML(f.severity)} · ${escapeHTML(f.confidence)} confidence · ${escapeHTML(f.verification)}</small><h2>${escapeHTML(f.title)}</h2><code>${escapeHTML(f.operation)}</code><p>${escapeHTML(f.description)}</p><p><b>Remediation:</b> ${escapeHTML(f.remediation)}</p><pre>${escapeHTML(JSON.stringify(f.evidence||{},null,2))}</pre></article>`).join('');
  const html=`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'"><title>Scanx assessment</title><style>body{font:15px/1.7 system-ui;color:#243a2e;max-width:1000px;margin:50px auto;padding:24px;background:#f6f8f3}article{background:white;border:1px solid #dfe8d8;border-radius:8px;margin:20px 0;padding:25px}small{color:#74905f}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f0f4eb;padding:16px}table{border-collapse:collapse;width:100%;font-size:12px}td,th{border-bottom:1px solid #dfe8d8;padding:10px;text-align:left}</style><h1>Scanx API security assessment</h1><p>${escapeHTML(r.target)} · ${escapeHTML(r.status)}</p><p>${levels.map(l=>`${l}: ${r.summary[l]}`).join(' · ')}</p>${articles||'<p>No findings were produced by the configured checks.</p>'}<h2>Coverage</h2><table><thead><tr><th>Operation</th><th>Module</th><th>Outcome</th><th>Reason</th></tr></thead><tbody>${rows}</tbody></table><h2>Limitations</h2><ul>${(r.limitations||[]).map(l=>`<li>${escapeHTML(l)}</li>`).join('')}</ul></html>`;
  download(html,'html','text/html');
}
async function api(url,options={}) {
  const response=await fetch(url,{...options,headers:{'Content-Type':'application/json',...options.headers}});
  const data=await response.json(); if(!response.ok)throw Error(typeof data.detail==='string'?data.detail:'The request could not be completed.');return data;
}
async function readFile(input){const file=$(input).files[0];if(!file)return '';if(file.size>1_500_000)throw Error('Use files smaller than 1.5 MB.');return file.text();}
async function inspectSpec(){
  const sequence=++inspectSequence;$('auth-scheme').innerHTML='<option value="">No credentials</option>';
  if(!$('spec-file').files.length)return;
  try{const data=await api('/api/inspect',{method:'POST',body:JSON.stringify({target:$('target').value,spec:await readFile('spec-file'),scenarios:await readFile('scenario-file')})});
    if(sequence!==inspectSequence)return;
    for(const name of data.schemes){const option=document.createElement('option');option.value=name;option.textContent=name;$('auth-scheme').append(option);}
    if(data.schemes.length)$('auth-scheme').value=data.schemes[0];
    $('spec-summary').textContent=`${data.operations} operations discovered · ${data.schemes.length} authentication schemes`;$('scan-error').textContent='';
  }catch(e){if(sequence===inspectSequence){$('scan-error').textContent=e.message;$('spec-summary').textContent='Specification needs attention.';}}
}
function newScan(){ $('hosted-setup').hidden=!state.hosted&&state.targets.length>0;$('scan-form').hidden=state.hosted||!state.targets.length;$('scan-dialog').showModal(); }
async function pollJob(id){
  $('activity').hidden=false;
  const start=Date.now();
  while(true){
    try{const job=await api(`/api/scans/${encodeURIComponent(id)}`);
      if(job.status!=='running'){$('activity').hidden=true;if(job.report){selectReport(job.report,'local',id);changeView('overview');toast('Assessment complete. Your report is ready.');}else toast(job.error||'Scan cancelled.');return;}
      $('activity').innerHTML=`<div><strong>Assessment running</strong><small>${Math.floor((Date.now()-start)/1000)}s elapsed · Gathering response evidence</small></div><button id="cancel-scan">Cancel scan</button>`;
      $('cancel-scan').onclick=async()=>{try{await api(`/api/scans/${encodeURIComponent(id)}`,{method:'DELETE'});}catch(e){toast(e.message);}};
    }catch(e){$('activity').hidden=true;toast(e.message);return;}
    await new Promise(resolve=>setTimeout(resolve,1000));
  }
}
document.querySelectorAll('[data-view]').forEach(button=>button.onclick=()=>changeView(button.dataset.view));
document.querySelector('.brand').onclick=()=>changeView('overview');
document.querySelectorAll('[data-close]').forEach(button=>button.onclick=()=>$(button.dataset.close).close());
document.querySelectorAll('[data-severity]').forEach(button=>button.onclick=()=>{changeView('findings');$('severity-filter').value=button.dataset.severity;renderFindings();});
$('findings-body').onclick=e=>{const button=e.target.closest('[data-finding]');if(button)showFinding(+button.dataset.finding);};
$('history-list').onclick=e=>{const button=e.target.closest('[data-history]');if(button){const h=state.history[+button.dataset.history];selectReport(h.report,h.source,h.job);changeView('overview');}};
for(const id of ['search','severity-filter','verification-filter'])$(id).addEventListener('input',renderFindings);
$('clear-filters').onclick=clearFilters;
$('import-button').onclick=()=>$('report-file').click();
$('report-file').onchange=async e=>{try{const file=e.target.files[0];if(!file)return;if(file.size>8*1024*1024)throw Error('Choose a report smaller than 8 MB.');selectReport(JSON.parse(await file.text()),'import');changeView('overview');toast('Report imported. Your file stays in this browser tab.');}catch(error){toast(error.message);}finally{e.target.value='';}};
$('demo-menu').onclick=()=>loadDemo(state.source==='demo'&&state.findings.length?'protected':'vulnerable');
$('guide-demo').onclick=()=>loadDemo();
$('new-scan').onclick=newScan;
$('export-button').onclick=exportReport;
for(const id of ['copy-command','setup-copy'])$(id).onclick=()=>copy(setup);
$('setup-demo').onclick=()=>{$('scan-dialog').close();loadDemo();};
$('scan-dialog').addEventListener('close',()=>{$('token-a').value='';$('token-b').value='';});
$('spec-file').onchange=inspectSpec;$('scenario-file').onchange=inspectSpec;
$('scan-form').onsubmit=async e=>{
  e.preventDefault();$('scan-error').textContent='';$('run-scan').disabled=true;
  try{const checks=[...document.querySelectorAll('[name=check]:checked')].map(input=>input.value);
    if(!checks.length)throw Error('Select at least one security check.');
    if($('timing').checked&&!checks.includes('injection'))throw Error('Enable injection checks to use timing probes.');
    const body={target:$('target').value,spec:await readFile('spec-file'),scenarios:await readFile('scenario-file'),auth_scheme:$('auth-scheme').value,token_a:$('token-a').value,token_b:$('token-b').value,checks,timing:$('timing').checked,sql_dialect:$('sql-dialect').value};
    const job=await api('/api/scans',{method:'POST',body:JSON.stringify(body)});body.token_a='';body.token_b='';$('scan-dialog').close();pollJob(job.id);
  }catch(error){$('scan-error').textContent=error.message;}finally{$('run-scan').disabled=false;}
};
async function initialize(){
  await loadDemo();
  if(window.SCANX_HOSTED===false){
    try{const config=await api('/api/capabilities');state.hosted=false;state.targets=config.targets;$('runtime-label').textContent='Local Python runner';$('runtime-pill').innerHTML='<i></i> Local runner connected';
      for(const target of state.targets){const option=document.createElement('option');option.textContent=target;option.value=target;$('target').append(option);}
      const jobs=await api('/api/scans');
      for(const job of jobs){if(job.status==='running'){pollJob(job.id);continue;}if(job.status==='complete'){const full=await api(`/api/scans/${encodeURIComponent(job.id)}`);state.history.push({key:job.id,report:validate(full.report),source:'local',job:job.id});}}
      renderHistory();
    }catch(e){toast('Local runner unavailable. Sample reports are still available.');}
  }
}
initialize();
