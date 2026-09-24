"""Small local operator workspace served by the daemon."""

CONTROL_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>connectd control</title><style>
:root{font-family:system-ui,sans-serif;color:#17211e;background:#f4f7f4}
body{max-width:1100px;margin:auto;padding:24px}h1{margin:0 0 4px;font-size:2rem}h2{margin-top:0}
.sub{color:#53645c;margin-bottom:24px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}
.card{background:white;border:1px solid #d6e0d8;border-radius:14px;padding:20px;margin-bottom:20px;box-shadow:0 3px 12px #183b2510}
label{display:block;font-size:.82rem;font-weight:650;margin:12px 0 4px}input,select,textarea,button{font:inherit}
input,select,textarea{box-sizing:border-box;width:100%;padding:10px;border:1px solid #bbc9bf;border-radius:8px;background:white}
button{border:0;border-radius:8px;background:#196d42;color:white;padding:10px 16px;cursor:pointer;margin-top:12px}
button.secondary{background:#e4eee6;color:#174b30;margin:4px}.row{display:flex;gap:8px;align-items:end}
.row>*{flex:1}.item{border-top:1px solid #e5ebe6;padding:10px 0}.item button{margin:0}
.muted{color:#637269;font-size:.85rem}.error{color:#a12626}.ok{color:#176b3e}
pre{white-space:pre-wrap;word-break:break-word;font-size:.82rem;background:#f5f8f6;padding:12px;border-radius:8px;max-height:300px;overflow:auto}
@media(max-width:720px){.grid{grid-template-columns:1fr}.row{display:block}}
</style></head><body>
<h1>connectd control</h1><div class="sub">Tasks, trusted memory, and verified execution history</div>
<section class="card"><div class="row"><div><label for="token">Operator token</label><input id="token" type="password" autocomplete="off" placeholder="Paste your operator bearer token"></div><div><button id="load">Load workspace</button></div></div><p class="muted">The token stays in this browser tab's memory and is not saved.</p><div id="status"></div></section>
<section class="card" id="onboarding" hidden><h2>Organization setup</h2>
<div class="grid"><form id="new-org"><h3>Create organization</h3>
<label for="org-name">Organization name</label><input id="org-name" required maxlength="200">
<button type="submit">Create organization</button></form>
<form id="new-user"><h3>Add a user</h3>
<label for="user-org">Organization</label><select id="user-org"></select>
<label for="user-name">Display name</label><input id="user-name" required maxlength="200">
<label for="user-role">Role</label><select id="user-role"><option>viewer</option><option>operator</option><option>admin</option></select>
<button type="submit">Issue user token</button></form></div>
<div id="issued-token" class="muted">New user tokens are shown once.</div></section>
<div class="grid"><section class="card" id="new-task-card"><h2>New task</h2><form id="new-task">
<label for="title">Title</label><input id="title" required maxlength="500">
<label for="privacy">Privacy</label><select id="privacy"><option>public</option><option>low_sensitive</option><option>repo_sensitive</option><option>secret_sensitive</option></select>
<label for="scope">Memory scope</label><input id="scope" required placeholder="repo:my-project">
<label for="profile">Execution profile</label><select id="profile"><option>balanced</option><option>dev_fast</option><option>prod_secure</option></select>
<button type="submit">Create task</button></form></section>
<section class="card"><h2>Tasks</h2><div id="tasks" class="muted">Load workspace to see tasks.</div></section></div>
<div class="grid"><section class="card"><h2>Audit timeline</h2><div id="audit" class="muted">Select a task.</div></section>
<section class="card" id="candidates-card"><h2>Memory candidates</h2><div id="candidates" class="muted">Load workspace to review candidates.</div></section></div>
<section class="card" id="memory-card"><h2>Memory ledger</h2><div class="row"><div><label for="memory-scope">Scope</label><input id="memory-scope" placeholder="repo:my-project"></div><div><button id="load-memory">Inspect claims</button></div></div><div id="memory-ledger" class="muted">Enter a scope to inspect promoted, stale, superseded, and pending claims.</div></section>
<section class="card" id="nodes-card"><h2>Compute nodes</h2><div id="compute-nodes" class="muted">Load workspace to inspect node health and capacity.</div></section>
<script>
let token='',identity=null;const byId=id=>document.getElementById(id);
async function api(path,options={}){const r=await fetch(path,{...options,headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json',...(options.headers||{})}});if(!r.ok)throw Error((await r.text()).slice(0,300));return r.json()}
function status(message,error=false){byId('status').textContent=message;byId('status').className=error?'error':'ok'}
function element(tag,text){const node=document.createElement(tag);node.textContent=text;return node}
async function load(){token=byId('token').value.trim();if(!token){status('Enter an operator token.',true);return}try{identity=await api('/api/v1/me');renderTasks(await api('/api/v1/tasks'));byId('new-task-card').hidden=identity.role==='viewer';const global=identity.bootstrap;byId('candidates-card').hidden=!global;byId('memory-card').hidden=!global;byId('nodes-card').hidden=!global;byId('onboarding').hidden=identity.role!=='admin';byId('new-org').hidden=!global;if(global){const [candidates,nodes,orgs]=await Promise.all([api('/api/v1/memory/candidates'),api('/api/v1/compute/nodes'),api('/api/v1/orgs')]);renderCandidates(candidates);renderNodes(nodes);renderOrganizations(orgs)}else if(identity.role==='admin'){renderOrganizations([{org_id:identity.org_id,name:'Current organization'}])}status('Workspace loaded for '+identity.role+'.')}catch(e){status(e.message,true)}}
function renderOrganizations(orgs){const select=byId('user-org');select.replaceChildren();for(const org of orgs){const option=element('option',org.name+' · '+org.org_id);option.value=org.org_id;select.append(option)}}
function renderTasks(tasks){const root=byId('tasks');root.replaceChildren();if(!tasks.length){root.textContent='No tasks yet.';return}for(const task of tasks){const item=element('div',task.title+' · '+task.privacy_class+' · '+task.status);item.className='item';const btn=element('button','View audit');btn.className='secondary';btn.onclick=()=>showAudit(task.task_id);item.append(btn);root.append(item)}}
function renderCandidates(items){const root=byId('candidates');root.replaceChildren();if(!items.length){root.textContent='No pending candidates.';return}for(const claim of items){const item=element('div',claim.claim_text);item.className='item';const btn=element('button','Promote');btn.className='secondary';btn.onclick=async()=>{try{await api('/api/v1/memory/claims/'+encodeURIComponent(claim.claim_id)+'/promote',{method:'POST'});load()}catch(e){status(e.message,true)}};item.append(btn);root.append(item)}}
function renderNodes(nodes){const root=byId('compute-nodes');root.replaceChildren();if(!nodes.length){root.textContent='No compute nodes registered.';return}for(const node of nodes){const item=element('div',node.node_id+' · '+node.model_id+' · '+(node.healthy?'healthy':'unavailable'));item.className='item';const detail=element('pre',JSON.stringify({last_health_at:node.last_health_at,capacity:node.capacity_json?JSON.parse(node.capacity_json):null},null,2));item.append(detail);const button=element('button','Probe now');button.className='secondary';button.onclick=async()=>{try{await api('/api/v1/compute/nodes/'+encodeURIComponent(node.node_id)+'/probe',{method:'POST'});await load()}catch(e){status(e.message,true)}};if(node.last_health_at!==null||node.healthy===false)item.append(button);root.append(item)}}
async function showAudit(id){try{const audit=await api('/api/v1/tasks/'+encodeURIComponent(id)+'/audit');byId('audit').replaceChildren(element('pre',JSON.stringify(audit,null,2)))}catch(e){status(e.message,true)}}
byId('load-memory').onclick=async()=>{const scope=byId('memory-scope').value.trim();if(!scope){status('Enter a memory scope.',true);return}try{const result=await api('/api/v1/memory/recall',{method:'POST',body:JSON.stringify({scope,max_items:100})});byId('memory-ledger').replaceChildren(element('pre',JSON.stringify(result.items,null,2)))}catch(e){status(e.message,true)}};
byId('load').onclick=load;
byId('new-org').onsubmit=async e=>{e.preventDefault();try{const org=await api('/api/v1/orgs',{method:'POST',body:JSON.stringify({name:byId('org-name').value.trim()})});byId('org-name').value='';status('Created organization '+org.name);await load();byId('user-org').value=org.org_id}catch(error){status(error.message,true)}};
byId('new-user').onsubmit=async e=>{e.preventDefault();try{const org=byId('user-org').value;const user=await api('/api/v1/orgs/'+encodeURIComponent(org)+'/users',{method:'POST',body:JSON.stringify({display_name:byId('user-name').value.trim(),role:byId('user-role').value})});byId('issued-token').replaceChildren(element('pre',user.token));byId('user-name').value='';status('Created user '+user.user_id+'. Copy the token now; it will not be shown again.')}catch(error){status(error.message,true)}};
byId('new-task').onsubmit=async e=>{e.preventDefault();try{const result=await api('/api/v1/tasks',{method:'POST',body:JSON.stringify({title:byId('title').value,privacy_class:byId('privacy').value,memory_scope:byId('scope').value,execution_profile:byId('profile').value})});status('Created task '+result.task_id);byId('title').value='';await load()}catch(error){status(error.message,true)}};
</script></body></html>"""
