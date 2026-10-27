const $ = id => document.getElementById(id);
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(url, opts){const response=await fetch(url,opts);const data=await response.json().catch(()=>({detail:'Unexpected server response'}));if(!response.ok)throw new Error(typeof data.detail==='string'?data.detail:'Request failed');return data;}
function render(data){
 $('scanid').textContent=`Scan #${data.id} · ${data.ai_status}`;
 let html=`<p class="summary">${escapeHtml(data.summary)}</p><p><strong>${data.findings.length} potential finding(s)</strong> · ${escapeHtml(data.filename)}</p>`;
 if(!data.findings.length)html+='<div class="empty">No patterns detected. This does not prove the file is secure.</div>';
 for(const f of data.findings){html+=`<article class="finding"><span class="pill ${escapeHtml(f.severity)}">${escapeHtml(f.severity.toUpperCase())}</span><small>${escapeHtml(f.source)} · ${f.line?'Line '+f.line:'Line unknown'}</small><h3>${escapeHtml(f.title)}</h3><p>${escapeHtml(f.description)}</p><p><b>Recommended:</b> ${escapeHtml(f.recommendation)}</p></article>`;}
 if(data.fixed_code)html+=`<h3>AI-suggested revised code (review before using)</h3><a href="/api/scans/${data.id}/fixed" download>Download suggested fix</a><pre>${escapeHtml(data.fixed_code)}</pre>`;
 $('result').innerHTML=html;
}
async function loadHistory(){try{const items=await api('/api/scans');$('history').innerHTML=items.length?items.map(s=>`<div class="history-row"><div><strong>${escapeHtml(s.filename)}</strong><small>Scan #${s.id} · ${escapeHtml(s.created_at)} · AI ${escapeHtml(s.ai_status)}</small></div><button data-id="${s.id}">View report</button></div>`).join(''):'No saved scans yet.'; $('history').querySelectorAll('button[data-id]').forEach(b=>b.onclick=async()=>{try{render(await api('/api/scans/'+b.dataset.id));window.scrollTo({top:300,behavior:'smooth'});}catch(e){$('status').textContent=e.message;}});}catch(e){$('history').textContent=e.message;}}
$('file').addEventListener('change',async e=>{const f=e.target.files[0];if(!f)return;$('filename').value=f.name; if(f.size>150000){$('status').textContent='File exceeds 150 KB';return;} $('source').value=await f.text();});
$('scan').onclick=async()=>{const b=$('scan');b.disabled=true;$('status').textContent='Analyzing locally…';try{const result=await api('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename:$('filename').value,code:$('source').value})});render(result);$('status').textContent='Analysis saved';await loadHistory();}catch(e){$('status').textContent=e.message;}finally{b.disabled=false;}};
$('refresh').onclick=loadHistory;loadHistory();
