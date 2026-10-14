import { BACKEND_EVENT, callDesktopApi, chooseSaveFile } from "../shell/js/bridge.js";
import { t } from "../shell/js/i18n.js";
import { showToast } from "../shell/js/toast-manager.js";
import { importantLogs, normalizeLogEntry, mergeActivitySnapshot } from "../shell/js/log-format.js";

function el(tag, cls="", text=""){ const n=document.createElement(tag); if(cls)n.className=cls; if(text!==null&&text!==undefined)n.textContent=String(text); return n; }
function button(label,cls=""){ const n=el("button",`ns-button ${cls}`.trim(),label); n.type="button"; return n; }
function card(title,description=""){ const root=document.createElement("ns-card"); const section=el("div","ns-card__section"); section.appendChild(el("h2","ns-card__title",title)); if(description)section.appendChild(el("p","ns-card__description",description)); root.appendChild(section); return {root,section}; }
function fmtSize(size){ const raw=Number(size); if(!Number.isFinite(raw)||raw<0)return ""; const units=["B","KB","MB","GB","TB"]; let v=raw,i=0; while(v>=1024&&i<units.length-1){v/=1024;i++;} return i===0?`${Math.round(v)} ${units[i]}`:`${v.toFixed(1)} ${units[i]}`; }
function fmtTime(seconds){ try{return new Date(Number(seconds)*1000).toLocaleTimeString();}catch(_){return "";} }
function transferStatusKey(value){ const raw=String(value||"receiving").toLowerCase(); if(raw==="completed"||raw==="committed")return "transfer_status_completed"; if(raw==="failed")return "transfer_status_failed"; if(raw==="cancelled")return "transfer_status_cancelled"; if(raw==="waiting"||raw==="pending")return "transfer_status_waiting"; return "transfer_status_receiving"; }

export function mountActivity({host,headerTitle}){
  let disposed=false; let snapshot=null;
  headerTitle.textContent=t("activity"); host.replaceChildren();
  host.appendChild(document.createElement("ns-loading-state"));

  async function load(){
    try{ const response=await callDesktopApi("get_activity_snapshot"); if(!response?.ok)throw new Error(response?.error?.code||"activity failed"); snapshot=mergeActivitySnapshot(snapshot,response.data); if(!disposed)render(); }
    catch(_){ if(!disposed)renderError(); }
  }
  function renderError(){ host.replaceChildren(); const state=document.createElement("ns-error-state"); state.setAttribute("title",t("activity")); state.setAttribute("message",t("service_unavailable_safe",{service:t("incoming"),support_code:"ACTIVITY"})); const retry=button(t("retry"),"ns-button--primary"); retry.dataset.stateAction="true"; retry.addEventListener("click",load); state.appendChild(retry); host.appendChild(state); }
  async function decide(requestId,accepted){ const response=await callDesktopApi("resolve_upload",{request_id:requestId,accepted}); if(!response?.ok){showToast("error","request_expired");return;} showToast(accepted?"success":"warning",accepted?"accepted":"declined"); await load(); }
  async function exportLogs(){
    if(!(snapshot?.logs||[]).length){showToast("info","no_logs_to_export");return;}
    const stamp=new Date().toISOString().replaceAll(":","").replaceAll("-","").slice(0,15); const picker=await chooseSaveFile(`netshare-logs-${stamp}.txt`); if(!picker?.ok||!picker.data?.path)return;
    const response=await callDesktopApi("export_activity_logs",{target_path:picker.data.path}); if(response?.ok)showToast("success","logs_exported"); else showToast("error","service_unavailable_safe",{service:t("log"),support_code:response?.error?.code||"EXPORT"});
  }
  function pendingRows(section){
    const items=(snapshot?.pending_uploads||[]).filter(x=>x.status==="pending");
    if(!items.length)return false;
    const label=el("div","ns-activity__subheading",t("transfer_waiting_approval")); section.appendChild(label);
    const list=el("div","ns-activity__incoming"); items.forEach(item=>{const row=el("div","ns-activity__request"); const head=el("div","ns-activity__request-head"); const copy=el("div"); copy.append(el("div","ns-activity__request-title",t("upload_request_title",{client:item.client||"—",filename:item.filename})),el("div","ns-activity__request-meta",t("upload_pending",{size:fmtSize(item.size)}))); const actions=el("div","ns-inline-actions"); const no=button(t("decline"),"ns-button--compact ns-button--danger"); no.addEventListener("click",()=>decide(item.request_id,false)); const yes=button(t("accept"),"ns-button--compact ns-button--primary"); yes.addEventListener("click",()=>decide(item.request_id,true)); actions.append(no,yes); head.append(copy,actions); row.appendChild(head); list.appendChild(row);}); section.appendChild(list);return true;
  }
  function transferRows(section){
    const items=[...(snapshot?.transfers||[])].sort((a,b)=>Number(b.time||0)-Number(a.time||0));
    if(!items.length)return false;
    section.appendChild(el("div","ns-activity__subheading",t("transfer_live_activity")));
    const list=el("div","ns-activity__transfers");
    for(const item of items){
      const row=el("div","ns-activity__transfer");
      const head=el("div","ns-activity__transfer-head");
      const copy=el("div","ns-activity__transfer-copy");
      copy.appendChild(el("div","ns-activity__request-title",item.filename||t("incoming_transfer")));
      const pct=Math.max(0,Math.min(100,Math.round(Number(item.progress||0)*100)));
      const statusKey=transferStatusKey(item.status);
      const status=t(statusKey);
      copy.appendChild(el("div","ns-activity__request-meta",t("transfer_progress_detail",{status,percent:pct,received:fmtSize(item.received_bytes||0),total:fmtSize(item.total_bytes||0),client:item.client||"—"})));
      const terminal=statusKey==="transfer_status_completed"||statusKey==="transfer_status_failed"||statusKey==="transfer_status_cancelled";
      if(terminal){
        const stateClass=statusKey==="transfer_status_completed"?"success":statusKey==="transfer_status_failed"?"error":"warning";
        const state=el("div",`ns-activity__transfer-state ns-activity__transfer-state--${stateClass}`);
        if(statusKey==="transfer_status_completed"){const icon=el("span","ns-activity__transfer-state-icon");icon.textContent="✓";state.append(icon,document.createTextNode(status));}else state.textContent=status;
        head.append(copy,state); row.appendChild(head);
      }else{
        head.append(copy,el("div","ns-activity__transfer-percent",`${pct}%`)); row.appendChild(head);
        const track=el("div","ns-activity__progress"); const fill=el("div","ns-activity__progress-fill"); fill.style.width=`${pct}%`; track.appendChild(fill); row.appendChild(track);
      }
      if(item.path)row.appendChild(el("div","ns-activity__request-meta",item.path));
      list.appendChild(row);
    }
    section.appendChild(list); return true;
  }
  function incomingCard(){
    const {root,section}=card(t("incoming_transfers"),t("incoming_transfers_description"));
    const hasPending=pendingRows(section); const hasTransfers=transferRows(section);
    if(!hasPending&&!hasTransfers)section.appendChild(el("div","ns-devices__empty",t("incoming_waiting")));
    return root;
  }
  function consoleCard(){
    const {root,section}=card(t("server_log")); const top=el("div","ns-inline-status"); top.appendChild(el("span","ns-muted",snapshot?.existing_log_stream_available?t("available"):t("unavailable"))); const exp=button(t("export_logs"),"ns-button--compact"); exp.addEventListener("click",exportLogs); top.appendChild(exp); section.appendChild(top); const consoleEl=el("div","ns-activity__console"); const visibleLogs=importantLogs(snapshot?.logs||[]); visibleLogs.forEach(item=>{const line=el("div","ns-activity__line"); line.append(el("span","ns-activity__time",fmtTime(item.time)),el("span",`ns-activity__kind-${String(item.kind||"info").toLowerCase()}`,item.message)); consoleEl.appendChild(line);}); if(!visibleLogs.length)consoleEl.appendChild(el("div","ns-subtle",t("no_logs_to_export"))); section.appendChild(consoleEl); requestAnimationFrame(()=>{if(!disposed&&consoleEl.isConnected)consoleEl.scrollTop=consoleEl.scrollHeight;}); return root;
  }
  function render(){ if(disposed)return; host.replaceChildren(); const heading=el("div","ns-section-heading"); const c=el("div"); c.append(el("div","ns-section-heading__eyebrow",`04 / ${t("activity")}`),el("h1","ns-section-heading__title",t("activity")),el("p","ns-section-heading__description",t("activity_description"))); const actions=el("div","view-actions"); const exp=button(t("export_logs"),"ns-button--compact"); exp.addEventListener("click",exportLogs); actions.appendChild(exp); heading.append(c,actions); host.appendChild(heading); const view=el("div","ns-activity"); view.append(incomingCard(),consoleCard()); host.appendChild(view); }
  function onActivity(event){ try{ const activity=event?.detail?.payload?.activity; if(!activity||disposed)return; if(activity.stream==="log"){ if(!normalizeLogEntry(activity)) return; snapshot=mergeActivitySnapshot(snapshot,{...(snapshot||{}),logs:[activity],write_activity:[],transfers:[]}); render(); } else if(activity.stream==="transfer"){ snapshot=mergeActivitySnapshot(snapshot,{...(snapshot||{}),logs:[],write_activity:[],transfers:[activity]}); render(); } else { load(); }}catch(_){} }
  globalThis.addEventListener("netshare:activity.appended",onActivity); load(); return()=>{disposed=true;globalThis.removeEventListener("netshare:activity.appended",onActivity);};
}
