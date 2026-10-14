import { callDesktopApi, chooseFolder, chooseFile, chooseSaveFile, openExternalUrl, BACKEND_EVENT } from "../shell/js/bridge.js";
import { t, languages } from "../shell/js/i18n.js";
import { showToast } from "../shell/js/toast-manager.js";
import { choiceDialog, editablePasswordDialog, passwordDialog } from "../shell/js/dialogs.js";

const ADVANCED_SECTIONS = new Set(["security","data_vault","ffmpeg","premium","cloud","tunnel","manage_folders","guest_profiles","co_servers"]);
const FFMPEG_INSTALL_URL = "https://ffmpeg.org/download.html";
const SECTIONS = [
  ["settings_group_general", [["appearance","appearance"],["performance","performance"]]],
  ["settings_group_advanced", [["security","security"],["data_vault","data_vault"],["ffmpeg","ffmpeg"],["premium","premium"],["cloud","cloud"],["tunnel","tunnel"],["manage_folders","manage_folders"],["guest_profiles","guest_profiles"],["co_servers","co_servers"]]],
  ["settings_group_system", [["permissions","permissions"],["history","history"],["about","about"]]],
];

function el(tag, cls="", text=null){ const n=document.createElement(tag); if(cls)n.className=cls; if(text!==null)n.textContent=String(text); return n; }
function btn(label, cls=""){ const n=el("button",`ns-button ${cls}`.trim(),label); n.type="button"; return n; }
function field(label, value="", type="text"){ const wrap=el("label","ns-field"); wrap.appendChild(el("span","ns-field__label",label)); const input=el("input","ns-input"); input.type=type; input.value=value ?? ""; wrap.appendChild(input); return {wrap,input}; }
function placeFieldControl(fieldDef,row,...extras){ const control=fieldDef?.input||fieldDef?.select; if(!control)return row; const parent=control.parentNode; if(parent)parent.insertBefore(row,control); else fieldDef?.wrap?.appendChild(row); row.append(control,...extras); return row; }
function selectField(label, options, value){ const wrap=el("label","ns-field"); wrap.appendChild(el("span","ns-field__label",label)); const select=el("select","ns-select"); for(const [v,l,disabled] of options){ const o=el("option","",l); o.value=v; o.disabled=Boolean(disabled); if(String(v)===String(value))o.selected=true; select.appendChild(o);} wrap.appendChild(select); return {wrap,select}; }
function segmentedField(label,options,value){
  const wrap=el("div","ns-field ns-settings-segmented-field");
  wrap.appendChild(el("span","ns-field__label",label));
  const group=el("div","ns-segmented-control"); group.setAttribute("role","group"); group.setAttribute("aria-label",label);
  let current=String(value??""); const listeners=[];
  const sync=()=>{for(const button of group.querySelectorAll("button")){const active=button.dataset.value===current;button.classList.toggle("is-active",active);button.setAttribute("aria-pressed",active?"true":"false");}};
  for(const [v,l,disabled] of options){const b=el("button","ns-segmented-control__button",l);b.type="button";b.dataset.value=String(v);b.disabled=Boolean(disabled);b.addEventListener("click",async()=>{if(b.disabled||b.dataset.value===current)return;const previous=current;current=b.dataset.value;sync();b.disabled=true;try{for(const listener of listeners)await listener(current,previous);}catch(_error){current=previous;sync();showToast("error","server_start_failed");}finally{b.disabled=Boolean(disabled);}});group.appendChild(b);}
  wrap.appendChild(group); sync();
  return {wrap,group,get value(){return current;},onChange(fn){listeners.push(fn);}};
}
function rangeField(label,value,min,max,description=""){
  const row=el("div","ns-settings-range-row"); const copy=el("div","ns-settings-range-row__copy"); copy.appendChild(el("div","ns-toggle-row__title",label)); if(description)copy.appendChild(el("div","ns-toggle-row__description",description));
  const control=el("div","ns-settings-range-row__control"); const input=el("input","ns-range"); input.type="range"; input.min=String(min); input.max=String(max); input.step="1"; input.value=String(value); const out=el("span","ns-settings-range-row__value",input.value); input.addEventListener("input",()=>{out.textContent=input.value;}); control.append(input,out); row.append(copy,control); return {row,input,out};
}
function card(title, description=""){ const root=document.createElement("ns-card"); const section=el("div","ns-card__section"); section.appendChild(el("h2","ns-card__title",title)); if(description)section.appendChild(el("p","ns-card__description",description)); root.appendChild(section); return {root,section}; }
function kv(parent,key,value){ const row=el("div","ns-settings-kv"); row.append(el("div","ns-settings-kv__key",key),el("div","ns-settings-value",value ?? "—")); parent.appendChild(row); }
function badge(text,tone="neutral"){ const b=document.createElement("ns-status-badge"); b.textContent=text; b.setAttribute("tone",tone); return b; }
function switchRow(label, checked, onChange, description=""){ const row=el("div","ns-toggle-row"); const copy=el("div","ns-toggle-row__copy"); copy.appendChild(el("div","ns-toggle-row__title",label)); if(description)copy.appendChild(el("div","ns-toggle-row__description",description)); const sw=el("button","ns-switch"); sw.type="button"; sw.setAttribute("role","switch"); sw.setAttribute("aria-checked",checked?"true":"false"); sw.addEventListener("click",async()=>{ const next=sw.getAttribute("aria-checked")!=="true"; sw.disabled=true; try{ if(await onChange(next)!==false)sw.setAttribute("aria-checked",next?"true":"false"); }catch(_error){showToast("error","server_start_failed");}finally{sw.disabled=false;} }); row.append(copy,sw); return row; }
function formatBytes(value){ if(value==null)return t("unavailable"); const units=["B","KiB","MiB","GiB","TiB"]; let n=Number(value),i=0; while(n>=1024&&i<units.length-1){n/=1024;i++;} return `${n.toFixed(i?1:0)} ${units[i]}`; }
async function copyText(value){
  if(!value)return false;
  try{ await navigator.clipboard.writeText(String(value)); return true; }catch(_){
    try{ const area=el("textarea"); area.value=String(value); area.style.position="fixed"; area.style.opacity="0"; document.body.appendChild(area); area.select(); const ok=document.execCommand("copy"); area.remove(); return Boolean(ok); }catch(__){ return false; }
  }
}
async function recoveryKeyDialog(phrase){
  return new Promise(resolve=>{
    const host=document.getElementById("dialog-host")||document.body;
    const dialog=document.createElement("ns-dialog");
    const header=el("div","ns-dialog__header"); header.appendChild(el("h2","ns-dialog__title",t("vault_recovery_key_title")));
    const body=el("div","ns-dialog__body");
    body.append(el("div","ns-muted",t("vault_recovery_key_description")));
    const block=el("pre","ns-vault-recovery-key",phrase); block.setAttribute("aria-label",t("vault_recovery_key_label")); body.appendChild(block);
    const footer=el("div","ns-dialog__footer");
    const copy=btn(t("vault_recovery_copy")); copy.addEventListener("click",async()=>{if(await copyText(phrase))showToast("success","copy");});
    const print=btn(t("vault_recovery_print")); print.addEventListener("click",()=>{
      const frame=document.createElement("iframe"); frame.className="ns-vault-print-frame"; document.body.appendChild(frame);
      const doc=frame.contentDocument; if(!doc){frame.remove();return;}
      doc.open(); doc.write("<!doctype html><meta charset=utf-8><title></title><style>body{font:16px monospace;padding:32px;line-height:1.8}h1{font:700 18px sans-serif}pre{white-space:pre-wrap;word-break:break-word}</style>"); doc.close();
      const title=doc.createElement("h1"); title.textContent=t("vault_recovery_key_title"); const pre=doc.createElement("pre"); pre.textContent=phrase; doc.body.append(title,pre);
      frame.contentWindow?.focus(); frame.contentWindow?.print(); globalThis.setTimeout(()=>frame.remove(),500);
    });
    const saved=btn(t("vault_recovery_saved"),"ns-button--primary"); saved.addEventListener("click",()=>dialog.close("saved"),{once:true});
    footer.append(copy,print,saved); dialog.append(header,body,footer);
    dialog.addEventListener("close",()=>{block.textContent="";try{dialog.remove();}catch(_){}resolve(true);},{once:true});
    host.appendChild(dialog); dialog.showModal();
  });
}
function formatTimestamp(value){ if(!value)return "—"; const d=new Date(Number(value)*1000); return Number.isNaN(d.getTime())?"—":d.toLocaleString(); }
function sectionHeading(host,title,copy=""){ host.appendChild(el("h2","ns-settings-section-title",title)); if(copy)host.appendChild(el("p","ns-settings-section-copy",copy)); }
async function api(method,params={}){
  const r=await callDesktopApi(method,params);
  if(!r?.ok){
    const error=new Error(r?.error?.code||method);
    error.code=String(r?.error?.code||method);
    error.details=(r?.error?.details&&typeof r.error.details==="object")?{...r.error.details}:{};
    throw error;
  }
  return r.data;
}
function cloudFailureText(error){
  const details=error?.details||{};
  const providerCode=String(details.provider_code||"").trim();
  const message=String(details.provider_message||"").trim();
  const http=Number(details.http_status||0);
  const parts=[];
  if(providerCode)parts.push(providerCode);
  if(message)parts.push(message);
  if(http>0)parts.push(`HTTP ${http}`);
  return parts.join(" · ")||String(error?.code||error?.message||"cloud_connection_failed");
}
function fail(host,retry,error=null,key="settings",openVault=null){ host.replaceChildren(); const state=document.createElement("ns-error-state"); const code=String(error?.code||error?.message||"WEBVIEW").slice(0,72); state.setAttribute("title",code==="vault_locked"?t("vault_locked"):(key==="security"?t("security_monitor_title"):(t(key)||t("settings")))); if(code==="vault_locked"){state.setAttribute("message",t("vault_locked_section_message"));const unlock=btn(t("vault_unlock"),"ns-button--primary");unlock.dataset.stateAction="true";unlock.addEventListener("click",()=>openVault?.());state.appendChild(unlock);}else{state.setAttribute("message",t("settings_section_load_error_safe",{support_code:code}));const b=btn(t("retry"),"ns-button--primary");b.dataset.stateAction="true";b.addEventListener("click",retry);state.appendChild(b);} host.appendChild(state); }

export function mountSettings({host,headerTitle}){
  let disposed=false; let active=String(globalThis.__netshareSettingsInitialSection||"appearance"); if(active==="updates")active="about"; globalThis.__netshareSettingsInitialSection=""; let body=null; let root=null; let showAdvanced=true; let sectionCleanup=()=>{}; let openSequence=0; const sessionSecrets={community:"",admin:"",web:""};
  headerTitle.textContent=t("settings"); host.replaceChildren();

  const heading=el("div","ns-section-heading"); const headingCopy=el("div"); headingCopy.append(el("div","ns-section-heading__eyebrow",`05 / ${t("settings")}`),el("h1","ns-section-heading__title",t("settings")),el("p","ns-section-heading__description",t("settings_description"))); heading.appendChild(headingCopy); host.appendChild(heading);
  root=el("div","ns-settings-view"); const nav=el("nav","ns-settings-nav"); body=el("div","ns-settings-body"); root.append(nav,body); host.appendChild(root);

  function renderNav(){
    nav.replaceChildren();
    const advanced=el("div","ns-settings-nav__advanced");
    advanced.appendChild(switchRow(t("advanced_features"),showAdvanced,async next=>{
      const updated=await api("update_advanced_visibility",{enabled:next});
      showAdvanced=Boolean(updated.show_advanced_settings);
      if(!showAdvanced&&ADVANCED_SECTIONS.has(active))active="permissions";
      renderNav();
      await open(active);
      return true;
    }));
    nav.appendChild(advanced);
    for(const [groupKey,items] of SECTIONS){
      const visible=items.filter(([key])=>showAdvanced||!ADVANCED_SECTIONS.has(key));
      if(!visible.length)continue;
      const g=el("div","ns-settings-nav__group");
      g.appendChild(el("div","ns-settings-nav__label",t(groupKey)));
      for(const [key,label] of visible){ const b=el("button","ns-settings-nav__item"); b.type="button"; b.dataset.settingsSection=key; const index=SECTIONS.flatMap(([,entries])=>entries).findIndex(([sectionKey])=>sectionKey===key)+1; b.append(el("span","nav-num",String(index).padStart(2,"0")),document.createTextNode(key==="security"?t("security_monitor_title"):t(label))); b.addEventListener("click",()=>open(key)); g.appendChild(b); }
      nav.appendChild(g);
    }
    markNav();
  }

  function markNav(){ for(const b of nav.querySelectorAll("[data-settings-section]")){ if(b.dataset.settingsSection===active)b.setAttribute("aria-current","page"); else b.removeAttribute("aria-current"); } }
  async function open(key){
    sectionCleanup(); sectionCleanup=()=>{}; active=key; markNav();
    const sequence=++openSequence;
    body.scrollTop=0;
    body.replaceChildren(document.createElement("ns-loading-state"));
    const page=el("div","ns-settings-page");
    try{
      const renderer=renderers[key];
      if(typeof renderer!=="function")throw new Error(`settings.renderer.${key}.missing`);
      await renderer(page);
      if(disposed||sequence!==openSequence||active!==key)return;
      body.replaceChildren(page);
      body.scrollTop=0;
    }catch(error){
      if(!disposed&&sequence===openSequence&&active===key)fail(body,()=>open(key),error,key,()=>open("data_vault"));
    }
  }

  const renderers={
    appearance: async(h)=>{
      const s=await api("get_settings_snapshot");
      sectionHeading(h,t("appearance"));
      const c=card(t("appearance"));
      c.section.classList.add("ns-settings-appearance");
      const theme=segmentedField(t("theme"),[["system",t("system")],["light",t("light")],["dark",t("dark")]],s.theme);
      const size=segmentedField(t("text_size"),[["small",t("small")],["normal",t("normal")],["large",t("large")]],s.text_size);
      theme.onChange(async value=>{
        const x=await api("update_appearance",{theme:value});
        document.documentElement.dataset.theme=x.theme==="system"?(matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light"):x.theme;
        showToast("success","save");
      });
      size.onChange(async value=>{
        const x=await api("update_appearance",{text_size:value});
        document.documentElement.dataset.textSize=x.text_size||"normal";
        showToast("success","save");
      });
      const langOptions=Object.entries(languages()).map(([code,label])=>[code,label]);
      const lang=selectField(t("language"),langOptions,s.language);
      lang.select.classList.add("ns-select--custom");
      lang.select.addEventListener("change",async()=>{await api("update_language",{language:lang.select.value});showToast("success","save");});
      c.section.append(theme.wrap,size.wrap,lang.wrap);
      h.appendChild(c.root);
    },
    performance: async(h)=>{
      const [s,d]=await Promise.all([api("get_settings_snapshot"),api("get_performance_details")]);
      sectionHeading(h,t("performance"),t("performance_description"));
      const ram=d.total_memory_bytes==null?t("performance_hardware_unknown"):`${(Number(d.total_memory_bytes)/(1024**3)).toFixed(1)} GiB`;

      const hardware=el("div","ns-performance-hardware");
      const icon=el("div","ns-performance-hardware__icon");
      icon.innerHTML='<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="4" width="16" height="16"/><path d="M9 9h6v6H9zM4 9h2M4 15h2M18 9h2M18 15h2M9 4v2M15 4v2M9 18v2M15 18v2"/></svg>';
      const copy=el("div","ns-performance-hardware__copy");
      copy.append(el("strong","",`${ram.toUpperCase()} · ${d.cpu_count} CPU`),el("span","",t("performance_hardware_summary",{ram,cpus:d.cpu_count})));
      hardware.append(icon,copy); h.appendChild(hardware);

      const presetCard=card(t("performance_preset"));
      const preset=segmentedField(t("performance_preset"),[
        ["economy",t("performance_preset_economy")],["balanced_light",t("performance_preset_balanced_light")],
        ["balanced",t("performance_preset_balanced")],["performance",t("performance_preset_performance")],
      ],d.selected_preset);
      preset.onChange(async value=>{await api("update_performance_preset",{preset:value});showToast("success","save");await open("performance");});
      presetCard.section.appendChild(preset.wrap); h.appendChild(presetCard.root);

      const workerCard=card(t("performance_advanced_coming_soon").replace(/\s*\(.*\)$/,""));
      workerCard.root.classList.add("ns-performance-workers-card");
      const hard=Math.max(2,Number(d.worker_hard_total||d.worker_budget?.hard_total||2));
      const iw=rangeField(t("performance_future_index_workers"),Number(d.worker_budget.index_workers||1),1,hard,t("performance_index_workers_limit",{maximum:hard}));
      const aw=rangeField(t("performance_future_analysis_workers"),Number(d.worker_budget.analysis_workers||1),1,hard,t("performance_analysis_workers_limit",{maximum:hard}));
      async function saveWorker(changed){
        iw.input.disabled=true;aw.input.disabled=true;
        try{
          await api("update_worker_budget",{index_workers:Number(iw.input.value),analysis_workers:Number(aw.input.value),changed});
          showToast("success","save");
          await open("performance");
        }finally{iw.input.disabled=false;aw.input.disabled=false;}
      }
      iw.input.addEventListener("change",()=>saveWorker("index"));
      aw.input.addEventListener("change",()=>saveWorker("analysis"));
      workerCard.section.append(iw.row,aw.row,el("div","ns-settings-note",t("performance_workers_summary",{used:d.worker_budget.index_workers+d.worker_budget.analysis_workers,maximum:d.worker_budget.hard_total,adjustment:d.worker_budget.adjusted||""})));
      const policy=d.policy||{};
      workerCard.section.appendChild(el("div","ns-settings-note",t("performance_policy_summary",{
        global_slots:policy.global_transcode_limit??"—",guest_slots:policy.guest_transcode_limit??"—",
        source:policy.source_available?t("available"):t("unavailable"),memory_limit:policy.ffmpeg_process_memory_limit_mib??"—",
      })));
      h.appendChild(workerCard.root);

      const g=card(t("performance_gpu_title"),t("performance_gpu_help"));
      const verified=d.gpu_backends.some(x=>x.verified);
      const choices=[["auto",t("performance_gpu_preference_auto")],["cpu",t("performance_gpu_preference_cpu")],["gpu",t("performance_gpu_preference_gpu"),!verified]];
      for(const b of d.gpu_backends)choices.push([b.backend,t(`performance_gpu_preference_${b.backend}`),!b.verified]);
      const gp=selectField(t("performance_gpu_preference"),choices,s.gpu_encoder_preference); gp.select.classList.add("ns-select--custom");
      g.section.appendChild(gp.wrap);
      gp.select.addEventListener("change",async()=>{await api("update_gpu_preference",{preference:gp.select.value});showToast("success","save");});
      for(const b of d.gpu_backends){const status=b.verified?t("performance_gpu_verified"):b.declared?t("performance_gpu_declared_only"):t("performance_gpu_not_declared");kv(g.section,b.backend.toUpperCase(),b.device_name?`${status} · ${b.device_name}`:status);}
      g.section.appendChild(el("div","ns-settings-note",t("performance_gpu_session_limit",{maximum:1})));
      const log=field(t("performance_log_budget_title"),s.log_buffer_lines,"number");log.input.min=200;log.input.max=5000;
      const saveLog=btn(t("save"));saveLog.addEventListener("click",async()=>{await api("update_log_buffer_lines",{value:Number(log.input.value)});showToast("success","save");});
      g.section.append(log.wrap,el("div","ns-muted",t("performance_log_budget_help")),saveLog);h.appendChild(g.root);
    },
    data_vault: async(h)=>{
      let d=await api("get_data_vault_settings");
      sectionHeading(h,t("data_vault"),t("data_vault_description"));

      const statusCard=card(t("vault_status"),t("vault_protected_scope_description"));
      statusCard.section.appendChild(badge(d.configured?(d.unlocked?t("vault_unlocked"):t("vault_locked")):t("vault_not_configured"),d.unlocked?"success":d.configured?"warning":"neutral"));
      if(d.configured){
        kv(statusCard.section,t("vault_mode"),d.mode==="password"?t("vault_mode_password"):t("vault_mode_os"));
        const recoveryText=d.recovery_decision==="enabled"?t("vault_recovery_enabled"):d.recovery_decision==="skipped"?t("vault_recovery_skipped"):t("vault_recovery_not_decided");
        kv(statusCard.section,t("vault_recovery"),recoveryText);
      }
      h.appendChild(statusCard.root);

      const migration=d.migration||{};
      if(d.configured&&d.unlocked&&(migration.state==="running"||migration.state==="failed")){
        const migrationCard=card(t("vault_migration_title"));
        if(migration.state==="running"){
          const total=Math.max(0,Number(migration.total_files)||0),completed=Math.max(0,Number(migration.completed_files)||0);
          const percent=total?Math.min(100,Math.round(completed*100/total)):0;
          migrationCard.section.appendChild(el("div","ns-settings-note",t("vault_migration_running",{completed,total,percent})));
          setTimeout(()=>{if(document.body.contains(h))open("data_vault");},750);
        }else{migrationCard.section.appendChild(el("div","ns-settings-note",t("vault_migration_failed")));}
        h.appendChild(migrationCard.root);
      }

      if(!d.configured){
        const setup=card(t("vault_configure"));
        const mode=segmentedField(t("vault_mode"),[["os",t("vault_mode_os"),!d.os_protection_available],["password",t("vault_mode_password")]],d.os_protection_available?"os":"password");
        const password=field(t("vault_password"),"","password"), confirm=field(t("vault_confirm_password"),"","password");
        const remember=switchRow(t("vault_remember_windows"),false,async next=>{remember.dataset.checked=next?"1":"0";return true;},t("vault_remember_windows_description")); remember.dataset.checked="0";
        const sync=()=>{const pw=mode.value==="password";password.wrap.hidden=!pw;confirm.wrap.hidden=!pw;remember.hidden=!pw;}; mode.onChange(()=>sync()); sync();
        const configure=btn(t("vault_configure"),"ns-button--primary");
        configure.addEventListener("click",async()=>{
          if(mode.value==="password"&&(password.input.value.length<8||password.input.value!==confirm.input.value)){showToast("error",password.input.value.length<8?"vault_password_too_short":"vault_password_mismatch");return;}
          configure.disabled=true;
          try{d=await api("configure_data_vault",{mode:mode.value,password:password.input.value,remember_on_windows:remember.dataset.checked==="1"});password.input.value="";confirm.input.value="";showToast("success","vault_configured_success");await open("data_vault");}catch(error){if(error?.code==="os_protection_unavailable"){showToast("error","vault_os_unavailable");await open("data_vault");}else showToast("error","vault_operation_failed");}finally{if(configure.isConnected)configure.disabled=false;}
        });
        setup.section.append(mode.wrap,password.wrap,confirm.wrap,remember,configure); h.appendChild(setup.root); return;
      }

      if(!d.unlocked){
        const unlock=card(t("vault_unlock"));
        if(d.mode==="os"){const b=btn(t("vault_unlock"),"ns-button--primary");b.addEventListener("click",async()=>{try{await api("unlock_data_vault",{method:"os"});showToast("success","vault_unlocked_success");await open("data_vault");}catch(_){showToast("error","vault_operation_failed");}});unlock.section.appendChild(b);}
        else{
          const pw=field(t("vault_password"),"","password"); const b=btn(t("vault_unlock"),"ns-button--primary"); b.addEventListener("click",async()=>{try{await api("unlock_data_vault",{method:"password",secret:pw.input.value});pw.input.value="";showToast("success","vault_unlocked_success");await open("data_vault");}catch(_){pw.input.value="";showToast("error","vault_operation_failed");}}); unlock.section.append(pw.wrap,b);
          if(d.recovery_enabled){const rk=field(t("vault_recovery_key_label"),"","password");const rb=btn(t("vault_recover"));rb.addEventListener("click",async()=>{try{await api("unlock_data_vault",{method:"recovery",secret:rk.input.value});rk.input.value="";showToast("success","vault_unlocked_success");await open("data_vault");}catch(_){rk.input.value="";showToast("error","vault_recovery_invalid");}});unlock.section.append(rk.wrap,rb);}
        }
        h.appendChild(unlock.root); return;
      }

      const protection=card(t("vault_mode"));
      protection.section.appendChild(el("div","ns-settings-note",d.mode==="password"?t("vault_mode_password_description"):t("vault_mode_os_description")));
      if(d.mode==="password"){
        const remember=switchRow(t("vault_remember_windows"),Boolean(d.remember_on_windows),async next=>{try{await api("set_data_vault_remember_on_windows",{enabled:next});showToast("success","save");return true;}catch(error){showToast("error",error?.code==="os_protection_unavailable"?"vault_os_unavailable":"vault_operation_failed");return false;}},t("vault_remember_windows_description")); protection.section.appendChild(remember);
        const current=field(t("vault_current_password"),"","password"), next=field(t("vault_new_password"),"","password"), confirm=field(t("vault_confirm_password"),"","password");
        const change=btn(t("vault_change_password")); change.addEventListener("click",async()=>{if(next.input.value.length<8||next.input.value!==confirm.input.value){showToast("error",next.input.value.length<8?"vault_password_too_short":"vault_password_mismatch");return;}try{await api("change_data_vault_password",{current_password:current.input.value,new_password:next.input.value});current.input.value=next.input.value=confirm.input.value="";showToast("success","vault_password_changed");}catch(_){current.input.value=next.input.value=confirm.input.value="";showToast("error","vault_operation_failed");}});
        protection.section.append(current.wrap,next.wrap,confirm.wrap,change);
        const toOs=btn(t("vault_mode_os"));toOs.disabled=!d.os_protection_available;toOs.addEventListener("click",async()=>{const pw=await passwordDialog({title:t("vault_change_mode"),message:t("vault_mode_os_description"),label:t("vault_current_password"),saveLabel:t("vault_change_mode"),cancelLabel:t("cancel")});if(pw===null)return;try{await api("change_data_vault_mode",{mode:"os",current_password:pw});showToast("success","vault_mode_changed");await open("data_vault");}catch(error){if(error?.code==="os_protection_unavailable"){showToast("error","vault_os_unavailable");await open("data_vault");}else showToast("error","vault_operation_failed");}});protection.section.appendChild(toOs);
      }else{
        const np=field(t("vault_new_password"),"","password"), cp=field(t("vault_confirm_password"),"","password"); const remember=switchRow(t("vault_remember_windows"),false,async next=>{remember.dataset.checked=next?"1":"0";return true;},t("vault_remember_windows_description"));remember.dataset.checked="0";
        const toPassword=btn(t("vault_mode_password"));toPassword.addEventListener("click",async()=>{if(np.input.value.length<8||np.input.value!==cp.input.value){showToast("error",np.input.value.length<8?"vault_password_too_short":"vault_password_mismatch");return;}try{await api("change_data_vault_mode",{mode:"password",new_password:np.input.value,remember_on_windows:remember.dataset.checked==="1"});np.input.value=cp.input.value="";showToast("success","vault_mode_changed");await open("data_vault");}catch(_){showToast("error","vault_operation_failed");}}); protection.section.append(np.wrap,cp.wrap,remember,toPassword);
      }
      h.appendChild(protection.root);

      if(d.recovery_decision==="undecided"){
        const recovery=card(t("vault_recovery"),t("vault_recovery_warning"));
        const generate=btn(t("vault_recovery_generate"),"ns-button--primary");generate.addEventListener("click",async()=>{try{const result=await api("generate_data_vault_recovery_key");await recoveryKeyDialog(result.recovery_key);await open("data_vault");}catch(_){showToast("error","vault_operation_failed");}});
        const skip=btn(t("vault_recovery_skip"),"ns-button--danger");skip.addEventListener("click",async()=>{const q=await choiceDialog({title:t("vault_recovery_skip"),message:t("vault_recovery_skip_warning"),actions:[{label:t("cancel"),value:"cancel"},{label:t("vault_recovery_skip_confirm"),value:"skip",kind:"danger"}]});if(q!=="skip")return;try{await api("skip_data_vault_recovery_key",{confirmed:true});await open("data_vault");}catch(_){showToast("error","vault_operation_failed");}}); recovery.section.append(generate,skip);h.appendChild(recovery.root);
      }
    },
    security: async(h)=>{
      const d=await api("get_security_monitor_settings");
      const cfg=d.config||{};
      sectionHeading(h,t("security_monitor_title"),t("security_monitor_description"));
      const savePatch=async patch=>{await api("update_security_monitor_settings",{values:patch});showToast("success","save");await open("security");};

      const protection=card(t("security_protection"));
      protection.section.append(
        switchRow(t("security_enable_monitoring"),Boolean(cfg.enabled),async value=>{await savePatch({enabled:value});return true;}),
        switchRow(t("security_system_notifications"),Boolean(cfg.notify),async value=>{await savePatch({notify:value});return true;}),
      );
      const mode=segmentedField(t("security_protection_mode"),[["monitor",t("security_mode_monitor")],["temporary",t("security_mode_temp_block")],["permanent",t("security_mode_permanent")]],cfg.block_mode||"temporary");
      mode.onChange(value=>savePatch({block_mode:value})); protection.section.appendChild(mode.wrap);
      const basic=el("div","ns-settings-security-grid");
      const auth=field(t("security_failed_auth_threshold"),cfg.auth_failures,"number");auth.input.min=2;auth.input.max=100;
      const authWindow=field(t("security_auth_window_seconds"),cfg.auth_window_seconds,"number");authWindow.input.min=10;authWindow.input.max=86400;
      const blockSeconds=field(t("security_temp_block_duration_seconds"),cfg.block_seconds,"number");blockSeconds.input.min=30;blockSeconds.input.max=604800;
      basic.append(auth.wrap,authWindow.wrap,blockSeconds.wrap);protection.section.appendChild(basic);
      const saveBasic=btn(t("save"),"ns-button--primary");saveBasic.addEventListener("click",()=>savePatch({auth_failures:Number(auth.input.value),auth_window_seconds:Number(authWindow.input.value),block_seconds:Number(blockSeconds.input.value)}));protection.section.appendChild(saveBasic);
      h.appendChild(protection.root);

      const expert=card(t("security_expert_detection"));
      const expertGrid=el("div","ns-settings-security-grid");
      const burst=field(t("security_request_burst_threshold"),cfg.burst_requests,"number");burst.input.min=30;burst.input.max=10000;
      const burstWindow=field(t("security_burst_window_seconds"),cfg.burst_window_seconds,"number");burstWindow.input.min=5;burstWindow.input.max=3600;
      const misses=field(t("security_unknown_route_threshold"),cfg.route_misses,"number");misses.input.min=3;misses.input.max=1000;
      const missWindow=field(t("security_route_scan_window_seconds"),cfg.route_window_seconds,"number");missWindow.input.min=5;missWindow.input.max=3600;
      expertGrid.append(burst.wrap,burstWindow.wrap,misses.wrap,missWindow.wrap);expert.section.appendChild(expertGrid);
      const saveExpert=btn(t("save"));saveExpert.addEventListener("click",()=>savePatch({burst_requests:Number(burst.input.value),burst_window_seconds:Number(burstWindow.input.value),route_misses:Number(misses.input.value),route_window_seconds:Number(missWindow.input.value)}));expert.section.appendChild(saveExpert);h.appendChild(expert.root);

      const blocked=card(t("security_blocked_sources"));
      const blocks=Array.isArray(d.blocked_ips)?d.blocked_ips:[];
      if(!blocks.length)blocked.section.appendChild(el("div","ns-muted",t("security_no_blocked_sources")));
      for(const item of blocks){const row=el("div","ns-settings-list-row");const main=el("div","ns-settings-list-row__main");const meta=item.permanent?t("security_mode_permanent"):`${Math.max(0,Number(item.remaining_seconds||0))}s · ${item.reason||""}`;main.append(el("div","ns-settings-list-row__title",item.ip||"—"),el("div","ns-settings-list-row__meta",meta));const unblock=btn(t("security_unblock"),"ns-button--compact");unblock.addEventListener("click",async()=>{await api("unblock_security_ip",{ip:item.ip});showToast("success","save");await open("security");});row.append(main,unblock);blocked.section.appendChild(row);}h.appendChild(blocked.root);

      const events=card(t("security_recent_events"));
      const eventItems=Array.isArray(d.events)?d.events:[];
      const actions=el("div","ns-settings-actions");const clear=btn(t("security_clear_history"),"ns-button--danger ns-button--compact");clear.disabled=!eventItems.length;clear.addEventListener("click",async()=>{const q=await choiceDialog({title:t("security_clear_history"),message:t("security_clear_history_confirm"),actions:[{label:t("cancel"),value:"cancel"},{label:t("security_clear_history"),value:"clear",kind:"danger"}]});if(q==="clear"){await api("clear_security_monitor_history");await open("security");}});actions.appendChild(clear);events.section.appendChild(actions);
      if(!eventItems.length)events.section.appendChild(el("div","ns-muted",t("security_no_events")));
      const list=el("div","ns-security-events");
      for(const item of eventItems.slice(0,100)){const row=el("div","ns-security-event");const dot=el("span",`ns-security-event__dot ns-security-event__dot--${item.severity||"info"}`);const main=el("div","ns-security-event__main");main.append(el("div","ns-security-event__title",`${String(item.type||"").replaceAll("_"," ").toUpperCase()} · ${item.ip||"—"}`),el("div","ns-security-event__meta",`${formatTimestamp(item.timestamp)}${item.method?` · ${item.method}`:""}${item.path?` · ${item.path}`:""}${item.action?` · ${item.action}`:""}`));row.append(dot,main);list.appendChild(row);}events.section.appendChild(list);h.appendChild(events.root);

      let stopped=false;let timer=null;const signature=JSON.stringify({events:eventItems.slice(0,20).map(x=>x.id),blocks:blocks.map(x=>[x.ip,x.remaining_seconds,x.permanent]),config:cfg});
      const tick=()=>{timer=globalThis.setTimeout(async()=>{if(stopped||disposed||active!=="security")return;try{const response=await callDesktopApi("get_security_monitor_settings");if(response?.ok){const n=response.data||{};const next=JSON.stringify({events:(n.events||[]).slice(0,20).map(x=>x.id),blocks:(n.blocked_ips||[]).map(x=>[x.ip,x.remaining_seconds,x.permanent]),config:n.config||{}});if(next!==signature){await open("security");return;}}}catch(_){}if(!stopped&&!disposed&&active==="security")tick();},2000);};tick();sectionCleanup=()=>{stopped=true;if(timer)globalThis.clearTimeout(timer);};
    },
    ffmpeg: async(h)=>{
      const [d, installPlan]=await Promise.all([api("get_ffmpeg_details"),api("get_ffmpeg_install_plan")]);
      sectionHeading(h,t("ffmpeg_settings"),t("ffmpeg_path_description"));
      const c=card(t("ffmpeg_settings"));
      const f=field(t("ffmpeg_settings"),d.configured_path||"");
      const row=el("div","ns-settings-inline-form");
      const browse=btn(t("browse")); browse.addEventListener("click",async()=>{ const r=await chooseFile(); if(r?.ok&&r.data.path)f.input.value=r.data.path; }); placeFieldControl(f,row,browse); c.section.appendChild(f.wrap);
      if(d.manual_path_invalid)c.section.appendChild(el("div","ns-settings-note ns-settings-danger-note",d.manual_path_error||t("ffmpeg_manual_invalid")));
      kv(c.section,t("ffmpeg_source_path"),d.detected_path||t("unavailable"));
      kv(c.section,t("available"),d.available?t("available"):t("unavailable"));
      kv(c.section,t("ffmpeg_label_hls"),d.hls_transcoding?t("available"):t("unavailable"));
      kv(c.section,t("performance_gpu_title"),d.hls_transcoding_gpu?t("available"):t("unavailable"));
      kv(c.section,t("ffmpeg_label_audio"),d.audio_analysis?t("available"):t("unavailable"));
      kv(c.section,t("ffmpeg_label_thumbnails"),d.video_thumbnails?t("available"):t("unavailable"));
      const installInfo=card(t("ffmpeg_install_button",{manager:String(installPlan.manager||"").toUpperCase()||"—"}),t("ffmpeg_install_legal_notice"));
      kv(installInfo.section,t("ffmpeg_install_os"),installPlan.os_family||t("unavailable"));
      kv(installInfo.section,t("ffmpeg_install_command"),installPlan.command||t("unavailable"));
      const installActions=el("div","ns-settings-actions");
      if(installPlan.supported){
        const install=btn(t("ffmpeg_install_button",{manager:String(installPlan.manager||"").toUpperCase()}),"ns-button--primary");
        install.addEventListener("click",async()=>{ install.disabled=true; try{ const result=await api("install_ffmpeg"); if(result?.started)showToast("success","ffmpeg_install_started"); else showToast("warning","ffmpeg_install_unavailable"); } finally { install.disabled=false; } });
        installActions.appendChild(install);
      } else {
        installInfo.section.appendChild(el("div","ns-settings-note",t("ffmpeg_install_unavailable")));
      }
      const official=btn(t("ffmpeg_install_help")); official.addEventListener("click",()=>openExternalUrl(FFMPEG_INSTALL_URL)); installActions.appendChild(official);
      installInfo.section.appendChild(installActions);
      const actions=el("div","ns-settings-actions");
      const re=btn(t("ffmpeg_recheck"),"ns-button--primary"); re.addEventListener("click",async()=>{ re.disabled=true; try{await api("recheck_ffmpeg",{path:f.input.value});showToast("success","ffmpeg_recheck");open("ffmpeg");}finally{re.disabled=false;} });
      actions.append(re); c.section.appendChild(actions); h.append(c.root,installInfo.root);
    },
    premium: async(h)=>{
      const d=await api("get_premium_settings");
      sectionHeading(h,t("premium"));

      // Show the real shared-root parents immediately. Premium marker discovery
      // continues in the Python background runtime so a large library never
      // blocks opening this Settings section.
      const parents=card(t("shared_folders"));
      if(!d.parent_folders?.length)parents.section.appendChild(el("div","ns-muted",t("unavailable")));
      for(const root of (d.parent_folders||[])){
        const r=el("div","ns-settings-list-row");
        const m=el("div","ns-settings-list-row__main");
        m.append(el("div","ns-settings-list-row__title",root.name||root.path),el("div","ns-settings-list-row__meta",root.path));
        r.appendChild(m); parents.section.appendChild(r);
      }
      h.appendChild(parents.root);

      const create=card(t("mark_folder_premium"));
      const path=field(t("directory")); path.input.readOnly=true;
      const browse=btn(t("browse")); browse.addEventListener("click",async()=>{const r=await chooseFolder();if(r?.ok&&r.data.path)path.input.value=r.data.path;});
      const pr=el("div","ns-settings-inline-form"); placeFieldControl(path,pr,browse);
      const label=field(t("premium_folder_label_prompt"));
      const price=field(t("premium_folder_price_prompt"));
      const mark=btn(t("mark_folder_premium"),"ns-button--primary");
      mark.addEventListener("click",async()=>{await api("mark_premium_folder",{path:path.input.value,label:label.input.value,price_note:price.input.value});showToast("success","premium_marked_log",{folder:path.input.value});open("premium");});
      create.section.append(path.wrap,label.wrap,price.wrap,mark); h.appendChild(create.root);

      const folders=card(t("premium_folders"));
      const folderRows=el("div","ns-settings-premium-results"); folders.section.appendChild(folderRows); h.appendChild(folders.root);
      const renderFolders=(snapshot)=>{
        folderRows.replaceChildren();
        if(snapshot.scan_error)folderRows.appendChild(el("div","ns-settings-note ns-settings-danger-note",snapshot.scan_error));
        for(const x of (snapshot.folders||[])){
          const r=el("div","ns-settings-list-row"); const m=el("div","ns-settings-list-row__main");
          m.append(el("div","ns-settings-list-row__title",x.label||x.folder_path),el("div","ns-settings-list-row__meta",`${x.folder_path}${x.price_note?` · ${x.price_note}`:""}`));
          const b=btn(t("generate_code"),"ns-button--compact");
          b.addEventListener("click",async()=>{const code=await api("generate_premium_code",{folder_path:x.folder_path});if(code?.code){try{await navigator.clipboard.writeText(code.code);}catch(_){}showToast("success","premium_code_generated_log",{folder:x.folder_path});}open("premium");});
          r.append(m,b); folderRows.appendChild(r);
        }
        if(snapshot.scanning){
          const status=el("div","ns-settings-background-status");
          const dot=el("span","ns-settings-background-status__dot");
          status.append(dot,document.createTextNode(`${t("loading")}…`)); folderRows.appendChild(status);
        }else if(!(snapshot.folders||[]).length&&!snapshot.scan_error){
          folderRows.appendChild(el("div","ns-muted",t("no_premium_folders")));
        }
      };
      renderFolders(d);

      const codes=card(t("codes_table"));
      if(!d.codes.length)codes.section.appendChild(el("div","ns-muted",t("no_active_codes")));
      for(const x of d.codes){
        const r=el("div","ns-settings-list-row"); const status=x.revoked?t("code_revoked"):x.expired?t("code_expired"):x.used?t("code_redeemed"):t("code_unused");
        const m=el("div","ns-settings-list-row__main");m.append(el("div","ns-settings-list-row__title",`#${x.id} · ${status}`),el("div","ns-settings-list-row__meta",`${x.folder_path}${x.device_id?` · ${x.device_id}`:""}`));
        r.appendChild(m);
        if(!x.revoked){const b=btn(t("revoke"),"ns-button--danger ns-button--compact");b.addEventListener("click",async()=>{await api("revoke_premium_code",{code_id:x.id});open("premium");});r.appendChild(b);}
        codes.section.appendChild(r);
      }
      h.appendChild(codes.root);

      if(d.scanning){
        let cancelled=false; let timer=null;
        const poll=async()=>{
          if(cancelled||disposed||active!=="premium")return;
          try{
            const next=await api("get_premium_settings");
            if(cancelled||disposed||active!=="premium")return;
            renderFolders(next);
            if(next.scanning)timer=globalThis.setTimeout(poll,350);
          }catch(_){ if(!cancelled&&active==="premium")timer=globalThis.setTimeout(poll,800); }
        };
        timer=globalThis.setTimeout(poll,350);
        sectionCleanup=()=>{cancelled=true;if(timer)globalThis.clearTimeout(timer);};
      }
    },
    cloud: async(h)=>{
      const d=await api("get_cloud_settings");
      sectionHeading(h,t("cloud"));
      const accounts=card(t("cloud_accounts"));
      if(!d.accounts.length)accounts.section.appendChild(el("div","ns-muted",t("no_cloud_accounts")));
      for(const a of d.accounts){
        const r=el("div","ns-settings-list-row"),m=el("div","ns-settings-list-row__main");
        m.append(el("div","ns-settings-list-row__title",`${String(a.provider_id).toUpperCase()} · ${a.label}`),el("div","ns-settings-list-row__meta",a.account_id));
        const b=btn(t("disconnect"),"ns-button--danger ns-button--compact"); b.addEventListener("click",async()=>{await api("disconnect_cloud",{provider_id:a.provider_id,account_id:a.account_id});open("cloud");});
        r.append(m,b); accounts.section.appendChild(r);
      }
      h.appendChild(accounts.root);

      const savedProfiles=(d.saved_profiles||[]).filter(profile=>!profile.connected);
      const saved=card(t("saved_connectors"),t("saved_connector_hint"));
      if(!savedProfiles.length)saved.section.appendChild(el("div","ns-muted",t("saved_connectors_empty")));
      for(const profile of savedProfiles){
        const row=el("div","ns-settings-list-row"),main=el("div","ns-settings-list-row__main");
        main.append(
          el("div","ns-settings-list-row__title",`${String(profile.provider_id||"").toUpperCase()} · ${profile.label||profile.account_id}`),
          el("div","ns-settings-list-row__meta",profile.account_id||"")
        );
        const reconnect=btn(t("reconnect"),"ns-button--primary ns-button--compact");
        reconnect.addEventListener("click",async()=>{
          reconnect.disabled=true;
          try{
            let password="";
            if(profile.requires_password){
              password=await passwordDialog({title:t("reconnect"),message:profile.label||profile.account_id,label:t("mega_password_prompt"),saveLabel:t("reconnect"),cancelLabel:t("cancel")});
              if(password===null)return;
            }
            await api("reconnect_cloud",{profile_id:profile.profile_id,password});
            await open("cloud");
          }catch(error){showToast("error",cloudFailureText(error));}
          finally{reconnect.disabled=false;}
        });
        const forget=btn(t("forget_connector"),"ns-button--danger ns-button--compact");
        forget.addEventListener("click",async()=>{
          const confirmed=await choiceDialog({title:t("forget_connector"),message:`${String(profile.provider_id||"").toUpperCase()} · ${profile.label||profile.account_id}`,actions:[{label:t("cancel"),value:"cancel"},{label:t("forget_connector"),value:"forget",kind:"danger"}]});
          if(confirmed!=="forget")return;
          await api("forget_cloud_profile",{profile_id:profile.profile_id});
          await open("cloud");
        });
        const rowActions=el("div","ns-settings-actions");rowActions.append(reconnect,forget);
        row.append(main,rowActions); saved.section.appendChild(row);
      }
      const storage=d.secure_profile_storage||{};
      saved.section.appendChild(el("div",storage.os_protected?"ns-settings-note":"ns-settings-note ns-settings-danger-note",storage.os_protected?t("secure_connector_storage"):t("secure_connector_storage_fallback")));
      h.appendChild(saved.root);

      const providers=card(t("connect")); const actions=el("div","ns-settings-stack");
      const drive=field(t("drive_client_id_prompt")); const driveSecret=field(t("drive_client_secret"),"","password"); const driveSecretHelp=el("div","ns-settings-note",t("drive_client_secret_help")); const db=field(t("dropbox_app_key_prompt"));
      const me=field(t("mega_email_prompt"),"","email"); const mp=field(t("mega_password_prompt"),"","password");
      const driveError=el("div","ns-settings-note ns-settings-danger-note"); driveError.hidden=true;
      const dbtn=btn(`${t("connect")} · ${t("google_drive")}`); dbtn.disabled=!d.providers.drive.available; dbtn.addEventListener("click",async()=>{
        driveError.hidden=true; driveError.textContent=""; dbtn.disabled=true;
        try{
          await api("connect_cloud",{provider:"drive",client_id:drive.input.value,client_secret:driveSecret.input.value});
          driveSecret.input.value="";
          await open("cloud");
        }catch(error){
          driveError.textContent=cloudFailureText(error); driveError.hidden=false;
        }finally{dbtn.disabled=!d.providers.drive.available;}
      });
      actions.append(drive.wrap,driveSecret.wrap,driveSecretHelp,dbtn,driveError); if(!d.providers.drive.available)actions.appendChild(el("div","ns-settings-note ns-settings-danger-note",t("requests_missing")));
      const dropboxRedirect=String(d.providers.dropbox.redirect_uri||"");
      const dbSetup=el("div","ns-settings-note");
      const dbSetupText=el("div","",`${t("dropbox_redirect_uri")}: ${dropboxRedirect}`);
      const dbSetupHelp=el("div","ns-muted",t("dropbox_redirect_help"));
      const dbSetupActions=el("div","ns-settings-actions");
      if(dropboxRedirect){const copyRedirect=btn(t("copy"),"ns-button--compact");copyRedirect.addEventListener("click",async()=>{if(await copyText(dropboxRedirect))showToast("success","copy");});dbSetupActions.appendChild(copyRedirect);}
      dbSetup.append(dbSetupText,dbSetupHelp,dbSetupActions);
      const dbError=el("div","ns-settings-note ns-settings-danger-note"); dbError.hidden=true;
      const xbtn=btn(`${t("connect")} · ${t("dropbox")}`); xbtn.disabled=!d.providers.dropbox.available; xbtn.addEventListener("click",async()=>{
        dbError.hidden=true; dbError.textContent=""; xbtn.disabled=true;
        try{
          await api("connect_cloud",{provider:"dropbox",app_key:db.input.value});
          await open("cloud");
        }catch(error){
          dbError.textContent=cloudFailureText(error); dbError.hidden=false;
        }finally{xbtn.disabled=!d.providers.dropbox.available;}
      });
      actions.append(db.wrap,dbSetup,xbtn,dbError); if(!d.providers.dropbox.available)actions.appendChild(el("div","ns-settings-note ns-settings-danger-note",t("requests_missing")));
      const mbtn=btn(`${t("connect")} · ${t("mega")}`); mbtn.disabled=!d.providers.mega.available; mbtn.addEventListener("click",async()=>{await api("connect_cloud",{provider:"mega",email:me.input.value,password:mp.input.value});mp.input.value="";open("cloud");});
      actions.append(me.wrap,mp.wrap,mbtn); if(!d.providers.mega.available)actions.appendChild(el("div","ns-settings-note ns-settings-danger-note",d.providers.mega.message));
      actions.appendChild(el("div","ns-settings-note",t("mega_bridge_notice")));
      providers.section.appendChild(actions); h.appendChild(providers.root);
    },
    tunnel: async(h)=>{
      const [d,setup,server,permissions]=await Promise.all([api("get_tunnel_status"),api("get_cloudflare_status"),api("get_server_snapshot"),api("get_permissions_settings")]);
      sectionHeading(h,t("tunnel"));
      const ssh=card(t("public_sharing"));
      const sshUrl=d.ssh.url||""; kv(ssh.section,t("public_url"),sshUrl||t("offline"));
      const sshActions=el("div","ns-settings-actions");
      if(sshUrl){const copy=btn(t("copy"),"ns-button--compact");copy.addEventListener("click",async()=>{if(await copyText(sshUrl))showToast("success","copy");});sshActions.appendChild(copy);}
      const b=btn(d.ssh.active?t("stop_tunnel"):t("start_tunnel"),d.ssh.active?"ns-button--danger":"ns-button--primary"); b.disabled=!d.ssh.active&&!server.server_running;
      b.addEventListener("click",async()=>{await api(d.ssh.active?"stop_tunnel":"start_tunnel",d.ssh.active?{}:{rotate_keys:true});open("tunnel");}); sshActions.appendChild(b); ssh.section.appendChild(sshActions); h.appendChild(ssh.root);

      const runtime=d.cloudflare||{}; const cc=card(t("cf_domain"));
      const hostf=field(t("cf_hostname_prompt"),runtime.hostname||""); cc.section.appendChild(hostf.wrap);
      kv(cc.section,t("available"),setup.installed?t("available"):t("unavailable"));
      kv(cc.section,t("cf_status_ready"),(setup.tunnel_created&&setup.config_written)?t("cf_status_ready"):t("cf_status_not_ready"));
      if(!setup.installed)cc.section.appendChild(el("div","ns-settings-note ns-settings-danger-note",t("cf_not_installed")));
      const ar=el("div","ns-settings-actions");
      const login=btn(t("cf_login")); login.disabled=!setup.installed; login.addEventListener("click",async()=>{await api("cloudflare_login");open("tunnel");});
      const setupBtn=btn(t("cf_setup")); setupBtn.disabled=!setup.installed; setupBtn.addEventListener("click",async()=>{await api("cloudflare_setup",{hostname:hostf.input.value});open("tunnel");});
      const start=btn(runtime.active?t("cf_stop"):t("cf_start"),runtime.active?"ns-button--danger":"ns-button--primary"); start.disabled=!setup.installed||(!runtime.active&&!server.server_running);
      start.addEventListener("click",async()=>{
        if(runtime.active){await api("stop_cloudflare_tunnel");open("tunnel");return;}
        let admin=sessionSecrets.admin;
        if(!admin){admin=await passwordDialog({title:t("admin_key"),message:t("security_title"),label:t("admin_key"),saveLabel:t("cf_start"),cancelLabel:t("cancel")});}
        if(!admin)return;
        await api("start_cloudflare_tunnel",{hostname:hostf.input.value,admin_password:admin}); sessionSecrets.admin=admin; open("tunnel");
      });
      ar.append(login,setupBtn,start); cc.section.appendChild(ar);
      if(runtime.url){kv(cc.section,t("public_url"),runtime.url);const copy=btn(t("copy"),"ns-button--compact");copy.addEventListener("click",async()=>{if(await copyText(runtime.url))showToast("success","copy");});cc.section.appendChild(copy);}
      h.appendChild(cc.root);
    },
    manage_folders: async(h)=>{
      const [d,inbox]=await Promise.all([api("get_folder_tree"),api("get_inbox_management")]);
      sectionHeading(h,t("manage_folders"),t("manage_folders_description"));

      const inboxCard=card(t("inbox_management_title"),t("inbox_management_description"));
      const recent=inbox.recent_files||[];
      inboxCard.section.appendChild(el("div","ns-settings-subheading",t("inbox_recent_files")));
      if(!recent.length)inboxCard.section.appendChild(el("div","ns-muted",t("inbox_empty")));
      for(const item of recent){
        const row=el("div","ns-settings-list-row"); const main=el("div","ns-settings-list-row__main");
        main.append(el("div","ns-settings-list-row__title",item.name||"—"),el("div","ns-settings-list-row__meta",`${formatBytes(item.size)} · ${new Date(Number(item.modified_ns||0)/1e6).toLocaleString()}`));
        row.appendChild(main); inboxCard.section.appendChild(row);
      }
      const openInbox=btn(t("open_inbox_location"),"ns-button--primary");
      openInbox.addEventListener("click",async()=>{try{await api("open_inbox_folder");}catch(error){showToast("error","service_unavailable_safe",{service:t("inbox_management_title"),support_code:error?.code||"INBOX_OPEN"});}});
      inboxCard.section.appendChild(openInbox); h.appendChild(inboxCard.root);

      const historyCard=card(t("transfer_history_title"),t("transfer_history_description"));
      const historyHost=el("div","ns-settings-history-list"); const history=Array.isArray(inbox.history)?inbox.history:[]; let visibleCount=10;
      const actions=el("div","ns-settings-actions");
      const exportButton=btn(t("export_transfer_report"),"ns-button--primary");
      exportButton.addEventListener("click",async()=>{const stamp=new Date().toISOString().replaceAll(":","").replaceAll("-","").slice(0,15);const picker=await chooseSaveFile(`netshare-transfer-report-${stamp}.xlsx`);if(!picker?.ok||!picker.data?.path)return;const response=await callDesktopApi("export_transfer_report",{target_path:picker.data.path});if(response?.ok)showToast("success","transfer_report_exported");else showToast("error","service_unavailable_safe",{service:t("transfer_history_title"),support_code:response?.error?.code||"TRANSFER_EXPORT"});});
      const more=btn(t("load_more"),"ns-button--compact");
      const renderHistory=()=>{historyHost.replaceChildren();const visible=history.slice(0,visibleCount);if(!visible.length)historyHost.appendChild(el("div","ns-muted",t("transfer_history_empty")));for(const item of visible){const row=el("div","ns-settings-list-row");const main=el("div","ns-settings-list-row__main");const destination=item.destination_type==="shared"?t("transfer_destination_shared",{slot:item.destination_slot||"—",path:item.destination_path||"/"}):t("transfer_destination_inbox");main.append(el("div","ns-settings-list-row__title",item.name||String(item.path||"").split("/").pop()||"—"),el("div","ns-settings-list-row__meta",`${formatTimestamp(item.timestamp)} · ${formatBytes(item.size)} · ${item.source||"—"} · ${destination}`));row.appendChild(main);historyHost.appendChild(row);}more.hidden=visibleCount>=history.length;};
      more.addEventListener("click",()=>{visibleCount+=10;renderHistory();});
      actions.append(exportButton,more); historyCard.section.append(historyHost,actions); renderHistory(); h.appendChild(historyCard.root);

      const c=card(t("shared_folders")); const expanded=new Set();
      async function renderRows(){
        for(const n of [...c.section.querySelectorAll(".ns-settings-tree-row")])n.remove();
        const append=async(item,depth)=>{const r=el("div","ns-settings-tree-row");r.style.setProperty("--tree-depth",String(depth));r.appendChild(el("div","ns-settings-tree-indent"));const main=el("div","ns-settings-list-row__main");main.append(el("div","ns-settings-list-row__title",item.name),el("div","ns-settings-list-row__meta",item.path));r.appendChild(main);const a=el("div","ns-settings-actions");if(item.has_children){const e=btn(expanded.has(item.path)?"▾":"▸","ns-button--compact");e.addEventListener("click",async()=>{if(expanded.has(item.path))expanded.delete(item.path);else expanded.add(item.path);renderRows();});a.appendChild(e);}if(depth>0||item.directly_hidden){const b=btn(item.hidden?t("show_folder"):t("hide_folder"),item.hidden?"ns-button--compact":"ns-button--danger ns-button--compact");b.disabled=item.hidden&&!item.directly_hidden;b.addEventListener("click",async()=>{await api("set_folder_visibility",{path:item.path,hidden:!item.hidden});open("manage_folders");});a.appendChild(b);}r.appendChild(a);c.section.appendChild(r);if(expanded.has(item.path)){const kids=await api("get_folder_children",{path:item.path});for(const x of kids)await append(x,depth+1);}};
        for(const x of d.items)await append(x,0);
      }
      await renderRows();
      if(d.hidden.length){const hc=card(t("hidden_folders"));for(const x of d.hidden){const r=el("div","ns-settings-list-row");r.appendChild(el("div","ns-settings-list-row__title",x.path));const b=btn(t("show_folder"),"ns-button--compact");b.addEventListener("click",async()=>{await api("set_folder_visibility",{path:x.path,hidden:false});open("manage_folders");});r.appendChild(b);hc.section.appendChild(r);}h.appendChild(hc.root);}
      h.appendChild(c.root);
    },
    guest_profiles: async(h)=>{
      const d=await api("get_guest_profiles"); sectionHeading(h,t("guest_profiles"),t("guest_profiles_description"));const c=card(t("guest_profile_create"));const name=field(t("guest_profile_name"));const folder=field(t("guest_profile_folder"));folder.input.readOnly=true;const br=btn(t("browse"));br.addEventListener("click",async()=>{const r=await chooseFolder();if(r?.ok&&r.data.path)folder.input.value=r.data.path;});const row=el("div","ns-settings-inline-form");placeFieldControl(folder,row,br);const create=btn(t("guest_profile_create"),"ns-button--primary");create.addEventListener("click",async()=>{const x=await api("create_guest_profile",{name:name.input.value,folder_path:folder.input.value});if(x?.code){try{await navigator.clipboard.writeText(x.code);}catch(_){}showToast("success","guest_profile_created");}open("guest_profiles");});c.section.append(name.wrap,folder.wrap,create);h.appendChild(c.root);const list=card(t("guest_profiles"));for(const p of d.profiles){const r=el("div","ns-settings-list-row");const m=el("div","ns-settings-list-row__main");m.append(el("div","ns-settings-list-row__title",p.name),el("div","ns-settings-list-row__meta",p.allowed_paths.map(x=>`${x.root_slot}:${x.path}`).join(", ")));const b=btn(t("revoke"),"ns-button--danger ns-button--compact");b.addEventListener("click",async()=>{await api("revoke_guest_profile",{profile_id:p.id});open("guest_profiles");});r.append(m,b);list.section.appendChild(r);}h.appendChild(list.root);
    },
    co_servers: async(h)=>{
      const [d,server]=await Promise.all([api("get_cluster_settings"),api("get_server_snapshot")]);
      const effectiveRole=String(d.effective_role||d.role||"standalone");
      // Compatibility marker for the Round7 static contract: if(d.role==="slave") / if(d.role==="master")
      sectionHeading(h,t("co_servers"));
      const c=card(t("co_servers"));
      c.section.appendChild(badge(d.security.available?t("cluster_security_ready"):t("cluster_security_unavailable"),d.security.available?"success":"danger"));
      const reasonKey={cryptography_missing:"cluster_crypto_missing",zeroconf_missing:"cluster_zeroconf_missing",secure_storage_unavailable:"cluster_storage_unavailable"}[d.security.reason_code];
      c.section.appendChild(el("div","ns-settings-note",d.security.available?t("cluster_7a_ready_detail"):t(reasonKey||"cluster_storage_unavailable")));

      const role=selectField(t("cluster_role"),[["standalone",t("cluster_role_standalone")],["auto","AUTO"],["master",t("cluster_role_master")],["slave",t("cluster_role_slave")]],d.role);
      role.select.disabled=server.server_running||!d.security.available;
      role.select.addEventListener("change",async()=>{
        const next=role.select.value; role.select.disabled=true;
        try{
          const response=await callDesktopApi("update_cluster_role",{role:next});
          if(!response?.ok){showToast("error","service_unavailable_safe",{service:t("co_servers"),support_code:response?.error?.code||"CLUSTER_ROLE"});}
          await open("co_servers");
        }catch(error){
          showToast("error","service_unavailable_safe",{service:t("co_servers"),support_code:String(error?.message||"CLUSTER_ROLE").slice(0,72)});
          await open("co_servers");
        }
      });
      c.section.append(role.wrap,el("div","ns-muted",t("cluster_role_restart")));
      if(d.role==="auto"&&d.running&&["master","slave"].includes(effectiveRole)){
        c.section.appendChild(el("div","ns-settings-note",t("cluster_auto_effective",{role:effectiveRole.toUpperCase()})));
      }
      if(d.pairing_error)c.section.appendChild(el("div","ns-settings-note ns-settings-danger-note",d.pairing_error));

      const runClusterAction=async(buttonNode,method,params={})=>{
        if(buttonNode)buttonNode.disabled=true;
        try{
          const response=await callDesktopApi(method,params);
          if(!response?.ok){
            showToast("error","service_unavailable_safe",{service:t("co_servers"),support_code:response?.error?.code||"CLUSTER"});
            return false;
          }
          await open("co_servers");
          return true;
        }catch(error){
          const code=String(error?.message||"CLUSTER").slice(0,72);
          showToast("error","service_unavailable_safe",{service:t("co_servers"),support_code:code});
          return false;
        }finally{
          if(buttonNode?.isConnected)buttonNode.disabled=false;
        }
      };

      const actions=el("div","ns-cluster-actions");
      const refresh=btn(t("retry"));
      refresh.addEventListener("click",()=>open("co_servers"));
      actions.appendChild(refresh);

      if(effectiveRole==="slave"){
        const openWindow=btn(t("cluster_open_window"),"ns-button--primary");
        openWindow.disabled=!d.running||!d.security.available||d.slave_paired||d.pairing_active;
        openWindow.addEventListener("click",()=>runClusterAction(openWindow,"start_cluster_pairing"));
        actions.appendChild(openWindow);
        if(!d.running)c.section.appendChild(el("div","ns-muted",t("start_server_first")));

        if(d.slave_paired){
          const unlink=btn(t("cluster_unlink_local"),"ns-button--danger");
          unlink.addEventListener("click",async()=>{
            const q=await choiceDialog({title:t("co_servers"),message:t("cluster_unlink_local_confirm"),actions:[{label:t("cancel"),value:"cancel"},{label:t("cluster_unlink_local"),value:"unlink",kind:"danger"}]});
            if(q==="unlink")await runClusterAction(unlink,"unpair_cluster_local");
          });
          actions.appendChild(unlink);
        }
      }

      if(effectiveRole==="master"){
        c.section.appendChild(el("div","ns-muted",t("cluster_capacity",{used:d.slave_count??d.nodes.length,maximum:d.max_slaves??5})));
        const atCapacity=Number(d.available_slots??0)<=0;
        if(atCapacity)c.section.appendChild(el("div","ns-settings-note ns-settings-danger-note",t("cluster_limit_reached",{maximum:d.max_slaves??5})));
        if(d.running&&d.pairing_targets.length){
          for(const target of d.pairing_targets){
            const link=btn(`${t("cluster_link")} · ${target.name}`,"ns-button--primary");
            link.disabled=Boolean(d.pairing_active)||atCapacity;
            link.addEventListener("click",()=>runClusterAction(link,"start_cluster_pairing",{node_id:target.node_id,window_id:target.window_id}));
            actions.appendChild(link);
          }
          if(d.pairing_active)c.section.appendChild(el("div","ns-muted",t("cluster_pairing_busy")));
        }else{
          const waiting=btn(t("cluster_link"),"ns-button--primary");
          waiting.disabled=true;
          actions.appendChild(waiting);
          c.section.appendChild(el("div","ns-muted",d.running?t("cluster_no_slave"):(t("start_server_first"))));
        }
      }
      if(d.role!=="standalone"||effectiveRole!=="standalone")c.section.appendChild(actions);

      if(d.sas){
        const sasCard=el("div","ns-cluster-sas");
        sasCard.append(el("div","ns-settings-code",d.sas),el("div","ns-settings-note",t("cluster_compare",{sas:d.sas})));
        if(!d.pairing_decided){
          const confirm=el("div","ns-cluster-actions");
          const yes=btn(t("on"),"ns-button--primary"),no=btn(t("off"),"ns-button--danger");
          yes.addEventListener("click",()=>runClusterAction(yes,"confirm_cluster_pairing",{matches:true}));
          no.addEventListener("click",()=>runClusterAction(no,"confirm_cluster_pairing",{matches:false}));
          confirm.append(yes,no);sasCard.appendChild(confirm);
        }else{
          sasCard.appendChild(el("div","ns-muted",t("loading")));
        }
        c.section.appendChild(sasCard);
      }else if(d.pairing_active&&!d.pairing_error){
        c.section.appendChild(el("div","ns-settings-note",t("loading")));
      }

      if(effectiveRole==="master"&&d.nodes.length){
        const list=el("div","ns-cluster-node-list");
        for(const n of d.nodes){
          const r=el("div","ns-settings-list-row"),m=el("div","ns-settings-list-row__main");
          m.append(el("div","ns-settings-list-row__title",n.name),el("div","ns-settings-list-row__meta",n.online?t("online"):t("offline")));
          const unlink=btn(t("revoke"),"ns-button--danger ns-button--compact");
          unlink.disabled=!d.running;
          unlink.addEventListener("click",async()=>{
            const q=await choiceDialog({title:t("co_servers"),message:t("cluster_unlink_confirm",{name:n.name}),actions:[{label:t("cancel"),value:"cancel"},{label:t("revoke"),value:"unlink",kind:"danger"}]});
            if(q==="unlink")await runClusterAction(unlink,"unlink_cluster_node",{node_id:n.node_id});
          });
          r.append(m,unlink);list.appendChild(r);
        }
        c.section.appendChild(list);
      }

      h.appendChild(c.root);

      // Keep the Co-Servers page live for discovery, multi-Slave pairing and
      // post-enrollment state.  We poll the bounded snapshot and only rebuild
      // the section when something changed, avoiding the old leave/re-enter UI.
      if(d.running&&effectiveRole!=="standalone"){
        let stopped=false; let timer=null;
        const signature=(value)=>JSON.stringify({
          effective_role:value.effective_role, pairing_targets:value.pairing_targets,
          nearby_nodes:value.nearby_nodes, nodes:value.nodes, sas:value.sas,
          pairing_error:value.pairing_error, pairing_active:value.pairing_active,
          pairing_decided:value.pairing_decided, slave_paired:value.slave_paired,
          slave_count:value.slave_count, available_slots:value.available_slots,
          active_pairing_target:value.active_pairing_target,
        });
        const initial=signature(d);
        const tick=()=>{
          timer=globalThis.setTimeout(async()=>{
            if(stopped||disposed||active!=="co_servers")return;
            try{
              const response=await callDesktopApi("get_cluster_settings");
              if(response?.ok&&signature(response.data)!==initial){await open("co_servers");return;}
            }catch(_){}
            if(!stopped&&!disposed&&active==="co_servers")tick();
          },700);
        };
        tick();
        sectionCleanup=()=>{stopped=true;if(timer)globalThis.clearTimeout(timer);};
      }
    },
    permissions: async(h)=>{
      const [d,s]=await Promise.all([api("get_permissions_settings"),api("get_settings_snapshot")]);
      sectionHeading(h,t("permissions"));
      const c=card(t("config"));
      const gpu=d.hardware_profile.nvidia_detected&&d.hardware_profile.nvidia_name?` · ${d.hardware_profile.nvidia_name}`:"";
      kv(c.section,t("hardware_profile",{profile:String(d.hardware_profile.name).toUpperCase(),workers:d.hardware_profile.workers,gpu}),`${d.hardware_profile.name} · ${d.hardware_profile.workers}${gpu}`);
      const rescan=btn(t("rescan_media"));rescan.addEventListener("click",async()=>{await api("rescan_media");showToast("success","rescan_media");});c.section.appendChild(rescan);
      const grid=el("div","ns-settings-grid"),port=field(t("port"),d.port_text,"number"),name=field(t("name"),d.server_name);port.input.min=1;port.input.max=65532;grid.append(port.wrap,name.wrap);c.section.appendChild(grid);
      const save=btn(t("save"),"ns-button--primary");save.addEventListener("click",async()=>{await api("update_permissions_settings",{port:Number(port.input.value),server_name:name.input.value,allow_upload:d.allow_upload,allow_edit:d.allow_edit});showToast("success","save");open("permissions");});c.section.appendChild(save);
      const awakeState=d.keep_awake?(d.keep_awake_active?`${t("keep_awake_status_active")} · ${d.keep_awake_backend||""}`:(d.server_running?`${t("keep_awake_status_unavailable")}${d.keep_awake_error?` · ${d.keep_awake_error}`:""}`:t("keep_awake_status_waiting"))):t("keep_awake_description");
      const tls=d.transport_tls||{enabled:false,read_only:false,environment_override:null};
      const tlsDescription=t("tls_encrypt_local_connections_description");
      const tlsRow=switchRow(t("tls_encrypt_local_connections"),Boolean(tls.enabled),async v=>{
        await api("set_transport_tls",{enabled:v});
        showToast("success","save");
        await open("permissions");
        return true;
      },tlsDescription);
      const tlsSwitch=tlsRow.querySelector(".ns-switch");
      if(tls.read_only&&tlsSwitch){tlsSwitch.disabled=true;}
      if(tls.read_only){tlsRow.appendChild(el("div","ns-settings-note",t("tls_controlled_by_environment",{variable:tls.environment_variable||"NETSHARE_TLS_ENABLED"})));}
      c.section.append(
        switchRow(t("allow_receiving_files"),d.allow_upload,async v=>{await api("update_permissions_settings",{allow_upload:v});return true;}),
        switchRow(t("allow_document_edits"),d.allow_edit,async v=>{await api("update_permissions_settings",{allow_edit:v});return true;}),
        tlsRow,
        switchRow(t("keep_awake_active_label"),d.keep_awake,async v=>{await api("set_keep_awake",{enabled:v});await open("permissions");return true;},awakeState),
      );
      if(d.keep_awake&&d.server_running&&!d.keep_awake_active)c.section.appendChild(el("div","ns-settings-note ns-settings-danger-note",d.keep_awake_error||t("keep_awake_status_unavailable")));
      h.appendChild(c.root);

      const sec=card(t("local_pw"));
      sec.section.appendChild(el("div","ns-muted",t("lan_only")));
      const reminder=field(t("password_reminder_every"),s.password_reminder_days,"number");reminder.input.min=1;reminder.input.max=3650;
      const reminderRow=el("div","ns-settings-inline-form");placeFieldControl(reminder,reminderRow,el("span","ns-settings-value",t("days")));sec.section.appendChild(reminder.wrap);
      const reminderSave=btn(t("save"));reminderSave.addEventListener("click",async()=>{await api("update_password_reminder",{reminder_days:Number(reminder.input.value)});showToast("success","save");open("permissions");});sec.section.appendChild(reminderSave);
      const pw=btn(t("change_password"));pw.addEventListener("click",async()=>{
        pw.disabled=true;
        try{
          const secret=await api("get_local_password_secret");
          const saved=await editablePasswordDialog({
            title:t("local_pw"),message:t("lan_only"),currentPassword:secret.password||"",passwordLabel:t("new_password"),confirmLabel:t("password_confirm"),showLabel:t("show"),hideLabel:t("hide"),saveLabel:t("save"),cancelLabel:t("cancel"),tooShortMessage:t("password_too_short"),mismatchMessage:t("password_mismatch"),saveErrorMessage:t("password_save_failed"),savedMessage:t("password_saved_active"),
            onSave:async value=>{
              const response=await callDesktopApi("update_local_password",{password:value,reminder_days:Number(reminder.input.value)});
              if(!response?.ok)return {ok:false,error:String(response?.error?.code||t("server_start_failed"))};
              return {ok:true,message:t("password_saved_active")};
            },
          });
          if(saved){showToast("success","password_saved_title");await open("permissions");}
        }finally{pw.disabled=false;}
      });sec.section.appendChild(pw);h.appendChild(sec.root);

    },
    history: async(h)=>{
      const d=await api("get_history_settings");sectionHeading(h,t("share_history"));const c=card(t("share_history"));if(!d.items.length)c.section.appendChild(el("div","ns-muted",t("no_share_history")));for(const x of d.items){const date=x.last_shared_at?new Date(x.last_shared_at*1000).toLocaleString():"—";const r=el("div","ns-settings-list-row");const m=el("div","ns-settings-list-row__main");m.append(el("div","ns-settings-list-row__title",x.name),el("div","ns-settings-list-row__meta",t("share_history_detail",{count:x.share_count,date})+` · ${x.path}`));r.appendChild(m);c.section.appendChild(r);}if(d.items.length){const clear=btn(t("clear_history"),"ns-button--danger");clear.addEventListener("click",async()=>{const q=await choiceDialog({title:t("clear_history"),message:t("clear_history_confirm"),actions:[{label:t("cancel"),value:"cancel"},{label:t("clear_history"),value:"clear",kind:"danger"}]});if(q==="clear"){await api("clear_folder_history");open("history");}});c.section.appendChild(clear);}h.appendChild(c.root);
    },
    about: async(h)=>{
      const [updateState,about]=await Promise.all([api("get_updates_settings"),api("get_about_settings")]);
      sectionHeading(h,t("about"),t("update_mechanism_description"));
      const info=card(t("netshare_player"));
      kv(info.section,t("current_version"),`V${about.version}`);
      kv(info.section,t("legal_company"),about.company);
      info.section.appendChild(el("div","ns-settings-note ns-settings-danger-note",t("footer_warning")));
      const legal=el("div","ns-inline-actions ns-settings-legal-actions");
      const terms=btn(t("terms_of_use"));terms.addEventListener("click",()=>openExternalUrl(about.terms_url));
      const privacy=btn(t("privacy_policy"));privacy.addEventListener("click",()=>openExternalUrl(about.privacy_url));
      legal.append(terms,privacy);info.section.appendChild(legal);h.appendChild(info.root);

      const updates=card(t("updates"));
      const statusHost=el("div","ns-settings-update-status");updates.section.appendChild(statusHost);
      const actions=el("div","ns-inline-actions");const check=btn(t("check_for_updates"),"ns-button--primary");check.disabled=!updateState.check_available;actions.appendChild(check);updates.section.appendChild(actions);
      const renderStatus=d=>{statusHost.replaceChildren();actions.querySelectorAll("[data-update-download]").forEach(node=>node.remove());if(!d||d.status==="idle"){statusHost.appendChild(el("div","ns-settings-note",t("update_check_ready")));return;}if(d.status==="up_to_date"){statusHost.appendChild(el("div","ns-settings-note",t("update_up_to_date",{version:d.latest_version||d.current_version})));return;}if(d.status==="check_failed"){statusHost.appendChild(el("div","ns-settings-note ns-settings-danger-note",t("update_check_failed")));return;}if(d.status==="update_available"){statusHost.appendChild(el("div","ns-settings-note",t("update_available_message",{version:d.latest_version||"—"})));if(d.asset_name)kv(statusHost,t("update_package"),d.asset_name);const openDownload=btn(t("open_download"));openDownload.dataset.updateDownload="true";openDownload.addEventListener("click",()=>openExternalUrl(d.asset_url||d.release_url));actions.appendChild(openDownload);}};
      renderStatus(updateState);
      check.addEventListener("click",async()=>{check.disabled=true;check.textContent=t("checking_updates");try{renderStatus(await api("check_for_updates"));}catch(_){renderStatus({status:"check_failed"});}finally{check.disabled=false;check.textContent=t("check_for_updates");}});
      h.appendChild(updates.root);

      const reports=card(t("server_report_title"),t("server_report_description"));
      const exportServer=btn(t("export_server_report"),"ns-button--primary");
      exportServer.addEventListener("click",async()=>{const stamp=new Date().toISOString().replaceAll(":","").replaceAll("-","").slice(0,15);const picker=await chooseSaveFile(`netshare-server-report-${stamp}.xlsx`);if(!picker?.ok||!picker.data?.path)return;const response=await callDesktopApi("export_server_report",{target_path:picker.data.path});if(response?.ok)showToast("success","server_report_exported");else showToast("error","service_unavailable_safe",{service:t("server_report_title"),support_code:response?.error?.code||"SERVER_REPORT"});});
      reports.section.appendChild(exportServer); h.appendChild(reports.root);

      const maintenance=card(t("about_clear_data_title"),t("about_clear_data_description"));
      maintenance.root.classList.add("ns-settings-danger-zone");
      const stateHost=el("div","ns-settings-maintenance-status");
      maintenance.section.appendChild(stateHost);
      const activity=about.maintenance?.activity||{};
      const activeCount=Object.values(activity).reduce((sum,value)=>sum+Math.max(0,Number(value)||0),0);
      if(about.maintenance?.busy){
        stateHost.appendChild(el("div","ns-settings-note ns-settings-danger-note",`${t("about_clear_data_busy")} (${activeCount})`));
      }else if(about.maintenance?.server_running){
        stateHost.appendChild(el("div","ns-settings-note",t("about_reindexing")));
      }
      const clearData=btn(t("about_clear_data_button"),"ns-button--danger");
      clearData.disabled=Boolean(about.maintenance?.busy);
      clearData.addEventListener("click",async()=>{
        const confirmed=await choiceDialog({title:t("about_clear_data_confirm_title"),message:t("about_clear_data_confirm"),actions:[{label:t("cancel"),value:"cancel"},{label:t("about_clear_data_button"),value:"clear",kind:"danger"}]});
        if(confirmed!=="clear")return;
        clearData.disabled=true;stateHost.replaceChildren(el("div","ns-settings-note",t("loading")));
        try{
          const response=await callDesktopApi("clear_cache_and_data",{confirmed:true});
          if(!response?.ok){
            const code=String(response?.error?.code||"");
            const details=response?.error?.details?.activity||{};
            const total=Object.values(details).reduce((sum,value)=>sum+Math.max(0,Number(value)||0),0);
            stateHost.replaceChildren(el("div","ns-settings-note ns-settings-danger-note",code==="settings.maintenance.busy"?`${t("about_clear_data_busy")} (${total})`:t("about_clear_data_error")));
            return;
          }
          const copy=response.data?.reindexing?`${t("about_clear_data_success")} ${t("about_reindexing")}`:t("about_clear_data_success");
          stateHost.replaceChildren(el("div","ns-settings-note",copy));
          showToast("success","save");
          globalThis.setTimeout(()=>{if(!disposed&&active==="about")open("about");},900);
        }catch(_){
          stateHost.replaceChildren(el("div","ns-settings-note ns-settings-danger-note",t("about_clear_data_error")));
        }finally{clearData.disabled=false;}
      });
      maintenance.section.appendChild(clearData);
      h.appendChild(maintenance.root);
    },
  };

  const eventHandler=(event)=>{const name=event?.detail?.name;if(!disposed&&name==="settings.changed")open(active);};
  const settingsSectionHandler=(event)=>{let section=String(event?.detail?.section||"");if(section==="updates")section="about";if(!disposed&&renderers[section])open(section);};
  globalThis.addEventListener(BACKEND_EVENT,eventHandler);
  globalThis.addEventListener("netshare:settings.open-section",settingsSectionHandler);
  api("get_settings_snapshot").then(snapshot=>{
    if(disposed)return;
    showAdvanced=Boolean(snapshot.show_advanced_settings);
    if(!showAdvanced&&ADVANCED_SECTIONS.has(active))active="permissions";
    renderNav();
    open(active);
  }).catch(()=>{ renderNav(); open(active); });
  return()=>{disposed=true;sectionCleanup();globalThis.removeEventListener(BACKEND_EVENT,eventHandler);globalThis.removeEventListener("netshare:settings.open-section",settingsSectionHandler);};
}
