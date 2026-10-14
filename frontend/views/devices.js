import { BACKEND_EVENT, callDesktopApi } from "../shell/js/bridge.js";
import { t } from "../shell/js/i18n.js";
import { showToast } from "../shell/js/toast-manager.js";

function el(tag, className = "", text = "") {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}
function button(label, cls = "") {
  const node = el("button", `ns-button ${cls}`.trim(), label);
  node.type = "button";
  return node;
}
function card(title, description = "") {
  const root = document.createElement("ns-card");
  const section = el("div", "ns-card__section");
  section.appendChild(el("h2", "ns-card__title", title));
  if (description) section.appendChild(el("p", "ns-card__description", description));
  root.appendChild(section);
  return { root, section };
}
function formatDate(seconds) {
  if (seconds == null) return "—";
  try { return new Date(Number(seconds) * 1000).toLocaleString(); } catch (_) { return "—"; }
}
async function copyText(value) {
  if (!value) return false;
  try { await navigator.clipboard.writeText(String(value)); return true; }
  catch (_) {
    try {
      const input = document.createElement("textarea"); input.value=String(value); input.style.position="fixed"; input.style.opacity="0";
      document.body.appendChild(input); input.select(); const ok=document.execCommand("copy"); input.remove(); return Boolean(ok);
    } catch (_) { return false; }
  }
}

export function mountDevices({ host, headerTitle }) {
  let disposed = false;
  let pairing = null;
  let devices = [];
  let ticker = null;
  let secretVisible = false;
  let pairingRefreshPending = false;

  headerTitle.textContent = t("devices");
  host.replaceChildren();
  host.appendChild(document.createElement("ns-loading-state"));

  async function load() {
    try {
      const [pairingResponse, devicesResponse] = await Promise.all([
        callDesktopApi("get_pairing_snapshot"),
        callDesktopApi("list_trusted_devices"),
      ]);
      if (!pairingResponse?.ok) throw new Error(pairingResponse?.error?.code || "pairing snapshot failed");
      if (!devicesResponse?.ok) throw new Error(devicesResponse?.error?.code || "devices failed");
      pairing = pairingResponse.data;
      devices = Array.isArray(devicesResponse.data) ? devicesResponse.data : [];
      if (!disposed) render();
    } catch (_) { if (!disposed) renderError(); }
  }

  function renderError() {
    clearTicker(); host.replaceChildren();
    const state=document.createElement("ns-error-state");
    state.setAttribute("title", t("devices"));
    state.setAttribute("message", t("service_unavailable_safe", {service:t("trusted_devices"), support_code:"DEVICES"}));
    const retry=button(t("retry"),"ns-button--primary"); retry.dataset.stateAction="true"; retry.addEventListener("click",load); state.appendChild(retry); host.appendChild(state);
  }

  function clearTicker(){ if(ticker){ globalThis.clearInterval(ticker); ticker=null; } }
  function secondsLeft(){ return Math.max(0, Math.ceil(Number(pairing?.expires_at || 0) - Date.now()/1000)); }
  function formatCountdown(value){ const v=Math.max(0,value|0); return `${Math.floor(v/60)}:${String(v%60).padStart(2,"0")}`; }
  function shortDeviceId(value){ const text=String(value||""); return text.length>28?`${text.slice(0,12)}…${text.slice(-8)}`:text; }
  function updateTimerNode(node, remain){
    if(!node)return;
    const ttl=Math.max(1,Number(pairing?.ttl_seconds||600));
    const progress=Math.max(0,Math.min(1,Number(remain||0)/ttl));
    const circumference=2*Math.PI*34;
    const ring=node.querySelector("[data-pairing-timer-progress]");
    if(ring){
      ring.style.strokeDasharray=`${circumference.toFixed(3)}`;
      ring.style.strokeDashoffset=`${(circumference*(1-progress)).toFixed(3)}`;
    }
    const ratio=ttl?Number(remain||0)/ttl:0;
    node.dataset.tone=ratio>0.50?"green":ratio>0.25?"yellow":ratio>0.10?"orange":"red";
    const label=node.querySelector("[data-pairing-timer-label]");
    if(label)label.textContent=remain?formatCountdown(remain):"";
    node.classList.toggle("is-inactive",!remain);
  }

  async function startPairing() {
    const response=await callDesktopApi("start_pairing");
    if(!response?.ok){ showToast("error","service_unavailable_safe",{service:t("local_pairing"),support_code:response?.error?.code||"PAIR"}); return; }
    pairing=response.data; showToast("success","write_otp_generated"); render();
  }
  async function revoke(deviceId) {
    const response=await callDesktopApi("revoke_device",{device_id:deviceId});
    if(!response?.ok){ showToast("error","service_unavailable_safe",{service:t("trusted_devices"),support_code:response?.error?.code||"REVOKE"}); return; }
    showToast("success","pair_revoked_log",{device:deviceId}); await load();
  }
  async function showQr() {
    const response=await callDesktopApi("get_pairing_qr");
    if(!response?.ok || !response.data?.available || !response.data?.data_url){ showToast("warning","qr_install"); return; }
    const dialog=document.createElement("ns-dialog");
    const header=el("div","ns-dialog__header ns-dialog__header--centered");
    const title=el("h2","ns-dialog__title",t("qr_code_title"));
    const close=el("button","icon-btn ns-dialog__close"); close.type="button"; close.setAttribute("aria-label",t("cancel")); close.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M18 6 6 18M6 6l12 12"/></svg>'; close.addEventListener("click",()=>dialog.close("close"));
    header.append(title,close);
    const body=el("div","ns-dialog__body ns-dialog__body--qr");
    const image=el("img","ns-qr-image"); image.src=response.data.data_url; image.alt=t("authenticator_setup"); body.appendChild(image);
    dialog.append(header,body); document.getElementById("dialog-host")?.appendChild(dialog); dialog.addEventListener("close",()=>dialog.remove(),{once:true}); dialog.showModal();
  }

  function makePairingCard() {
    const {root,section}=card(t("pair_new_device"),t("pair_new_device_description"));
    const wrap=el("div","ns-devices__pairing");
    const codeRow=el("div","ns-devices__code-row");
    const codeCopy=el("div"); codeCopy.append(el("div","ns-field__label",t("current_code")),el("div","ns-code",pairing?.pairing_code || "—"));
    codeRow.appendChild(codeCopy);
    if(pairing?.active){
      const timer=el("div","ns-devices__timer"); timer.dataset.pairingTimer="true";
      const ring=document.createElementNS("http://www.w3.org/2000/svg","svg"); ring.setAttribute("viewBox","0 0 76 76"); ring.setAttribute("aria-hidden","true"); ring.classList.add("ns-devices__timer-ring");
      const track=document.createElementNS("http://www.w3.org/2000/svg","circle"); track.setAttribute("cx","38"); track.setAttribute("cy","38"); track.setAttribute("r","34"); track.classList.add("ns-devices__timer-track");
      const progress=document.createElementNS("http://www.w3.org/2000/svg","circle"); progress.setAttribute("cx","38"); progress.setAttribute("cy","38"); progress.setAttribute("r","34"); progress.classList.add("ns-devices__timer-progress"); progress.dataset.pairingTimerProgress="true";
      ring.append(track,progress);
      const timerLabel=el("span","ns-devices__timer-label",formatCountdown(secondsLeft())); timerLabel.dataset.pairingTimerLabel="true"; timer.append(ring,timerLabel); updateTimerNode(timer,secondsLeft());
      codeRow.appendChild(timer);
    }
    wrap.appendChild(codeRow);
    const controls=el("div","ns-inline-actions"); const start=button(t("start_pairing"),"ns-button--primary"); start.addEventListener("click",startPairing); controls.appendChild(start);
    if(pairing?.pairing_code){ const copy=button(t("copy")); copy.addEventListener("click",async()=>{ if(await copyText(pairing.pairing_code)) showToast("success","write_otp_generated"); }); controls.appendChild(copy); }
    wrap.appendChild(controls); section.appendChild(wrap); return root;
  }

  function makeAuthenticatorCard() {
    const {root,section}=card(t("authenticator_setup"));
    const stack=el("div","ns-devices__auth-stack");

    const uriRow=el("div","ns-devices__secret-row");
    const uri=el("div","ns-devices__secret-value",pairing?.provisioning_uri || "—");
    uri.title=String(pairing?.provisioning_uri || "");
    const copyUri=button(t("copy"),"ns-button--compact");
    copyUri.disabled=!pairing?.provisioning_uri;
    copyUri.addEventListener("click",async()=>{ if(await copyText(pairing?.provisioning_uri)) showToast("success","copy"); });
    uriRow.append(uri,copyUri);
    stack.appendChild(uriRow);

    const row=el("div","ns-devices__secret-row");
    const display=el("div","ns-devices__secret-value ns-secret",secretVisible ? pairing?.totp_secret : "••••••••••••••••");
    display.title=secretVisible?String(pairing?.totp_secret||""):"";
    const show=button(secretVisible?t("hide"):t("show"),"ns-button--compact"); show.addEventListener("click",()=>{secretVisible=!secretVisible; render();});
    const copy=button(t("copy"),"ns-button--compact"); copy.addEventListener("click",async()=>{ if(await copyText(pairing?.totp_secret)) showToast("success","copy"); });
    row.append(display,show,copy); stack.appendChild(row);
    if(pairing?.qr_available){ const qr=button(t("qr_short"),"ns-button--compact ns-devices__qr-button"); qr.addEventListener("click",showQr); stack.appendChild(qr); }
    section.appendChild(stack);
    return root;
  }

  function makeDevicesCard() {
    const {root,section}=card(t("trusted_devices"),t("trusted_devices_description"));
    if(!devices.length){ section.appendChild(el("div","ns-devices__empty",t("no_devices_paired"))); return root; }
    const wrap=el("div","ns-table-wrap"); const table=el("table","ns-table");
    const head=el("thead"); const hr=el("tr"); ["#",t("trusted_devices"),t("history"),t("code_status"),""].forEach(v=>hr.appendChild(el("th","",v))); head.appendChild(hr); table.appendChild(head);
    const body=el("tbody");
    devices.forEach((device,index)=>{
      const tr=el("tr"); tr.appendChild(el("td","ns-table__mono",String(index+1).padStart(2,"0"))); const idCell=el("td","ns-table__mono ns-devices__device-id",shortDeviceId(device.device_id)); idCell.title=String(device.device_id||""); tr.appendChild(idCell); tr.appendChild(el("td","ns-table__mono",formatDate(device.paired_at)));
      const status=el("td"); const badge=document.createElement("ns-status-badge"); badge.setAttribute("tone",device.connected?"success":"neutral"); badge.textContent=device.connected?t("online"):t("offline"); status.appendChild(badge); tr.appendChild(status);
      const actions=el("td","ns-table__actions"); const revokeButton=button(t("revoke"),"ns-button--compact ns-button--danger"); revokeButton.addEventListener("click",()=>revoke(device.device_id)); actions.appendChild(revokeButton); tr.appendChild(actions); body.appendChild(tr);
    });
    table.appendChild(body); wrap.appendChild(table); section.appendChild(wrap); return root;
  }

  async function refreshActivePairing(){
    if(disposed || pairingRefreshPending || !pairing?.active)return;
    pairingRefreshPending=true;
    try{
      const response=await callDesktopApi("get_pairing_snapshot");
      if(!response?.ok)return;
      const next=response.data||{};
      if(!next.active || !next.pairing_code){
        pairing=next;
        clearTicker();
        await load();
        return;
      }
      pairing=next;
      const node=host.querySelector("[data-pairing-timer]");
      const remain=secondsLeft();
      updateTimerNode(node,remain);
      if(!remain){ clearTicker(); pairing={...pairing,active:false,pairing_code:"",expires_at:0}; render(); }
    }finally{
      pairingRefreshPending=false;
    }
  }

  function render(){
    if(disposed)return; clearTicker(); host.replaceChildren();
    const heading=el("div","ns-section-heading"); const copy=el("div"); copy.append(el("div","ns-section-heading__eyebrow",`03 / ${t("devices")}`),el("h1","ns-section-heading__title",t("devices")),el("p","ns-section-heading__description",t("devices_description"))); const actions=el("div","view-actions"); const pair=button(t("pair_device"),"ns-button--primary"); pair.addEventListener("click",startPairing); actions.appendChild(pair); heading.append(copy,actions); host.appendChild(heading);
    const view=el("div","ns-devices"); const grid=el("div","ns-devices__grid"); const left=el("div"); left.appendChild(makeDevicesCard()); const right=el("div","ns-form-stack"); right.append(makePairingCard(),makeAuthenticatorCard()); grid.append(left,right); view.appendChild(grid); host.appendChild(view);
    if(pairing?.active){ ticker=globalThis.setInterval(()=>{ void refreshActivePairing(); },1000); }
  }

  function onBackendEvent(event){ try{ if(event?.detail?.name==="devices.changed") load(); }catch(_){} }
  globalThis.addEventListener(BACKEND_EVENT,onBackendEvent);
  load();
  return()=>{ disposed=true; clearTicker(); globalThis.removeEventListener(BACKEND_EVENT,onBackendEvent); };
}
