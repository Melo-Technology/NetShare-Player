"""TLS transport and encrypted enrollment for bilateral SAS pairing."""
import base64, hashlib, hmac, json, secrets, socket, time
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .bootstrap import BOOTSTRAP_ALPN, BOOTSTRAP_TIMEOUT_SECONDS, BootstrapError, BootstrapTarget, _node_id, bootstrap_client_context, bootstrap_server_context
from .protocol import receive_frame, send_frame
from .registry import SlaveNode
from .revocation import RevocationRegistry
from .sas_pairing import Ceremony, commit, confirm, derive, full_transcript, make_context, public
from .tls import PeerTrustStore

def b64(v): return base64.b64encode(v).decode()
def unb64(v):
    try: return base64.b64decode(str(v),validate=True)
    except Exception as e: raise BootstrapError("invalid SAS encoding") from e
def fp(cert): return cert.fingerprint(hashes.SHA256())
def seal(key,transcript,payload):
    nonce=secrets.token_bytes(12); aad=hashlib.sha256(transcript).digest(); raw=json.dumps(payload,separators=(",",":"),sort_keys=True).encode()
    return {"nonce":b64(nonce),"sealed":b64(AESGCM(key).encrypt(nonce,raw,aad))}
def open_sealed(key,transcript,value):
    try: return json.loads(AESGCM(key).decrypt(unb64(value["nonce"]),unb64(value["sealed"]),hashlib.sha256(transcript).digest()))
    except Exception as e: raise BootstrapError("invalid enrollment envelope") from e

class SlaveSasSession:
    def __init__(self,*,store,trust_path,target,ceremony,on_master_authenticated=lambda _name,_url:None): self.store=store; self.trust_path=trust_path; self.target=target; self.ceremony=ceremony; self.on_master_authenticated=on_master_authenticated
    def handle(self,raw):
        secure=bootstrap_server_context(self.store,self.target.node_id).wrap_socket(raw,server_side=True); secure.settimeout(BOOTSTRAP_TIMEOUT_SECONDS)
        try:
            if secure.selected_alpn_protocol()!=BOOTSTRAP_ALPN: raise BootstrapError("invalid bootstrap ALPN")
            self.ceremony.claim(); slave_cert=x509.load_pem_x509_certificate((self.store.directory/"bootstrap_cert.pem").read_bytes())
            sk=X25519PrivateKey.generate(); sp=public(sk)
            send_frame(secure,{"v":2,"node_id":self.target.node_id,"name":self.target.name,"window_id":self.target.window_id,"content_port":self.target.content_port,"public":b64(sp)})
            first=receive_frame(secure); master_cert=x509.load_pem_x509_certificate(unb64(first.get("certificate"))); mp=unb64(first.get("public"))
            ctx=make_context(self.target.window_id,_node_id(master_cert),self.target.node_id,mp,sp,fp(master_cert),fp(slave_cert)); mc=unb64(first.get("commitment")); sn=secrets.token_bytes(16)
            send_frame(secure,{"commitment":b64(commit("slave",ctx,sn))}); mn=unb64(receive_frame(secure).get("nonce"))
            if not hmac.compare_digest(mc,commit("master",ctx,mn)): raise BootstrapError("master commitment mismatch")
            send_frame(secure,{"nonce":b64(sn)}); transcript=full_transcript(ctx,mn,sn); material=derive(sk,mp,transcript)
            if not hmac.compare_digest(unb64(receive_frame(secure).get("confirm")),confirm(material,"master",transcript)): raise BootstrapError("master confirmation failed")
            send_frame(secure,{"confirm":b64(confirm(material,"slave",transcript))}); self.ceremony.present(material.sas); secure.settimeout(max(1,self.ceremony.expires_at-int(time.time()))); self.ceremony.wait()
            master_ok=receive_frame(secure).get("matches") is True; send_frame(secure,{"matches":True})
            if not master_ok: raise BootstrapError("SAS rejected")
            enrollment=open_sealed(material.envelope_key,transcript,receive_frame(secure)); ca=x509.load_pem_x509_certificate(unb64(enrollment["ca"])); node=x509.load_pem_x509_certificate(unb64(enrollment["node_certificate"])); master=x509.load_pem_x509_certificate(unb64(enrollment["master_certificate"])); ca.public_key().verify(master.signature,master.tbs_certificate_bytes)
            identity=self.store.install_joined_identity(cluster_id=enrollment["cluster_id"],node_id=self.target.node_id,ca_certificate=ca,node_certificate=node); PeerTrustStore(self.trust_path,identity.ca_fingerprint).allow(enrollment["master_node_id"],master)
            signing=unb64(enrollment["signing_public_key"])
            if len(signing)!=32: raise BootstrapError("invalid signing key")
            (self.store.directory/"master_signing_key.bin").write_bytes(signing); RevocationRegistry(self.store.directory/"revocations.json").synchronize_generation(self.target.node_id,int(enrollment["audience_generation"])); self.on_master_authenticated(str(enrollment.get("master_name") or ""),str(enrollment.get("master_lan_url") or "")); send_frame(secure,{"status":"installed"})
        finally: self.ceremony.close(); secure.close()

def enroll_sas(*,target,ceremony,master_store,master_trust,registry,signing_public_key,audience_generation=0,master_name="",master_lan_url="",target_created_at=0):
    raw=socket.create_connection((target.host,target.bootstrap_port),timeout=BOOTSTRAP_TIMEOUT_SECONDS); secure=bootstrap_client_context().wrap_socket(raw,server_hostname=None); secure.settimeout(BOOTSTRAP_TIMEOUT_SECONDS)
    try:
        ceremony.claim(); slave_cert=x509.load_der_x509_certificate(secure.getpeercert(binary_form=True)); hello=receive_frame(secure)
        if hello.get("v")!=2 or hello.get("node_id")!=target.node_id or hello.get("window_id")!=target.window_id: raise BootstrapError("target mismatch")
        identity=master_store.load_identity(); master_cert=x509.load_pem_x509_certificate(identity.node_certificate_path.read_bytes()); sk=X25519PrivateKey.generate(); mp=public(sk); sp=unb64(hello.get("public")); ctx=make_context(target.window_id,identity.node_id,target.node_id,mp,sp,fp(master_cert),fp(slave_cert)); mn=secrets.token_bytes(16)
        send_frame(secure,{"certificate":b64(identity.node_certificate_path.read_bytes()),"public":b64(mp),"commitment":b64(commit("master",ctx,mn))}); sc=unb64(receive_frame(secure).get("commitment")); send_frame(secure,{"nonce":b64(mn)}); sn=unb64(receive_frame(secure).get("nonce"))
        if not hmac.compare_digest(sc,commit("slave",ctx,sn)): raise BootstrapError("slave commitment mismatch")
        transcript=full_transcript(ctx,mn,sn); material=derive(sk,sp,transcript); send_frame(secure,{"confirm":b64(confirm(material,"master",transcript))})
        if not hmac.compare_digest(unb64(receive_frame(secure).get("confirm")),confirm(material,"slave",transcript)): raise BootstrapError("slave confirmation failed")
        ceremony.present(material.sas); secure.settimeout(max(1,ceremony.expires_at-int(time.time()))); ceremony.wait(); send_frame(secure,{"matches":True})
        if receive_frame(secure).get("matches") is not True: raise BootstrapError("SAS rejected")
        cert=master_store.issue_node_certificate(target.node_id,slave_cert.public_key()); send_frame(secure,seal(material.envelope_key,transcript,{"cluster_id":identity.cluster_id,"master_node_id":identity.node_id,"master_name":str(master_name),"master_lan_url":str(master_lan_url),"ca":b64(identity.ca_certificate_path.read_bytes()),"master_certificate":b64(identity.node_certificate_path.read_bytes()),"node_certificate":b64(cert.public_bytes(serialization.Encoding.PEM)),"signing_public_key":b64(signing_public_key),"audience_generation":int(audience_generation)}))
        if receive_frame(secure).get("status")!="installed": raise BootstrapError("installation failed")
        master_trust.allow(target.node_id,cert); node=SlaveNode(target.node_id,str(hello.get("name") or target.name),target.host,target.content_port,cert.serial_number,False,int(target_created_at or 0)); registry.add(node); return node
    finally: ceremony.close(); secure.close()
