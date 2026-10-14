"""X25519 numeric-comparison pairing.

Ephemeral X25519 protects passive listeners. Commit/reveal nonces bind the
window, roles, node identities, DH keys and temporary TLS certificates before
either nonce is disclosed. A six-digit SAS accepted on both PCs limits an
undetected active MITM to about 10^-6 per single-use ceremony; this depends on
careful visual comparison.

A Slave key is certified for one cluster/node/serial only. It signs neither CA
nor tickets. Once its serial is removed from Master trust and its ticket
generation revoked, even a stolen, later-unlocked Slave cannot rejoin without
a new SAS ceremony and certificate.
"""
from __future__ import annotations
import hashlib, hmac, threading, time
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

LABEL=b"netshare-cluster-sas-v2"; TTL=300; NONCE_SIZE=16
class SasError(ValueError): pass

def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
def frame(*values): return b"".join(len(v).to_bytes(2,"big")+v for v in values)
def make_context(window,master,slave,mpub,spub,mfp,sfp):
    values=(LABEL,window.encode(),master.encode(),slave.encode(),mpub,spub,mfp,sfp)
    if len(window)!=16 or len(mpub)!=32 or len(spub)!=32 or any(not v for v in values): raise SasError("invalid transcript")
    return frame(*values)
def commit(role,ctx,nonce):
    if role not in ("master","slave") or len(nonce)!=16: raise SasError("invalid commitment")
    return hmac.new(nonce,LABEL+b"/commit/"+role.encode()+ctx,hashlib.sha256).digest()
def full_transcript(ctx,mnonce,snonce):
    if len(mnonce)!=16 or len(snonce)!=16: raise SasError("invalid nonce")
    return ctx+mnonce+snonce
@dataclass(frozen=True)
class Material:
    master_confirm: bytes; slave_confirm: bytes; envelope_key: bytes; sas: str
def derive(private,peer,transcript):
    try: shared=private.exchange(X25519PublicKey.from_public_bytes(peer))
    except ValueError as error: raise SasError("invalid public key") from error
    if hmac.compare_digest(shared,bytes(32)): raise SasError("invalid shared secret")
    out=HKDF(algorithm=hashes.SHA256(),length=100,salt=hashlib.sha256(transcript).digest(),info=LABEL+b"/keys").derive(shared)
    return Material(out[:32],out[32:64],out[64:96],f"{int.from_bytes(out[96:],'big')%1000000:06d}")
def confirm(material,role,transcript):
    key=material.master_confirm if role=="master" else material.slave_confirm if role=="slave" else None
    if key is None: raise SasError("invalid role")
    return hmac.new(key,LABEL+b"/confirm/"+role.encode()+transcript,hashlib.sha256).digest()

class Ceremony:
    def __init__(self,clock=time.time):
        self.expires_at=int(clock())+TTL; self.claimed=False; self.closed=False; self.sas=""; self._decision=None; self._cv=threading.Condition()
    def claim(self,clock=time.time):
        with self._cv:
            if self.closed or int(clock())>self.expires_at:
                self.closed=True; raise SasError("window unavailable")
            if self.claimed: raise SasError("window already claimed")
            self.claimed=True
    def present(self,value):
        with self._cv:
            if self.closed or not self.claimed or len(value)!=6 or not value.isdigit(): raise SasError("ceremony unavailable")
            self.sas=value; self._cv.notify_all()
    def decide(self,matches):
        with self._cv:
            if self.closed or not self.sas or self._decision is not None: raise SasError("ceremony unavailable")
            self._decision=bool(matches); self._cv.notify_all()
    def wait(self,clock=time.time):
        with self._cv:
            if self._decision is None: self._cv.wait(max(0,self.expires_at-clock()))
            if self._decision is not True:
                self.closed=True; self.sas=""; self._decision=None; self._cv.notify_all()
                raise SasError("rejected or expired")
    def close(self):
        with self._cv: self.closed=True; self.sas=""; self._decision=None; self._cv.notify_all()
