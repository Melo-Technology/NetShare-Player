"""TLS 1.3 bootstrap transport shared by the X25519/SAS ceremony."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from .identity import ClusterIdentityStore
BOOTSTRAP_ALPN="netshare-cluster-bootstrap/2"; BOOTSTRAP_TIMEOUT_SECONDS=5.0; BOOTSTRAP_CERT_VALID_MINUTES=10
class BootstrapError(ValueError): pass
@dataclass(frozen=True)
class BootstrapTarget:
    node_id:str; name:str; host:str; bootstrap_port:int; content_port:int; window_id:str
def _node_id(certificate):
    try: values=certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier)
    except x509.ExtensionNotFound as error: raise BootstrapError("certificate node identity missing") from error
    matches=[v[len("urn:netshare:node:"):] for v in values if v.startswith("urn:netshare:node:")]
    if len(matches)!=1: raise BootstrapError("certificate node identity invalid")
    return matches[0]
def create_bootstrap_certificate(store:ClusterIdentityStore,node_id:str)->Path:
    key=store.load_node_private_key() if store.node_key_path.exists() else None
    if key is None: store.create_node_key(); key=store.load_node_private_key()
    now=datetime.now(timezone.utc); name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"NetShare bootstrap")])
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(minutes=10)).add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(f"urn:netshare:node:{node_id}")]),critical=False).sign(key,algorithm=None))
    path=store.directory/"bootstrap_cert.pem"; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(cert.public_bytes(serialization.Encoding.PEM)); return path
def bootstrap_server_context(store,node_id):
    c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.minimum_version=c.maximum_version=ssl.TLSVersion.TLSv1_3; c.options|=ssl.OP_NO_COMPRESSION; c.set_alpn_protocols([BOOTSTRAP_ALPN]); c.load_cert_chain(str(create_bootstrap_certificate(store,node_id)),str(store.node_key_path),password=store.node_private_key_password()); return c
def bootstrap_client_context():
    c=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.minimum_version=c.maximum_version=ssl.TLSVersion.TLSv1_3; c.check_hostname=False; c.verify_mode=ssl.CERT_NONE; c.options|=ssl.OP_NO_COMPRESSION; c.set_alpn_protocols([BOOTSTRAP_ALPN]); return c