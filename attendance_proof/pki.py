"""CA kampus: mengikat NPM / NIP ke public key chip saat registrasi tatap muka (misalnya saat KRS)."""
from .chip import VendorRoot
from .crypto import PROTO, ProtocolError, enc, new_keypair, verify


def cert_body(cert: dict) -> bytes:
    return enc({"proto": PROTO, "type": "CERT", "id": cert["id"], "role": cert["role"], "pk": cert["pk"]})


class CampusCA:
    def __init__(self, vendor: VendorRoot):
        sk, self.public_key = new_keypair()
        self._sign = lambda m: sk.sign(m)
        self.vendor = vendor

    def enroll(self, identity: str, role: str, chip_pk: bytes, attestation: bytes) -> dict:
        # Kampus hanya menerbitkan sertifikat untuk kunci yang terbukti lahir di secure chip
        self.vendor.check(chip_pk, attestation)
        cert = {"id": identity, "role": role, "pk": chip_pk}
        cert["sig"] = self._sign(cert_body(cert))
        return cert


def check_cert(cert: dict, ca_pk: bytes, role: str):
    """Dipanggil oleh HP mahasiswa dan server. ca_pk di-pin di dalam aplikasi."""
    verify(ca_pk, cert["sig"], cert_body(cert), f"sertifikat {cert.get('id')}")
    if cert["role"] != role:
        raise ProtocolError(f"sertifikat {cert['id']} berperan {cert['role']}, bukan {role}")
