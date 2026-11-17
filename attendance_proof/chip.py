"""Simulasi secure chip (Secure Enclave / StrongBox) dan root attestation vendor HP.

Di HP sungguhan private key dibuat di dalam chip dan sistem operasi tidak punya API untuk
mengeluarkannya. Di simulasi ini private key hanya hidup di dalam closure fungsi sign, tidak
pernah disimpan sebagai atribut objek, dan export_private_key selalu menolak.
"""
from .crypto import PROTO, enc, new_keypair, verify


class VendorRoot:
    """Root attestation milik vendor HP. Membuktikan bahwa sebuah public key lahir di chip asli."""

    def __init__(self):
        sk, self.public_key = new_keypair()
        self._attest = lambda pk: sk.sign(enc({"proto": PROTO, "type": "ATTEST", "pk": pk}))

    def attest(self, chip_pk: bytes) -> bytes:
        return self._attest(chip_pk)

    def check(self, chip_pk: bytes, attestation: bytes):
        verify(self.public_key, attestation, enc({"proto": PROTO, "type": "ATTEST", "pk": chip_pk}), "attestation vendor")


class SecureChip:
    def __init__(self, vendor: VendorRoot):
        sk, self.public_key = new_keypair()
        self._sign = lambda msg: sk.sign(msg)        # private key terkunci di closure
        self.attestation = vendor.attest(self.public_key)

    def sign(self, msg: bytes) -> bytes:
        return self._sign(msg)

    def export_private_key(self):
        raise PermissionError("kunci non-exportable: private key tidak pernah keluar dari secure chip")
