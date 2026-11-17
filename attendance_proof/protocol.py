"""Protokol Attendance Proof: beacon dosen, saksi tetangga acak, klaim hadir, verifikasi, audit acak."""
import os

from .chip import SecureChip
from .crypto import PROTO, ProtocolError, enc, h, verify
from .pki import check_cert

WINDOW = 3.0        # detik: beacon, permintaan saksi, dan klaim harus terjadi dalam jendela ini
GRACE = 2.0         # detik: toleransi jaringan HP -> server
K_WITNESS = 2       # jumlah saksi wajib
M_CANDIDATES = 4    # saksi harus berasal dari 4 kandidat teratas hasil undian
AUDIT_SIZE = 3      # jumlah nama yang dipanggil dosen untuk audit tatap muka


def candidates(seed: bytes, npm: str, roster) -> list:
    """Urutan kandidat saksi untuk npm, ditentukan seed dosen. Mahasiswa tidak bisa memilih."""
    others = [j for j in roster if j != npm]
    return sorted(others, key=lambda j: h(PROTO, "WITNESS", seed, npm, j))[:M_CANDIDATES]


def audit_pick(seed: bytes, present) -> list:
    return sorted(present, key=lambda j: h(PROTO, "AUDIT", seed, j))[:AUDIT_SIZE]


def beacon_body(b):
    return enc({"proto": PROTO, "type": "BEACON", **{k: b[k] for k in ("sid", "round", "t", "nonce", "seed")}})


def wit_body(w):
    return enc({"proto": PROTO, "type": "WIT", **{k: w[k] for k in ("sid", "round", "nonce", "subject", "witness", "t")}})


def claim_body(c):
    wit_digest = [h(w["witness"], w["sig"]) for w in c["witnesses"]]
    return enc({"proto": PROTO, "type": "CLAIM", "wit": wit_digest,
                **{k: c[k] for k in ("sid", "round", "nonce", "npm", "t")}})


class Lecturer:
    def __init__(self, nip, vendor, ca):
        self.id, self.chip = nip, SecureChip(vendor)
        self.cert = ca.enroll(nip, "dosen", self.chip.public_key, self.chip.attestation)

    def beacon(self, sid, rnd, t):
        b = {"sid": sid, "round": rnd, "t": t, "nonce": os.urandom(16), "seed": os.urandom(16), "cert": self.cert}
        b["sig"] = self.chip.sign(beacon_body(b))
        return b


class Phone:
    def __init__(self, npm, vendor, ca, seat):
        self.npm, self.seat, self.chip = npm, seat, SecureChip(vendor)
        self.cert = ca.enroll(npm, "mhs", self.chip.public_key, self.chip.attestation)
        self.ca_pk = ca.public_key           # di-pin di aplikasi, tidak diambil dari server
        self.beacon = None

    def hear_beacon(self, b, now):
        check_cert(b["cert"], self.ca_pk, "dosen")
        verify(b["cert"]["pk"], b["sig"], beacon_body(b), "beacon dosen")
        if now - b["t"] > WINDOW:
            raise ProtocolError(f"beacon basi ({now - b['t']:.1f} s > {WINDOW} s)")
        self.beacon = b

    def witness_for(self, subject, nonce, now):
        """Dijalankan otomatis oleh chip saksi saat menerima permintaan lewat BLE."""
        b = self.beacon
        if b is None or b["nonce"] != nonce:
            raise ProtocolError(f"saksi {self.npm} tidak mendengar beacon yang sama")
        if now - b["t"] > WINDOW:
            raise ProtocolError(f"permintaan saksi terlambat ({now - b['t']:.1f} s > {WINDOW} s)")
        w = {"sid": b["sid"], "round": b["round"], "nonce": nonce, "subject": subject,
             "witness": self.npm, "t": now, "cert": self.cert}
        w["sig"] = self.chip.sign(wit_body(w))
        return w

    def claim(self, witnesses, now):
        b = self.beacon
        c = {"sid": b["sid"], "round": b["round"], "nonce": b["nonce"], "npm": self.npm,
             "t": now, "witnesses": witnesses, "cert": self.cert}
        c["sig"] = self.chip.sign(claim_body(c))
        return c


class Verifier:
    """Server presensi. Tidak memegang kunci siapa pun, hanya memeriksa bukti."""

    def __init__(self, ca_pk, roster):
        self.ca_pk, self.roster = ca_pk, list(roster)
        self.beacon, self.seen = None, set()

    def open_round(self, b):
        check_cert(b["cert"], self.ca_pk, "dosen")
        verify(b["cert"]["pk"], b["sig"], beacon_body(b), "beacon dosen")
        self.beacon, self.seen = b, set()

    def check(self, c, now):
        b = self.beacon
        check_cert(c["cert"], self.ca_pk, "mhs")
        if c["cert"]["id"] != c["npm"] or c["npm"] not in self.roster:
            raise ProtocolError("NPM pada klaim tidak cocok dengan sertifikat atau tidak terdaftar")
        verify(c["cert"]["pk"], c["sig"], claim_body(c), f"klaim {c['npm']}")
        if (c["sid"], c["round"], c["nonce"]) != (b["sid"], b["round"], b["nonce"]):
            raise ProtocolError("klaim bukan untuk ronde ini (nonce/sid berbeda), replay ditolak")
        if c["npm"] in self.seen:
            raise ProtocolError("klaim ganda pada ronde yang sama")
        if now - b["t"] > WINDOW + GRACE:
            raise ProtocolError(f"klaim sampai terlambat ({now - b['t']:.1f} s)")
        allowed = candidates(b["seed"], c["npm"], self.roster)
        valid = set()
        for w in c["witnesses"]:
            check_cert(w["cert"], self.ca_pk, "mhs")
            if w["cert"]["id"] != w["witness"]:
                raise ProtocolError("identitas saksi tidak cocok dengan sertifikat")
            verify(w["cert"]["pk"], w["sig"], wit_body(w), f"saksi {w['witness']}")
            if w["subject"] != c["npm"] or w["nonce"] != b["nonce"] or w["t"] - b["t"] > WINDOW:
                raise ProtocolError(f"kesaksian {w['witness']} bukan untuk klaim ini")
            if w["witness"] not in allowed:
                raise ProtocolError(f"saksi {w['witness']} bukan hasil undian untuk {c['npm']} (kandidat: {', '.join(allowed)})")
            valid.add(w["witness"])
        if len(valid) < K_WITNESS:
            raise ProtocolError(f"saksi kurang ({len(valid)}/{K_WITNESS})")
        self.seen.add(c["npm"])
        return True
