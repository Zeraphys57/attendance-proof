"""Ruang kelas virtual: posisi kursi, jangkauan BLE, jam simulasi, dan skenario serangan.

Yang disimulasikan hanya dunia fisik (jarak, delay, siapa memegang HP siapa).
Semua tanda tangan dan verifikasinya memakai Ed25519 asli dari library cryptography.
"""
import math
import os

from .chip import SecureChip, VendorRoot
from .crypto import ProtocolError
from .pki import CampusCA
from .protocol import AUDIT_SIZE, Lecturer, Phone, Verifier, audit_pick, candidates

BLE_RANGE = 12.0     # meter
BLE_HOP = 0.05       # detik per hop BLE
NAMES = ["Andi", "Budi", "Citra", "Dewi", "Eko", "Fajar", "Gita", "Hana", "Irfan", "Joko",
         "Kevin", "Lala", "Made", "Nadia", "Oki", "Putri", "Raka", "Sari", "Tono", "Wulan"]
HOME = (5000.0, 5000.0)


class Classroom:
    def __init__(self):
        self.vendor = VendorRoot()
        self.ca = CampusCA(self.vendor)
        self.lecturer = Lecturer("Pak Dosen", self.vendor, self.ca)
        self.lecturer_pos = (6.0, -1.0)
        seats = [(2.0 * (i % 5) + 2, 2.0 * (i // 5) + 1) for i in range(len(NAMES))]
        self.phones = {n: Phone(n, self.vendor, self.ca, s) for n, s in zip(NAMES, seats)}
        self.verifier = Verifier(self.ca.public_key, NAMES)
        self.sid, self.round = "KRIPTO-P11", 0

    def near(self, a, b):
        return math.dist(a, b) <= BLE_RANGE

    def start_round(self, t0=0.0):
        self.round += 1
        b = self.lecturer.beacon(self.sid, self.round, t0)
        self.verifier.open_round(b)
        for p in self.phones.values():
            p.beacon = None
            if self.near(p.seat, self.lecturer_pos):
                p.hear_beacon(b, t0 + BLE_HOP)
        return b

    def collect_witnesses(self, p, b, now, pick=None):
        """Minta tanda tangan ke kandidat hasil undian yang ada di jangkauan BLE."""
        ws = []
        for name in pick or candidates(b["seed"], p.npm, NAMES):
            q = self.phones[name]
            if q is p or not self.near(p.seat, q.seat):
                continue
            try:
                ws.append(q.witness_for(p.npm, b["nonce"], now))
            except ProtocolError:
                continue
            if len(ws) == 2:
                break
        return ws

    def attend(self, name, t0=0.0, delay=0.0):
        p = self.phones[name]
        b = self.verifier.beacon
        ws = self.collect_witnesses(p, b, t0 + delay + 0.2)
        c = p.claim(ws, t0 + delay + 0.4)
        return self.verifier.check(c, t0 + delay + 0.7)

    def everyone_except(self, absent=(), t0=0.0):
        ok = []
        for n in NAMES:
            if n not in absent:
                self.attend(n, t0)
                ok.append(n)
        return ok


def run(label, attack, expect="TERDETEKSI"):
    """Jalankan satu skenario. attack() mengembalikan teks hasil atau melempar error saat ditolak."""
    try:
        note = attack()
        result = ("LOLOS", note)
    except (ProtocolError, PermissionError) as e:
        result = ("TERDETEKSI", f"{type(e).__name__}: {e}")
    return {"label": label, "status": result[0], "detail": result[1], "expected": expect}


# ---------------------------------------------------------------- skenario

def s_normal():
    k = Classroom(); k.start_round()
    ok = k.everyone_except()
    return f"{len(ok)}/{len(NAMES)} mahasiswa hadir terverifikasi, masing masing dengan 2 saksi hasil undian"


def s_absen_dari_rumah():
    """Budi di rumah. Teman memotret QR beacon dan mengirim lewat WhatsApp (delay 8 detik)."""
    k = Classroom(); b = k.start_round()
    budi = k.phones["Budi"]; budi.seat = HOME
    budi.hear_beacon(b, 8.0)


def s_absen_dari_rumah_beacon_tepat_waktu():
    """Andaikan beacon sampai cepat, Budi tetap tidak punya saksi dalam jangkauan BLE."""
    k = Classroom(); b = k.start_round()
    budi = k.phones["Budi"]; budi.seat = HOME
    budi.beacon = b
    k.verifier.check(budi.claim(k.collect_witnesses(budi, b, 0.3), 0.5), 0.8)


def s_salin_kunci():
    """Budi mencoba mengekspor private key supaya HP joki bisa absen atas namanya."""
    k = Classroom(); k.start_round()
    k.phones["Budi"].chip.export_private_key()


def s_joki_pakai_sertifikat_budi():
    """Joki memasang sertifikat Budi di HP-nya sendiri, tapi chip joki punya kunci berbeda."""
    k = Classroom(); b = k.start_round()
    joki = Phone("Joki", k.vendor, k.ca, (4.0, 3.0))
    joki.hear_beacon(b, 0.05)
    joki.npm, joki.cert = "Budi", k.phones["Budi"].cert
    ws = k.collect_witnesses(joki, b, 0.3)
    k.verifier.check(joki.claim(ws, 0.5), 0.8)


def s_saksi_pilihan_sendiri():
    """Budi meminta sahabatnya jadi saksi, padahal sahabatnya bukan hasil undian."""
    k = Classroom(); b = k.start_round()
    allowed = candidates(b["seed"], "Budi", NAMES)
    bestie = [n for n in NAMES if n not in allowed and n != "Budi"][:2]
    budi = k.phones["Budi"]
    ws = k.collect_witnesses(budi, b, 0.3, pick=bestie)
    k.verifier.check(budi.claim(ws, 0.5), 0.8)


def s_beacon_palsu():
    """Server atau penyerang menyiarkan beacon dengan kunci dosen palsu (sertifikat buatan sendiri)."""
    k = Classroom(); k.start_round()
    rogue_ca = CampusCA(k.vendor)
    fake = Lecturer("Pak Dosen", k.vendor, rogue_ca)
    k.phones["Andi"].hear_beacon(fake.beacon(k.sid, 99, 0.0), 0.05)


def s_replay_minggu_lalu():
    """Klaim sah dari ronde sebelumnya dikirim ulang di ronde berikutnya."""
    k = Classroom(); b = k.start_round()
    andi = k.phones["Andi"]
    old = andi.claim(k.collect_witnesses(andi, b, 0.3), 0.5)
    k.start_round(t0=0.0)
    k.verifier.check(old, 0.8)


def s_ubah_klaim():
    """Mallory mencegat klaim Andi lalu mengganti NPM-nya menjadi Budi."""
    k = Classroom(); b = k.start_round()
    andi = k.phones["Andi"]
    c = andi.claim(k.collect_witnesses(andi, b, 0.3), 0.5)
    c["npm"], c["cert"] = "Budi", k.phones["Budi"].cert
    k.verifier.check(c, 0.8)


def s_admin_nakal():
    """Admin server menambahkan kehadiran Budi tanpa HP Budi (tanda tangan dibuat chip lain)."""
    k = Classroom(); b = k.start_round()
    admin_chip = SecureChip(k.vendor)
    c = {"sid": b["sid"], "round": b["round"], "nonce": b["nonce"], "npm": "Budi", "t": 0.5,
         "witnesses": [], "cert": k.phones["Budi"].cert}
    from .protocol import claim_body
    c["sig"] = admin_chip.sign(claim_body(c))
    k.verifier.check(c, 0.8)


def s_relay_ble_cepat():
    """Batasan: proxy BLE di kelas meneruskan sinyal ke HP Budi di rumah dengan delay 0,4 detik."""
    k = Classroom(); b = k.start_round()
    budi = k.phones["Budi"]
    budi.beacon = b                       # beacon diteruskan proxy dalam 0,4 s, masih dalam jendela
    ws = k.collect_witnesses(budi, b, 0.6)   # proxy duduk di kursi Budi, jadi saksi tetap terjangkau
    budi.seat = HOME
    k.verifier.check(budi.claim(ws, 0.8), 1.1)
    return "lolos verifikasi kriptografi, perlu distance bounding (pengembangan)"


def s_titip_hp():
    """Batasan: Andi membawa HP Budi ke kelas. Kriptografi lolos, ditangkap audit acak."""
    k = Classroom(); b = k.start_round()
    k.phones["Budi"].seat = k.phones["Andi"].seat     # dua HP di kursi yang sama
    present = k.everyone_except()
    n = len(present)
    p1 = AUDIT_SIZE / n
    p14 = 1 - (1 - p1) ** 14
    called = audit_pick(os.urandom(16), present)
    return (f"lolos kriptografi, peluang ketahuan audit {p1:.0%} per pertemuan, "
            f"{p14:.0%} dalam 14 pertemuan (audit kali ini memanggil: {', '.join(called)})")


SCENARIOS = [
    ("S0 Kelas normal, 20 mahasiswa", s_normal, "LOLOS"),
    ("A1 Absen dari rumah, foto beacon dikirim lewat WA", s_absen_dari_rumah, "TERDETEKSI"),
    ("A2 Absen dari rumah, beacon tepat waktu tapi tanpa saksi", s_absen_dari_rumah_beacon_tepat_waktu, "TERDETEKSI"),
    ("A3 Mengekspor private key dari chip", s_salin_kunci, "TERDETEKSI"),
    ("A4 Joki memakai sertifikat Budi di HP sendiri", s_joki_pakai_sertifikat_budi, "TERDETEKSI"),
    ("A5 Saksi dipilih sendiri, bukan hasil undian", s_saksi_pilihan_sendiri, "TERDETEKSI"),
    ("A6 MITM: beacon dengan kunci dosen palsu", s_beacon_palsu, "TERDETEKSI"),
    ("A7 Replay klaim ronde sebelumnya", s_replay_minggu_lalu, "TERDETEKSI"),
    ("A8 MITM: klaim diubah di jalan", s_ubah_klaim, "TERDETEKSI"),
    ("A9 Admin server menyisipkan kehadiran palsu", s_admin_nakal, "TERDETEKSI"),
    ("B1 Batasan: relay BLE cepat lewat proxy", s_relay_ble_cepat, "LOLOS"),
    ("B2 Batasan: satu orang membawa dua HP", s_titip_hp, "LOLOS"),
]
