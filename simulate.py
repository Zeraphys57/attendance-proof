"""Jalankan: python simulate.py"""
from attendance_proof.sim import SCENARIOS, run


def main():
    print("Attendance Proof: simulasi presensi anti titip absen\n")
    bad = 0
    for label, fn, expect in SCENARIOS:
        r = run(label, fn, expect)
        mark = "OK " if r["status"] == expect else "!! "
        bad += r["status"] != expect
        print(f"{mark}[{r['status']:<10}] {label}")
        if r["detail"]:
            print(f"               {r['detail']}")
    print(f"\n{len(SCENARIOS) - bad}/{len(SCENARIOS)} skenario sesuai ekspektasi desain")
    return bad


if __name__ == "__main__":
    raise SystemExit(main())
