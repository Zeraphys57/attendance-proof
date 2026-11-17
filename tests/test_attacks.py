import pytest

from attendance_proof.sim import SCENARIOS, run


@pytest.mark.parametrize("label,fn,expect", SCENARIOS, ids=[s[0].split()[0] for s in SCENARIOS])
def test_scenario(label, fn, expect):
    assert run(label, fn, expect)["status"] == expect


def test_kelas_normal_stabil():
    """Undian saksi acak tidak boleh membuat mahasiswa jujur gagal absen."""
    for _ in range(25):
        assert run("normal", SCENARIOS[0][1])["status"] == "LOLOS"
