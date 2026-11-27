import stat

import pytest

from nexrecon.modules import searchsploit_scan as ss


@pytest.fixture(autouse=True)
def _reset_cache(monkeypatch):
    # El resolver cachea el resultado en variables de módulo; sin resetear
    # esto, el primer test que corra decide el resultado de todos los demás.
    monkeypatch.setattr(ss, "_resolved", False)
    monkeypatch.setattr(ss, "_resolved_path", None)
    yield


def test_env_var_override_wins(monkeypatch, tmp_path):
    fake = tmp_path / "searchsploit"
    fake.write_text("#!/bin/sh\necho hi\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("NEXRECON_SEARCHSPLOIT_PATH", str(fake))
    assert ss._resolve_path() == str(fake)
    assert ss.searchsploit_available() is True


def test_falls_back_to_common_install_path_when_which_fails(monkeypatch, tmp_path):
    # Reproduce el caso real: instalación oficial de exploitdb que deja
    # `searchsploit` como alias de shell, invisible para shutil.which.
    fake = tmp_path / "searchsploit"
    fake.write_text("#!/bin/sh\necho hi\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.delenv("NEXRECON_SEARCHSPLOIT_PATH", raising=False)
    monkeypatch.setattr(ss.shutil, "which", lambda name: None)
    monkeypatch.setattr(ss, "_COMMON_PATHS", (str(fake),))
    assert ss._resolve_path() == str(fake)


def test_not_available_when_nothing_resolves(monkeypatch):
    monkeypatch.delenv("NEXRECON_SEARCHSPLOIT_PATH", raising=False)
    monkeypatch.setattr(ss.shutil, "which", lambda name: None)
    monkeypatch.setattr(ss, "_COMMON_PATHS", ())
    assert ss.searchsploit_available() is False


def test_gather_exploits_mentions_env_var_when_not_found(monkeypatch):
    from nexrecon.models import HostResult
    monkeypatch.delenv("NEXRECON_SEARCHSPLOIT_PATH", raising=False)
    monkeypatch.setattr(ss.shutil, "which", lambda name: None)
    monkeypatch.setattr(ss, "_COMMON_PATHS", ())
    host = HostResult(hostname="t.example")
    findings = ss.gather_exploits_for_host(host)
    assert len(findings) == 1
    assert "NEXRECON_SEARCHSPLOIT_PATH" in findings[0].detail


def test_resolves_alias_from_zshrc(monkeypatch, tmp_path):
    fake = tmp_path / "searchsploit"
    fake.write_text("#!/bin/sh\necho hi\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    zshrc = tmp_path / ".zshrc"
    zshrc.write_text(f'alias ls="ls --color"\nalias searchsploit="{fake}"\n')
    monkeypatch.delenv("NEXRECON_SEARCHSPLOIT_PATH", raising=False)
    monkeypatch.setattr(ss.shutil, "which", lambda name: None)
    monkeypatch.setattr(ss, "_COMMON_PATHS", ())
    monkeypatch.setattr(ss, "_SHELL_RC_FILES", (str(zshrc),))
    assert ss._resolve_path() == str(fake)


def test_resolves_alias_from_bashrc_with_extra_args(monkeypatch, tmp_path):
    fake = tmp_path / "searchsploit"
    fake.write_text("#!/bin/sh\necho hi\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    bashrc = tmp_path / ".bashrc"
    bashrc.write_text(f"alias searchsploit='{fake} --color'\n")
    monkeypatch.delenv("NEXRECON_SEARCHSPLOIT_PATH", raising=False)
    monkeypatch.setattr(ss.shutil, "which", lambda name: None)
    monkeypatch.setattr(ss, "_COMMON_PATHS", ())
    monkeypatch.setattr(ss, "_SHELL_RC_FILES", (str(bashrc),))
    assert ss._resolve_path() == str(fake)


def test_ignores_alias_pointing_to_nothing_real(monkeypatch, tmp_path):
    rc = tmp_path / ".zshrc"
    rc.write_text("alias searchsploit='/does/not/exist'\n")
    monkeypatch.delenv("NEXRECON_SEARCHSPLOIT_PATH", raising=False)
    monkeypatch.setattr(ss.shutil, "which", lambda name: None)
    monkeypatch.setattr(ss, "_COMMON_PATHS", ())
    monkeypatch.setattr(ss, "_SHELL_RC_FILES", (str(rc),))
    assert ss._resolve_path() is None


def test_missing_rc_files_dont_crash(monkeypatch):
    monkeypatch.delenv("NEXRECON_SEARCHSPLOIT_PATH", raising=False)
    monkeypatch.setattr(ss.shutil, "which", lambda name: None)
    monkeypatch.setattr(ss, "_COMMON_PATHS", ())
    monkeypatch.setattr(ss, "_SHELL_RC_FILES", ("~/.this_file_does_not_exist_nexrecon_test",))
    assert ss._resolve_path() is None
