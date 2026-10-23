from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_angr_uses_compatible_pycparser_version():
    """angr 9.2.223 is incompatible with pycparser 3.12's token stream API."""
    manifests = (
        PROJECT_ROOT / "requirements.txt",
        PROJECT_ROOT / "pyproject.toml",
        PROJECT_ROOT / "setup.py",
    )

    for manifest in manifests:
        content = manifest.read_text(encoding="utf-8")
        assert "pycparser==3.11" in content, (
            f"{manifest.name} must pin pycparser 3.11 for angr 9.2.223"
        )
