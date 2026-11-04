from pathlib import Path

PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
ALEMBIC_INI: Path = PROJECT_ROOT / "alembic.ini"
STATIC_DIR: Path = PROJECT_ROOT / "static"
