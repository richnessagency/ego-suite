"""Core configuration and paths for EGO Suite."""

from pathlib import Path
import json

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = DATA_DIR / "reports"
BIN_DIR = BASE_DIR / "bin"
VENV_BIN_DIR = BASE_DIR / ".venv" / "bin"
NODE_BIN_DIR = BASE_DIR / ".node_tools" / "node_modules" / ".bin"
DB_PATH = DATA_DIR / "ego.db"
SELECTED_TOOLS_PATH = BASE_DIR / "selected-tools.json"


def ensure_directories() -> None:
    """Create portable runtime directories if they do not exist."""
    for directory in (DATA_DIR, REPORTS_DIR, BIN_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def load_selected_tools() -> list[dict]:
    """Load the user's selected tools from selected-tools.json."""
    if not SELECTED_TOOLS_PATH.exists():
        return []
    try:
        data = json.loads(SELECTED_TOOLS_PATH.read_text(encoding="utf-8"))
        return data.get("tools", [])
    except (json.JSONDecodeError, OSError):
        return []

