"""Label every unlabelled classification in a config's database, e.g. a database fed only from Gmail's
Spam folders: `python scripts/label_all.py <config> bulk`. Each label goes through the console's own
validation, exactly as if typed by the owner."""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # run as `python scripts/label_all.py`
from rubberbandbox.config import load  # noqa: E402
from rubberbandbox.console import main as console  # noqa: E402

config_path, label = sys.argv[1], sys.argv[2]
db = sqlite3.connect(load(config_path).db)
rows = db.execute("SELECT c.raw FROM classifications c LEFT JOIN labels l ON l.raw=c.raw WHERE l.raw IS NULL").fetchall()
db.close()
for (raw,) in rows:
    console(["label", raw, label, "--config", config_path])
print(f"labelled {len(rows)} as {label}", file=sys.stderr)
