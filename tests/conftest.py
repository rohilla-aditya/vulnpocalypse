"""Put the agent directory on sys.path.

Lets the suite run from the repo root or from inside `tests/`.
"""

import sys
from pathlib import Path

AGENT_ROOT = Path(__file__).resolve().parent.parent
if str(AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(AGENT_ROOT))
