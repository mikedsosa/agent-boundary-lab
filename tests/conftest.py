from pathlib import Path

import pytest

from agentlab.workspace import open_lab, prepare_workspace


@pytest.fixture
def lab(tmp_path: Path):
    base = tmp_path / "ws"
    prepare_workspace(base)
    opened = open_lab(base)
    try:
        yield opened
    finally:
        opened.close()
