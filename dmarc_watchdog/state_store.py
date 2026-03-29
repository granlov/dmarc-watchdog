import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class StateStore:
    def __init__(self, stateFilePath: str):
        self.stateFilePath = Path(stateFilePath)
        self.stateFilePath.parent.mkdir(parents=True, exist_ok=True)

    def load_state(self) -> dict[str, Any]:
        if not self.stateFilePath.exists():
            return {
                "processedAttachmentHashes": [],
                "lastSuccessfulRunUtc": None,
                "lastRunStatus": "never-run",
            }

        with self.stateFilePath.open("r", encoding="utf-8") as stateFile:
            return json.load(stateFile)

    def save_state(self, state: dict[str, Any]) -> None:
        with self.stateFilePath.open("w", encoding="utf-8") as stateFile:
            json.dump(state, stateFile, indent=2, sort_keys=True)
            stateFile.write("\n")

    def mark_successful_run(self, state: dict[str, Any]) -> None:
        state["lastSuccessfulRunUtc"] = datetime.now(timezone.utc).isoformat()
        state["lastRunStatus"] = "success"
        self.save_state(state)

    def mark_failed_run(self, state: dict[str, Any]) -> None:
        state["lastRunStatus"] = "failed"
        self.save_state(state)
