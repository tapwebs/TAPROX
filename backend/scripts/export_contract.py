"""Write the backend's OpenAPI document to shared/api-contracts/openapi.json.

The running backend does not serve /openapi.json (it would be unauthenticated surface), so the
contract is generated offline from the same application factory the server uses.

    cd backend && uv run python -m scripts.export_contract      (or: npm run contracts:export)
"""

import json
from pathlib import Path

from sqlalchemy import create_engine

from app.core.config import Settings
from app.main import create_app

CONTRACT_PATH = Path(__file__).resolve().parents[2] / "shared" / "api-contracts" / "openapi.json"


def build_contract() -> str:
    # No request is served: the token and database only satisfy the application factory.
    settings = Settings(data_dir=Path("unused"), api_token="x" * 43)
    app = create_app(settings, create_engine("sqlite://"))
    return json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n"


def main() -> None:
    CONTRACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONTRACT_PATH.write_text(build_contract(), encoding="utf-8", newline="\n")
    print(f"wrote {CONTRACT_PATH}")


if __name__ == "__main__":
    main()
