import argparse
import sys

from .config import ConfigurationError, load_app_config
from .runner import run_watchdog


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DMARC Watchdog")
    parser.add_argument(
        "--config",
        default="config/config.example.json",
        help="Path to config JSON file",
    )
    return parser


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()

    try:
        appConfig = load_app_config(args.config)
    except ConfigurationError as configurationError:
        print(f"CONFIG ERROR: {configurationError}")
        return 2

    return run_watchdog(appConfig)


if __name__ == "__main__":
    sys.exit(main())
