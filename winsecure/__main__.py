"""
WinSecure Module Entrypoint for `python -m winsecure`
"""
import sys
from winsecure.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
