"""
Entry point for running ActionSentry as a module: python -m actionsentry
"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
