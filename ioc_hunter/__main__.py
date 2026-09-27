"""Enable `python -m ioc_hunter`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
