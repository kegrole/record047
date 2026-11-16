"""Allow ``python -m safextract`` as an alias of the CLI module."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
