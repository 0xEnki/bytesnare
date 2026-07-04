"""Allow running ``python -m shadownet`` from the project root."""

from __future__ import annotations

if __name__ == "__main__":
    from .entrypoint import main

    main()
