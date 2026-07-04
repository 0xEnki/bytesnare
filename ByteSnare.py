"""
ByteSnare — Legacy entrypoint for backward compatibility.

Redirects to the ShadowNet package.
"""

from __future__ import annotations

from shadownet import main

if __name__ == "__main__":
    main()
