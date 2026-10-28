"""Allow ``python -m nmap_scan``."""

from .cli import entrypoint

if __name__ == "__main__":
    entrypoint()
