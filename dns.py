import argparse
from pathlib import Path

from src.dnsserver import DnsServer


def main():
    args_namespace = get_argsparser()
    server = DnsServer(
        args_namespace.port,
        args_namespace.source,
        args_namespace.cachefile,
    )
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()


def get_argsparser() -> argparse.Namespace:
    argsparser = argparse.ArgumentParser(description="Caching DNS server.")
    argsparser.add_argument(
        "-p", "--port", help="Server port", type=int, default=53
    )
    argsparser.add_argument(
        "-s",
        "--source",
        help="Server to get and cache responces from.",
        default="1.1.1.1:53",
    )
    argsparser.add_argument(
        "-c",
        "--cachefile",
        help="Path to cache file.",
        type=Path,
        default="./usr/cache.txt",
    )
    argsparser.parse_args()
    return argsparser.parse_args()


if __name__ == "__main__":
    main()
