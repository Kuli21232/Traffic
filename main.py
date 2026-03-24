#!/usr/bin/env python3
"""
LocalBypass — local DPI circumvention proxy.

Usage:
    python main.py [--host 127.0.0.1] [--port 8080] [--strategy auto]

Then set your browser / system proxy to HTTP proxy 127.0.0.1:8080.
"""
import argparse
import logging
import sys

from bypass.config import Config
from bypass.proxy import BypassProxy
from bypass.strategies import STRATEGIES


def main() -> None:
    parser = argparse.ArgumentParser(
        description="LocalBypass — local DPI circumvention proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Strategies:
  auto          Probe each host and cache the fastest working strategy (default)
  direct        No manipulation — plain TCP
  tls_split     Split TLS ClientHello at the SNI field (2 TCP segments)
  tls_fragment  Send TLS ClientHello byte-by-byte (or --fragment-size chunks)
  http_split    Split HTTP request before the Host: header
  disorder      Send ghost segment with TTL=1, then full data (needs root)

Examples:
  python main.py                          # auto mode, port 8080
  python main.py --strategy tls_split     # force TLS split for all hosts
  python main.py --port 1080 --verbose    # custom port, verbose logging
        """,
    )
    parser.add_argument("--host", default="127.0.0.1", help="Listen address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Listen port (default: 8080)")
    parser.add_argument(
        "--strategy",
        default="auto",
        choices=["auto"] + list(STRATEGIES.keys()),
        help="DPI bypass strategy (default: auto)",
    )
    parser.add_argument(
        "--fragment-size",
        type=int,
        default=2,
        metavar="BYTES",
        help="Chunk size for fragment strategies (default: 2)",
    )
    parser.add_argument(
        "--fragment-delay",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="Delay between fragments in seconds (default: 0)",
    )
    parser.add_argument(
        "--probe-timeout",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="Timeout for auto-probe connections (default: 5)",
    )
    parser.add_argument(
        "--cache-file",
        default="strategy_cache.json",
        metavar="PATH",
        help="Strategy cache file (default: strategy_cache.json)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose (DEBUG) logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)-8s] %(message)s",
        datefmt="%H:%M:%S",
    )

    config = Config(
        host=args.host,
        port=args.port,
        strategy=args.strategy,
        fragment_size=args.fragment_size,
        fragment_delay=args.fragment_delay,
        probe_timeout=args.probe_timeout,
        cache_file=args.cache_file,
        verbose=args.verbose,
    )

    proxy = BypassProxy(args.host, args.port, config)

    print(f"  LocalBypass v0.1")
    print(f"  Listening : http://{args.host}:{args.port}")
    print(f"  Strategy  : {args.strategy}")
    print(f"  Configure your browser/system to use HTTP proxy {args.host}:{args.port}")
    print(f"  Press Ctrl+C to stop.")
    print()

    try:
        proxy.start()
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
