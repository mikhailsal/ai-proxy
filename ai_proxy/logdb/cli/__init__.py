import sys
from typing import Optional, List

from .parsers import build_parser
from .commands import cmd_init

# Explicitly re-export cmd_init so test suites can access it as
# `ai_proxy.logdb.cli.cmd_init` without triggering unused-import lint errors.
__all__ = ["build_parser", "cmd_init"]


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
