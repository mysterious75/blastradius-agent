"""python -m blastradius.api — start the REST API on :8001."""

import argparse

import uvicorn


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="blastradius-api")
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args(argv)

    from blastradius.api.server import app

    uvicorn.run(app, host=args.host, port=args.port, reload=args.reload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
