#!/usr/bin/env python3
"""Write a deterministic, harmless 16 MiB wheel fixture for the profiling example."""
import argparse
import zipfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("output", help="output wheel path")
args = parser.parse_args()
payload = (b"A" * 4096 + b"\0") * 4095 + b"\0HTTPS://example.invalid/webhook\0"
with zipfile.ZipFile(args.output, "w", compression=zipfile.ZIP_DEFLATED) as wheel:
    wheel.writestr("demo/payload.bin", payload)
    wheel.writestr("demo-1.0.dist-info/METADATA", "Name: demo\nVersion: 1.0\n")
    wheel.writestr("demo-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\n")
