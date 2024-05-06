#!/usr/bin/env python

import pandas as pd
import sys

def expect_eq(got, want):
    if got != want:
        print(f"Expected {want}, got {got}")
        sys.exit(1)

df = pd.read_parquet(sys.argv[1])
expect_eq(len(df), 4)

# Strings should be stored correctly and decode as binary strings (not UTF-8).
expect_eq(df.to_dict()["text"][0], b"Hello, world!")
expect_eq(df.to_dict()["text"][3], b"Good bye, world!")

# Check that numbers are encoded correctly.
expect_eq(df.to_dict()["big_number"][2], 0xcafed00d)

print("[OK] - example parquet file is valid")
sys.exit(0)
