#!/usr/bin/env python

import pandas as pd
import sys

df = pd.read_parquet(sys.argv[1])
if len(df) != 4:
    print("Expected 4 rows, got %d" % len(df))
    sys.exit(1)

sys.exit(0)
