#!/usr/bin/env python3
# Copyright 2026 DNS Events contributors
# SPDX-License-Identifier: Apache-2.0
"""Backport https://github.com/boostorg/mpl/pull/77 (Boost Software License 1.0)."""
import pathlib
import sys
p = pathlib.Path(sys.argv[1]) / "libraries/cmake/source/boost/src/libs/mpl/include/boost/mpl/aux_/integral_wrapper.hpp"
old = "#if BOOST_WORKAROUND(__EDG_VERSION__, <= 243)"
new = old + " || __cplusplus >= 201103L"
s = p.read_text()
if new not in s:
    if s.count(old) != 1:
        raise SystemExit("Unexpected Boost MPL header; refusing blind patch")
    p.write_text(s.replace(old, new))
