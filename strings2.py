#!/usr/bin/env python

import angr
import logging
import sys

if len(sys.argv) != 2:
    print("Usage: python strings2.py <file>")
    exit(1)

# sensible logging
logging.getLogger("angr.sim_manager").setLevel(logging.INFO)

# Options
filename = sys.argv[1]
use_libs = False

p = angr.Project(filename, auto_load_libs=use_libs)

cfg = p.analyses.CFGFast(show_progressbar=True)

state = p.factory.entry_state()
simgr = p.factory.simgr(state)

s = simgr.active[0]

#-----------------------------

# Reversing showed that "flag" should be printed at some point
simgr.explore(find=lambda s: len(s.posix.dumps(1)) > 0 and
                            b"flag" in s.posix.dumps(1) or 
                            b"Flag" in s.posix.dumps(1) or 
                            b"FLAG" in s.posix.dumps(1))

if len(simgr.found) > 0:
    print("Possible flag found")
    print(simgr.found[0].posix.dumps(0))
    print(simgr.found[0].posix.dumps(1))
    print(simgr.found[0].posix.dumps(2))
else:
    print("No match")
