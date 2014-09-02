# -*- coding: utf-8 -*-

import core
import argparse
import sys

import platform
if platform.architecture()[0] != "32bit":
    print "This program must run in 32-bit mode!"
    sys.exit(0)

# enable call stack tracing
sys.tracebacklimit = 1

# parse arguments
parser = argparse.ArgumentParser()
parser.add_argument("-p", metavar='PID',
                    type=int,
                    help="Specifies the decimal process ID to be debugged.")
parser.add_argument("path_to_exe", metavar='path', nargs="?",
                    help="Specifies the program path to be debugged.")

if len(sys.argv) > 1:
    args = parser.parse_args()
else:
    parser.print_help()
    exit(0)

debugger = core.Debugger()

if args.p != None:
    debugger.attach(args.p)
    debugger.detach()
else:
    debugger.load(args.path_to_exe)
    debugger.start_debug()


