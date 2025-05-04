#!/usr/bin/env python3
"""
This script accepts command-line arguments and passes them to a function in handle_commands module.
"""

import sys
import handle_commands

def main():
    """
    Parse command-line arguments and call the function bchoc from handle_commands module.
    """
    handle_commands.bchoc(sys.argv[1:])
    sys.exit(0)

if __name__ == '__main__':
    main()