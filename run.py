#!/usr/bin/env python3
# Hello Pi
# A program to identify the ip address of Raspberry Pis added to the local area network.
#
# David Smith
# 4/11/21
# License: MIT

# NOTE:
# Using this 'run' stub module to import and run the main module ensures that the main module only gets loaded into
# sys.modules once.  Otherwise, it could be loaded one time as '__main__' and a second time by its real name if it is
# imported by other modules.

import app


def execute():
    """
    Primary program entry point.
    :return: None
    """
    # Run the app
    app.main()


if __name__ == "__main__":
    execute()
