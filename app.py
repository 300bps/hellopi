#!/usr/bin/env python3
# Hello Pi
# A program to identify the ip address of Raspberry Pis added to the local area network.
#
# David Smith
# 4/11/21
# License: MIT

import logging
import os


# ** Module configuration constants **
APP_NAME = "Hello Pi"
APP_VERSION = "0.1"

LOG_FILENAME = APP_NAME + ".log"
LOG_RECORD_FILTER_LEVEL = logging.INFO  # Log/propagate log records >= this level


# ** Module objects/variables **
# Local logger for this module
logger = logging.getLogger(__name__)



def main(argv=None):
    """
    Application main routine.
    :param argv: List of command-line arguments or None.
    :return: None
    """
    # Initialize logging functionality
    ver_str = f"(Version {APP_VERSION:s})"
    logging.basicConfig(filename=os.path.join(os.path.dirname(os.path.abspath(__file__)), LOG_FILENAME), level=logging.INFO, format="%(asctime)s   [%(module)12.12s:%(lineno)4s] %(levelname)-8s %(message)s", filemode='w')
    logging.info(APP_NAME + " " + ver_str)

    print(APP_NAME)
    print(ver_str+"\n")

    # Your Code Here



# Ensure that the software is run in the expected way - through the run.py script
if __name__ == "__main__":
    print("To run this software, execute 'python run.py'.")
