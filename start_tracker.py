#
# Copyright (C) 2026 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course.
#
# StreapRous release
#
# The authors hereby grant to Licensee personal permission to use
# and modify the Licensed Source Code for the sole purpose of studying
# while attending the course
#

"""
start_tracker
~~~~~~~~~~~~~

Entry point for launching the P2P tracker server powered by StreapRous.
"""

import argparse

from apps.tracker_app import create_tracker_app

DEFAULT_IP = "0.0.0.0"
DEFAULT_PORT = 8000


def main():
    """Parse CLI arguments and launch the tracker application."""
    parser = argparse.ArgumentParser(
        prog="Tracker",
        description="Start the StreapRous P2P tracker daemon",
    )
    parser.add_argument(
        "--server-ip",
        type=str,
        default=DEFAULT_IP,
        help=f"IP address to bind the server (default: {DEFAULT_IP})",
    )
    parser.add_argument(
        "--server-port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Port number to bind the server (default: {DEFAULT_PORT})",
    )

    args = parser.parse_args()
    create_tracker_app(args.server_ip, args.server_port)


if __name__ == "__main__":
    main()
