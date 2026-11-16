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
start_peer
~~~~~~~~~~

Entry point for launching a hybrid P2P Peer Node with both a P2P TCP listener
and a StreapRous local Web API.
"""

import argparse

from apps.peer_app import create_peer_app

DEFAULT_WEB_IP = "0.0.0.0"
DEFAULT_WEB_PORT = 8081
DEFAULT_P2P_IP = "0.0.0.0"
DEFAULT_P2P_PORT = 9001
DEFAULT_TRACKER_URL = "http://127.0.0.1:8000"


def main():
    """Parse CLI arguments and start the P2P peer node."""
    parser = argparse.ArgumentParser(
        prog="PeerNode",
        description="Start a StreapRous hybrid P2P Peer Node",
    )
    parser.add_argument(
        "--web-ip",
        type=str,
        default=DEFAULT_WEB_IP,
        help=f"IP address for local Web UI/API (default: {DEFAULT_WEB_IP})",
    )
    parser.add_argument(
        "--web-port",
        type=int,
        default=DEFAULT_WEB_PORT,
        help=f"Port for local Web UI/API (default: {DEFAULT_WEB_PORT})",
    )
    parser.add_argument(
        "--p2p-ip",
        type=str,
        default=DEFAULT_P2P_IP,
        help=f"IP address for P2P TCP listener (default: {DEFAULT_P2P_IP})",
    )
    parser.add_argument(
        "--p2p-port",
        type=int,
        default=DEFAULT_P2P_PORT,
        help=f"Port for P2P TCP listener (default: {DEFAULT_P2P_PORT})",
    )
    parser.add_argument(
        "--tracker-url",
        type=str,
        default=DEFAULT_TRACKER_URL,
        help=f"Tracker server base URL (default: {DEFAULT_TRACKER_URL})",
    )

    args = parser.parse_args()
    create_peer_app(
        web_port=args.web_port,
        p2p_port=args.p2p_port,
        tracker_url=args.tracker_url,
        web_ip=args.web_ip,
        p2p_ip=args.p2p_ip,
    )


if __name__ == "__main__":
    main()
