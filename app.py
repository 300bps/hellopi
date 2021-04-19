#!/usr/bin/env python3
# Hello Pi
# A program to identify the ip address of Raspberry Pis added to the local area network.
#
# David Smith
# 4/11/21
# License: MIT

import datetime as dt
import logging
import os
import socket
import sys
import traceback

import ipxray.packet as ipxray



# ** Module configuration constants **
APP_NAME = "Hello Pi"
APP_VERSION = "0.1"

LOG_FILENAME = APP_NAME.replace(" ", "_") + ".log"
LOG_RECORD_FILTER_LEVEL = logging.INFO  # Log/propagate log records >= this level

# The organizationally unique ids (OUI) for Raspberry Pis (first 3 bytes of the MAC address)
# RASPBERRY_PI_MAC_OUIS = [bytes.fromhex("b827eb"), bytes.fromhex("dca632"), bytes.fromhex("e45f01")]
RASPBERRY_PI_MAC_OUIS = [bytes.fromhex("5cf5da"), bytes.fromhex("347c25")]

# Identify the current OS platform
OS_PLATFORM = sys.platform


# ** Module objects/variables **
# Local logger for this module
logger = logging.getLogger(__name__)

# Command-line arguments
cmdline_args_dict = {'-h': False, '-a': False, '-v': False}

show_all_devices = False                    # When True, show all devices - not just RPIs
verbose_output = False                      # When True, additional info is output
windows_platform = "win32" in OS_PLATFORM   # True when on Windows; False otherwise



def format_time(datetime: dt.datetime) -> str:
    """
    Apply simple formatting to display the time from a datetime.datetime object.
    :param datetime: datetime.datetime object to use as time to display
    :return: A time string formatted such as "1:27.03 AM"
    """
    if not isinstance(datetime, dt.datetime):
        raise TypeError("TypeError: datetime.datetime object required.")

    return datetime.strftime("%-I:%M.%S %p")


def open_socket():
    """
    Open a raw socket in promiscuous mode to receive all LAN packets.
    :return: A raw socket in promiscuous mode
    """
    # socket.
    ETH_P_ALL = 0x0003      # Receive all layer 3 protocols
    ETH_P_IP = 0x0800       # Receive only ip layer 3 protocol


    if "win32" in OS_PLATFORM:
        # Windows
        print("Win")

        # Create raw socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

        # TODO: REMOVE DEBUG LINE AND FIND WHY CTRL-C DOESN'T TERMINATE
        sock.settimeout(30)

        # Bind raw socket to ip broadcast address
        sock.bind(("255.255.255.255", 0))

        # [Windows specific] Include IP headers
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # [Windows specific] receive all packages
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    elif "darwin" in OS_PLATFORM:
        # Mac OSX
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))

    else:
        # *nix
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))

    return sock


def close_socket(sock: socket.socket):
    if "win32" in OS_PLATFORM:
        # Windows
        # Take socket out of promisc mode
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

        # Shutdown and close the socket
        # sock.shutdown(socket.SHUT_RDWR)
        sock.close()

    else:
        # Shutdown and close the socket
        sock.close()


def show_hello(p, dhcp, is_rpi=True, verbose=False):
    if is_rpi:
        if verbose:
            print(f"{format_time(dt.datetime.now())} | [IP Address {p.ip.format_ip_addr(dhcp.requested_ip)}] "
                  f"- Raspberry Pi '{dhcp.hostname}' ({p.enet.format_mac_addr(p.enet.src_mac)}) said \"Hello!\"")

        else:
            print(f"{p.ip.format_ip_addr(dhcp.requested_ip)}: Raspberry Pi '{dhcp.hostname}' said \"Hello!\"")

    else:
        print(f"{p.ip.format_ip_addr(dhcp.requested_ip)}: Device '{dhcp.hostname}' said \"Hello!\"")


def cmdline_options(argv: list, arg_dict: dict):
    """
    Parse command line arguments passed via 'argv'.
    :param argv: The list of command-line arguments as produced by sys.argv
    :param arg_dict: Dictionary of valid command-line argument entries of type {str: bool}.
    :return: arg_dict with args specified in argv True and unspecified args False
    """
    if len(argv) > 1:
        # Loop through options - skipping item 0 which is the name of the script
        for arg in argv[1:]:
            # Indicate which expected args that have been passed
            if arg in arg_dict:
                arg_dict[arg] = True

    return arg_dict



def show_help():
    print(APP_NAME, f"(v{APP_VERSION:s})")
    print("--------")
    print("This utility watches the local area network (LAN) for DHCP requests and reports the ip address of any "
          "Raspberry Pi that boots up connected to the same LAN. On Windows, option '-a' is always applied due to "
          "the inability to access the raw ethernet frame."
          )
    print("OPTIONS:")
    print("  -a\tDisplay ALL connected devices (not just RPis) that make a DHCP request for an ip address.")
    print("  -h\tDisplay this help message.")
    print("  -v\tDisplay verbose messages.")


def main(argv=None):
    """
    Application main routine.
    :param argv: List of command-line arguments or None.
    :return: None
    """
    global cmdline_args_dict
    global show_all_devices
    global verbose_output

    try:
        # Initialize logging functionality
        ver_str = f"(Version {APP_VERSION:s})"
        logging.basicConfig(filename=os.path.join(os.path.dirname(os.path.abspath(__file__)), LOG_FILENAME), level=logging.INFO, format="%(asctime)s   [%(module)12.12s:%(lineno)4s] %(levelname)-8s %(message)s", filemode='w')
        logging.info(APP_NAME + " " + ver_str)


        # Decipher command-line options and update
        cmdline_args_dict = cmdline_options(argv, cmdline_args_dict)

        # Cmdline arg: '-h' = Display help
        if cmdline_args_dict.get('-h', False):
            show_help()
            sys.exit(0)

        # Cmdline arg: '-a' = Display all device (not just RPis) DHCP requests
        if cmdline_args_dict.get('-a', False):
            show_all_devices = True

        # Windows always applies '-a' option
        elif windows_platform:
            show_all_devices = True

        # Cmdline arg: '-v' = Use verbose output statements
        if cmdline_args_dict.get('-v', False):
            verbose_output = True


        # Print initial info
        print(APP_NAME)
        if windows_platform:
            print("(Note: Windows always applies the '-a' option.)")

        if cmdline_args_dict.get("-v", False):
            # Verbose version
            if show_all_devices:
                msg = "Watching LAN for 'Hello' messages from all devices."
            else:
                msg = "Watching LAN for 'Hello' messages from Raspberry Pis."

            msg += " Power up a connected Raspberry Pi to see its ip address."
            print(msg)

        else:
            # Regular version
            if show_all_devices:
                print("Watching LAN for 'Hello' messages from all devices.")
            else:
                print("Watching LAN for 'Hello' messages from Raspberry Pis.")

        print()


        # Reuseable packet buffer
        packet_buffer = bytearray(2*4096)

        # Open the socket and look for desired packet
        sock = open_socket()
        try:
            while True:
                # Listen for packets
                packet_size = sock.recv_into(packet_buffer)
                if not packet_size:
                    continue

                # Attempt to decode the packet
                if windows_platform:
                    # Win sockets return ip protocol (layer 3)
                    # NOTE: Without layer 2, we can't get the MAC address to test the OUI to see if device is a RPi.
                    # The utility automatically applies the '-a' option to show all devices on Windows as a result.
                    p = ipxray.INETPacket(ip_packet=packet_buffer)
                    # $$$ TODO: Following line is debug
                    if p.udp and not p.udp.dst_port == 22 and not p.udp.src_port == 22:
                        print(p)

                else:
                    # *nix sockets return ethernet protocol (layer 2)
                    p = ipxray.INETPacket(enet_packet=packet_buffer)

                # Looking for DHCP messages being sent to DHCP server ...
                if p.udp and p.udp.dst_port == 67:

                    # Attempt to interpret DHCP packet
                    dhcp = ipxray.DHCPPacket(p.udp.payload)
                    if not dhcp.is_dhcp:
                        continue

                    # DHCP request message found
                    if dhcp.message_type == dhcp.OptionMessageType.DHCPRequest:
                        if windows_platform:
                            # Windows must treat everything as not RPi since it doesn't have access to MAC address
                            show_hello(p, dhcp, is_rpi=False, verbose=verbose_output)

                        else:
                            # If OUI is in RPi foundation OUIs, then it is a RPi
                            is_rpi = p.enet.src_mac[0:3] in RASPBERRY_PI_MAC_OUIS

                            if is_rpi or show_all_devices:
                                show_hello(p, dhcp, is_rpi=is_rpi, verbose=verbose_output)

        finally:
            # Close the socket when exiting
            if sock:
                close_socket(sock)

    except KeyboardInterrupt:
        sys.exit(0)

    except Exception as ex:
        # TODO: Clean up this
        print("Exception: ", ex)
        print(traceback.format_exc())
        logger.exception("Unhandled Exception:")
        sys.exit(-1)

    finally:
        # Handle any shutdown cleanup
        pass


# Ensure that the software is run in the expected way - through the run.py script
if __name__ == "__main__":
    print("To run this software, execute 'python run.py'.")
