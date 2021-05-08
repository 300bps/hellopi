#!/usr/bin/env python3
# Hello Pi
# A program to identify the ip address of Raspberry Pis (or other devices) added to the local area network.
#
# David Smith
# 4/11/21
# License: MIT

import errno
import datetime as dt
import logging
import os
import socket
import sys
import traceback

import ipxray.packet as ipxray



# ** Module configuration constants **
APP_NAME = "Hello Pi"
APP_VERSION = "1.0"

LOG_ENABLE_LOGGING = False
LOG_FILENAME = APP_NAME.replace(" ", "_").lower() + ".log"
LOG_LEVEL = logging.INFO

# The organizationally unique ids (OUI) for Raspberry Pis (first 3 bytes of the MAC address)
RASPBERRY_PI_MAC_OUIS = [bytes.fromhex("b827eb"), bytes.fromhex("dca632"), bytes.fromhex("e45f01")]

# Identify the current OS platform
OS_PLATFORM = sys.platform


# ** Module objects/variables **
logger = logging.getLogger(__name__)            # Local logger for this module
logger.addHandler(logging.NullHandler())        # Add a local null handler (eats messages when logging disabled)
logger.propagate = False                        # Prevent log messages from propagating further up than this level.

if LOG_ENABLE_LOGGING:
    # Configure the logger, log file, level, and format
    logging.basicConfig(filename=os.path.join(os.path.dirname(os.path.abspath(__file__)), LOG_FILENAME), level=LOG_LEVEL,
                        format="%(asctime)s   [%(module)12.12s:%(lineno)4s] %(levelname)-8s %(message)s", filemode='w')

# Command-line arguments
cmdline_args_dict = {'-a': False, '-h': False, '-q': False, '-v': False}

show_all_devices = False                    # When True, show all devices - not just RPIs
verbose_output = False                      # When True, additional info is output
windows_platform = "win32" in OS_PLATFORM   # True when on Windows; False otherwise



def format_time(datetime_obj: dt.datetime) -> str:
    """
    Apply simple formatting to display the time from a datetime.datetime object.
    :param datetime_obj: datetime.datetime object to use as time to display
    :return: A time string formatted such as "1:27.03 AM"
    """
    if not isinstance(datetime_obj, dt.datetime):
        raise TypeError("TypeError: datetime.datetime object required.")

    # Note: Windows doesn't support the -I formatter, so must use I for cross-platform
    return datetime_obj.strftime("%I:%M.%S %p")


def open_socket():
    """
    Open a raw socket in promiscuous mode to receive all LAN packets.
    :return: A raw socket in promiscuous mode
    """
    # socket.
    ETH_P_ALL = 0x0003      # Receive all layer 3 protocols
    ETH_P_IP = 0x0800       # Receive only ip layer 3 protocol


    if "win32" in OS_PLATFORM:
        # NOTE: On windows, firewall rules apply to raw sockets (unlike linux). Must add a windows firewall ALLOW rule
        # with the following characteristics:
        # WINDOWS FIREWALL ALLOW rule: Name->DHCP Server Port; Protocol->UDP; Local port->67; Remote port->68;
        # Local IP Address: 255.255.255.255; Remote IP Address: 0.0.0.0

        # Windows: Create raw socket
        # AF_INET DOES NOT BYPASS WINDOWS FIREWALL, so port of interest must be opened in the firewall
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

        except OSError as ex:
            # Permissions error under Windows
            if ex.errno == errno.WSAEACCES:
                if verbose_output:
                    msg = "Error: Program must be run with administrator privileges to open a raw socket."
                else:
                    msg = "Error: Program must be run with administrator privileges."
                print(msg)
                logger.error(msg)

            else:
                msg = "Error attempting to open raw socket: " + str(ex)
                print(msg)
                logger.error(msg)

            sys.exit(-1)

        # Socket calls are blocking - using a short timeout is required to keep responsive to user ctrl-C on Windows
        sock.settimeout(1)

        # Bind raw socket to ip broadcast address
        sock.bind(("255.255.255.255", 0))

        # # [Windows specific] Include IP headers
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # [Windows specific] receive all packages
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    elif "darwin" in OS_PLATFORM:
        # Mac OSX: Create raw socket
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))

        except PermissionError:
            if verbose_output:
                msg = ("Error: Program must be run with administrator privileges (via sudo or as root) " +
                       "to open a raw socket.")
            else:
                msg = "Error: Program must be run with administrator privileges (via sudo or as root)."

            print(msg)
            logger.error(msg)
            sys.exit(-1)

        except Exception as ex:
            msg = "Error attempting to open raw socket: " + str(ex)
            print(msg)
            logger.error(msg)
            sys.exit(-1)

        # Socket calls are blocking, but ctrl-C on seems to interrupt them without requiring a socket timeout
        # and therefore doesn't seem to need the following line.
        # sock.settimeout(1)

    else:
        # *nix: Create raw socket
        # AF_PACKET for raw socket access bypasses iptables, so packet can be read without opening the firewall port
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))

        except PermissionError:
            if verbose_output:
                msg = ("Error: Program must be run with administrator privileges (via sudo or as root) " +
                       "to open a raw socket.")
            else:
                msg = "Error: Program must be run with administrator privileges (via sudo or as root)."

            print(msg)
            logger.error(msg)
            sys.exit(-1)

        except Exception as ex:
            msg = "Error attempting to open raw socket: " + str(ex)
            print(msg)
            logger.error(msg)
            sys.exit(-1)

        # Socket calls are blocking, but ctrl-C on *nix seems to interrupt them without requiring a socket timeout
        # and therefore doesn't seem to need the following line.
        # sock.settimeout(1)

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


def show_hello(p: ipxray.INETPacket, dhcp: ipxray.DHCPPacket, is_rpi: bool = True, verbose: bool = False):
    """
    Display formatted 'hello' message.
    :param p: INETPacket
    :param dhcp: DHCPPacket
    :param is_rpi: True-device is an RPi; False-device is not an RPi
    :param verbose: True-provide more details; False-provide terse output
    :return:
    """
    verbose_ip = f"[IP Address {p.ip.format_ip_addr(dhcp.requested_ip)}]"
    verbose_common = f"{format_time(dt.datetime.now())} | {verbose_ip:<28} "

    terse_common = f"{p.ip.format_ip_addr(dhcp.requested_ip)+' ':<16}"

    if is_rpi:
        if verbose:
            hello_msg = (verbose_common +
                        f"- Raspberry Pi '{dhcp.hostname}' "
                        f"({ipxray.ENETPacket.format_mac_addr(dhcp.client_hw_address)}) said \"Hello!\"")

        else:
            hello_msg = terse_common + f"- Raspberry Pi '{dhcp.hostname}' said \"Hello!\""

    else:
        if verbose:
            hello_msg = (verbose_common + f"- Device '{dhcp.hostname}' "
            f"({ipxray.ENETPacket.format_mac_addr(dhcp.client_hw_address)}) said \"Hello!\"")

        else:
            hello_msg = terse_common + f"- Device '{dhcp.hostname}' said \"Hello!\""

    print(hello_msg)
    logger.info(hello_msg)


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
    print("While running, this utility monitors the local area network (LAN) for DHCP requests and reports the ip "
          "address of any Raspberry Pi that powers-up connected to the LAN.")
    print()
    print("OPTIONS:")
    print("  -a\tDisplay ALL devices (not just RPis) making a DHCP request for an ip address.")
    print("  -h\tDisplay this help message.")
    print("  -q\tQuiet the program startup information.")
    print("  -v\tDisplay verbose messages.")


def main():
    """
    Application main routine.
    :return: None
    """
    global cmdline_args_dict
    global show_all_devices
    global verbose_output

    try:
        # Command-line arguments
        argv = sys.argv

        ver_str = f"(Version {APP_VERSION:s})"
        logging.info(APP_NAME + " " + ver_str)
        if argv and len(argv) > 1:
            logging.info("Command line arguments: " + " ".join(argv[1:]))

        # Decipher command-line options and update
        cmdline_args_dict = cmdline_options(argv, cmdline_args_dict)

        # Cmdline arg: '-h' = Display help
        if cmdline_args_dict.get('-h', False):
            show_help()
            sys.exit(0)

        # Cmdline arg: '-a' = Display all device (not just RPis) DHCP requests
        if cmdline_args_dict.get('-a', False):
            show_all_devices = True

        # Cmdline arg: '-v' = Use verbose output statements
        if cmdline_args_dict.get('-v', False):
            verbose_output = True

        # Cmdline arg: '-q' = Quiet - suppress unnecessary output
        if not cmdline_args_dict.get('-q', False):
            # Print app identifying info and status
            print(APP_NAME)

            if verbose_output:
                # Verbose version
                if show_all_devices:
                    msg = "Watching LAN for 'Hello' messages from all devices."
                    msg += "\nPower-up a connected device to see its ip address."
                else:
                    msg = "Watching LAN for 'Hello' messages from Raspberry Pis."
                    msg += "\nPower-up a connected Raspberry Pi to see its ip address."

                print(msg)

            else:
                # Regular version
                if show_all_devices:
                    print("Watching LAN for 'Hello' messages from all devices.")
                else:
                    print("Watching LAN for 'Hello' messages from Raspberry Pis.")

            print()


        # Reusable packet buffer
        packet_buffer = bytearray(2*4096)

        # Open the socket and look for desired packet
        sock = open_socket()

        try:
            while True:
                try:
                    # Listen for packets (blocking call)
                    packet_size = sock.recv_into(packet_buffer)

                except socket.timeout:
                    packet_size = None

                if not packet_size:
                    continue

                # Attempt to decode the packet
                if windows_platform:
                    # Win sockets return ip protocol (layer 3)
                    p = ipxray.INETPacket(ip_packet=packet_buffer)

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
                        # If OUI is in RPi Foundation OUIs, then device is a RPi
                        is_rpi = dhcp.client_hw_address[0:3] in RASPBERRY_PI_MAC_OUIS

                        if is_rpi or show_all_devices:
                            show_hello(p, dhcp, is_rpi=is_rpi, verbose=verbose_output)

        finally:
            # Close the socket when exiting
            if sock:
                close_socket(sock)

    except KeyboardInterrupt:
        sys.exit(0)

    except Exception as ex:
        print("Exception: ", ex)
        print(traceback.format_exc())
        logger.exception("Unhandled Exception:")
        sys.exit(-1)



if __name__ == "__main__":
    main()
