# from __future__ import division
from datetime import datetime, timedelta
from colorlog import ColoredFormatter
from platform import system as system_name # Returns the system/OS name
from os import system as system_call       # Execute a shell command
import socket
import struct
import psutil
import os
import sys
import logging
import logging.handlers
import traceback
import netifaces
import re

__author__ = 'sbertelli'


def totimestamp(dt, epoch=datetime(1970, 1, 1)):
    td = dt - epoch
    # return td.total_seconds()
    return (td.microseconds + (td.seconds + td.days * 86400) * 10**6) / 10**6


def get_logging(script__file__, verbose=False, level=logging.INFO, log_directory=None):
    """
    Returns a log facility storing data into the default log directory
    :param script__file__: put here __file__ variable from your script
    :return: the log facility to be used in your script
    """

    if log_directory is None:
        # Configure the default logging directory client/log/...
        log_directory = os.path.dirname(script__file__)

    log = logging.getLogger()
    log_file = os.path.join(log_directory, '{}.log'.format(os.path.basename(script__file__)))
    file_handler = logging.handlers.TimedRotatingFileHandler(
        log_file, when='midnight', interval=1, backupCount=7,
    )

    formatter = logging.Formatter('%(asctime)s [%(module)s.%(funcName)s](%(lineno)d)-%(levelname)s: %(message)s')
    file_handler.setFormatter(formatter)
    log.addHandler(file_handler)

    if verbose:
        formatter = ColoredFormatter(
            "%(asctime)s %(log_color)s%(levelname)-8s%(reset)s [%(module)s.%(funcName)s] %(white)s%(message)s",
            datefmt=None,
            reset=True,
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red',
            }
        )
        shell_handler = logging.StreamHandler(stream=sys.stdout)
        shell_handler.setFormatter(formatter)
        log.addHandler(shell_handler)

        log.setLevel(level)
        log.info("Verbosity level: {}".format(level))

    return log


def log_error(exception=None):
    log = logging.getLogger()

    (_type, value, tb) = sys.exc_info()
    tblast = traceback.format_tb(tb, limit=None)

    traceback.print_tb(tb)

    if exception is not None:
        log.error("Error: " + exception.__str__())

    if len(tblast):
        log.error("An error occurred, traceback follows:")
        log.error(tblast)

    # (_type, value, tb) = sys.exc_info()
    # tblast = traceback.extract_tb(tb, limit=None)
    #
    # if len(tblast):
    #     log.error("An error occurred, traceback follows:")
    #     log.error(tblast)


def get_processes():
    """
    Retrieve an array containing details about the running processes
    :rtype : dict
    :return: List of tuples with (pid, command_line)
    """
    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
    processes = dict()
    for pid in pids:
        try:
            # Get command line
            command = open(os.path.join('/proc', pid, 'cmdline'), 'rb').read()

            # Get status description and clean result
            status = open(os.path.join('/proc', pid, 'status'), 'rb').read()
            status_lines = status.split("\n")

            # Create dictionary with all the values retrieved
            process_details = dict()

            for l in status_lines:
                l_array = l.split(":")
                if len(l_array) > 1:
                    text = str(l_array[1])

                    # Add detail to dictionary
                    process_details[l_array[0]] = text.replace("\t","")

            # Add details to processes dictionary
            processes[int(pid)] = process_details

        except IOError:
            continue

    return processes


def get_open_files(process_pid):
    """
    Return a tuple (process, symlink, file) with the open files for the given process
    :param process_pid: process pid to look for open files list
    :return: None on error, list of open files for current process on success (process, symlink, file)
    """
    try:
        proc_fd_links = os.listdir("/proc/{}/fd".format(process_pid))
    except Exception as e:
        log_error(e)
        print("Error Occurred")
        return None

    proc_files = []
    for filelink in proc_fd_links:
        try:
            linked_file = os.readlink("/proc/{}/fd/{}".format(process_pid,filelink))
        except OSError:
            linked_file = None

        proc_files.append(
            (process_pid,
             filelink,
             linked_file))
    return proc_files


def get_all_open_files():
    all_processes = get_processes()
    pids = all_processes.keys()
    files_list = list()
    for p in pids:
        process_files = get_open_files(p)
        if process_files is not None:
            files_list.extend(process_files)
    return files_list


def get_mac_address(ifname):
    """
    Returns the mac address of the specified interface
    :param ifname: String name of the network interface (ex. eth0)
    :return: String value of the MAC address for the given interface
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])


def get_cpu_usage():
    """
    Returns current cpu percent utilization
    :return: CPU utilization percentage
    """
    return psutil.cpu_percent(interval=1)


def get_memory_usage():
    """
    Current memory utilization
    :return: Current memory utilization in megabytes
    """
    return psutil.phymem_usage().total/1024/1024


def ascii_to_hex_repr(string, width=40):
    """
    Returns a string with the hex representation of each character of the given string value
    :param string: Input string containing the byte values to be converted
    :return: string containing the hex representation
    """
    result = '[XX]'
    for cols in range(0, min(width,len(string))):
        result += " {:02}".format(cols)

    result += "\n[00]"
    cnt = 0

    for x in string:
        if (cnt % width) == 0 and cnt > 1:
            result += "\n[{:02}]".format(cnt)

        result += " {}".format(format(x, '02x'))
        cnt += 1

    return result


def hex_log(string, width=40):
    result = '\n[XX]'
    for cols in range(0, min(width,len(string))):
        result += " {:02}".format(cols)

    result += "\n[00]"
    cnt = 0

    for x in string:
        if (cnt % width) == 0 and cnt > 1:
            result += "\n[{:02}]".format(cnt)

        result += " {}".format(format(x, '02x'))
        cnt += 1
    return result


def get_interface_ip(if_name):
    """
        Retrieves mac address and ip address from the given interface name
        :param if_name:
        :return: (mac, ip) Returns a tuple with the interface details
        """
    interfaces = netifaces.interfaces()
    mac = None
    ip = None

    if if_name not in interfaces:
        raise Exception('Unable to locate interface {}'.format(if_name))

    try:
        address = netifaces.ifaddresses(if_name)
    except Exception as ex:
        log_error(ex)
        return
    try:
        if netifaces.AF_INET in address:
            ip = address[netifaces.AF_INET][0]['addr']
    except Exception as ex:
        log_error(ex)
        return

    return ip


def get_interface_details(if_name):
    """
    Retrieves mac address and ip address from the given interface name
    :param if_name:
    :return: (mac, ip) Returns a tuple with the interface details
    """
    interfaces = netifaces.interfaces()
    mac = None
    ip = None

    if if_name not in interfaces:
        raise Exception('Unable to locate interface {}'.format(if_name))

    try:
        address = netifaces.ifaddresses(if_name)
    except Exception as ex:
        log_error(ex)
        return None, None

    try:
        if netifaces.AF_LINK in address:
            mac = address[netifaces.AF_LINK][0]['addr']
    except Exception as ex:
        log_error(ex)
        return None, None

    try:
        if netifaces.AF_INET in address:
            ip = address[netifaces.AF_INET][0]['addr']
    except Exception as ex:
        log_error(ex)

    return mac, ip


def get_gateway():
    """
    Retrieves the currently configured gateway address, None in case of failure
    :return: Address of the current gateway
    """
    try:
        gw = netifaces.gateways()
        return gw['default'][netifaces.AF_INET][0]
    except Exception as ex:
        log_error(ex)
        return None


def get_host_id():
    """
    Returns the current host id calculated from the local network mac address
    :return: string containing the current host id
    """
    # Available interfaces
    available_ifaces = netifaces.interfaces()
    available_ifaces = [item for item in available_ifaces if item == 'eth0']

    # There are no interfaces, quitting application
    if len(available_ifaces) == 0:
        return False

    # Using the first interface available for mac address
    return get_interface_details(available_ifaces[0])[0].replace(":", "-")


def ping(host):
    """
    Returns True if host (str) responds to a ping request.
    Remember that some hosts may not respond to a ping request even if the host name is valid.
    """

    # Ping parameters as function of OS
    parameters = "-n 1" if system_name().lower() == "windows" else "-c 1"

    # Pinging
    return system_call("ping " + parameters + " " + host) == 0


def get_uptime():
    r = os.popen("awk '{print $0/60;}' /proc/uptime").read().replace('\n','')
    return float(r)

def get_client_datetime():
    return datetime.now().isoformat()

def get_kites():
    kites = []
    pagekite_rows = os.popen("cat /etc/pagekite.d/10_default.rc").read().split('\n')
    for row in pagekite_rows:
        result = re.search('^service_on=[a-zA-Z]*-([0-9]*):([a-zA-Z0-9\.]*):[a-zA-Z0-9]*:[0-9]*:[a-zA-Z0-9\-]*$', row)
        if (result):
            kites.append("{}:{}".format(result.group(2),result.group(1)))
    return kites