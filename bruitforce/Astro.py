#!/usr/bin/python3
import sys
import os
from os import path
import time
import socket
import urllib.request, urllib.parse, urllib.error
import atexit
import requests
from pathlib import Path
import json
import subprocess
from flask import Flask, jsonify, request
from pyspark.sql import SparkSession
from pyspark.sql.types import StructType, StructField, StringType, ArrayType, MapType
from datetime import datetime
from urllib.parse import urlparse
import re
import argparse
import threading
import logging
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress insecure HTTPS warnings
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

# Flask app initialization
app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Define schema for Spark DataFrame
scan_schema = StructType([
    StructField("target", StringType(), True),
    StructField("timestamp", StringType(), True),
    StructField("port_scan", ArrayType(
        StructType([
            StructField("port", StringType(), True),
            StructField("service", StringType(), True),
            StructField("state", StringType(), True)
        ])
    ), True),
    StructField("sqlmap_scan", MapType(StringType(), StringType()), True),
    StructField("hydra_scan", MapType(StringType(), StringType()), True),
    StructField("sensitive_data", ArrayType(
        StructType([
            StructField("type", StringType(), True),
            StructField("match", StringType(), True),
            StructField("location", StringType(), True)
        ])
    ), True),
    StructField("gitleaks_scan", MapType(StringType(), StringType()), True)
])

# Constants
VERSION = "4.0"
RESULTS_DIR = "security_results"
WORDLISTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists")

class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    ENDC = '\033[0m'

def print_logo():
    logo = """
            ..',,,'..            
         .',;;;;;;;;,'.          
      ..,;;;;;;;;;;;;;;,..       
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
|   Author - Jasraj Choudhary   |
| Enhanced Security Framework   |
|_______________________________|
"""
    print(f"{Colors.BLUE}{logo}{Colors.ENDC}")

class SecurityScanner:
    def __init__(self):
        self.spark = SparkSession.builder \
            .appName("SecurityAnalytics") \
            .config("spark.driver.memory", "4g") \
            .config("spark.executor.memory", "4g") \
            .getOrCreate()
        self.results = {
            "target": None,
            "timestamp": None,
            "port_scan": [],
            "sqlmap_scan": {},
            "hydra_scan": {},
            "sensitive_data": [],
            "gitleaks_scan": {}
        }
        self.ensure_directories()
        
    def ensure_directories(self):
        os.makedirs(RESULTS_DIR, exist_ok=True)
        os.makedirs(WORDLISTS_DIR, exist_ok=True)
        os.makedirs("sqlmap_results", exist_ok=True)

    def parse_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            parsed = urlparse(url)
            if not parsed.netloc:{}
        except Exception as e:
            raise ValueError(f"URL parsing error: {str(e)}")

    def perform_port_scan(self, target):
        domain, _ = self.parse_url(target)
        results = []
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            80: "HTTP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-ALT"
        }
        
        logger.info(f"Scanning ports for domain: {domain}")
        
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((domain, port))
                if result == 0:
                    results.append({
                        "port": str(port),
                        "service": service,
                        "state": "open"
                    })
                    logger.info(f"Port {port} ({service}) is open")
                sock.close()
            except Exception as e:
                logger.error(f"Error scanning port {port}: {str(e)}")
        
        return results

    def run_sqlmap(self, target, level=1):
        try:
            command = [
                "sqlmap",
                "-u", target,
                "--batch",
                "--random-agent",
                f"--level={level}",
                "--risk=1",
                "--threads=4",
                "--output-dir=sqlmap_results"
            ]
            logger.info(f"Running SQLMap scan: {' '.join(command)}")
            
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, error = process.communicate()
            
            return {
                "output": output.decode() if output else "",
                "error": error.decode() if error else "",
                "command": " ".join(command)
            }
        except Exception as e:
            return {"error": f"SQLMap scan error: {str(e)}"}

    def run_hydra_scan(self, target, service_type):
        try:
            domain, path = self.parse_url(target)
            
            if not os.path.exists(os.path.join(WORDLISTS_DIR, "usernames.txt")):
                with open(os.path.join(WORDLISTS_DIR, "usernames.txt"), 'w') as f:
                    f.write("admin\nroot\nuser\n")
                    
            if not os.path.exists(os.path.join(WORDLISTS_DIR, "passwords.txt")):
                with open(os.path.join(WORDLISTS_DIR, "passwords.txt"), 'w') as f:
                    f.write("password\nadmin123\n12345678\n")
            
            base_command = [
                "hydra",
                "-L", f"{WORDLISTS_DIR}/usernames.txt",
                "-P", f"{WORDLISTS_DIR}/passwords.txt"
            ]
            
            if service_type.upper() == "HTTP-POST":
                command = base_command + [
                    domain,
                    "http-post-form",
                    f"{path}:username=^USER^&password=^PASS^:F=Login failed"
                ]
            elif service_type.upper() == "HTTP-GET":
                command = base_command + [
                    domain,
                    "http-get",
                    path
                ]
            elif service_type.upper() in ["SSH", "FTP", "MYSQL"]:
                command = base_command + [domain, service_type.lower()]
            else:
                raise ValueError(f"Unsupported service type: {service_type}")
            
            logger.info(f"Running Hydra command: {' '.join(command)}")
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, error = process.communicate()
            
            return {
                "command": " ".join(command),
                "output": output.decode() if output else "",
                "error": error.decode() if error else ""
            }
        except Exception as e:
            return {"error": f"Hydra scan error: {str(e)}"}

    def check_sensitive_data(self, target):
        try:
            response = requests.get(target, verify=False, timeout=10)
            findings = []
            
            patterns = {
                "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                "credit_card": r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
                "api_key": r"(?i)(api[_-]?key|api[_-]?token|access[_-]?token)['\"]?\s*[:=]\s*['\"]?\w+['\"]?",
                "private_key": r"-----BEGIN [A-Z]+ PRIVATE KEY-----",
                "password_field": r"(?i)password['\"]?\s*[:=]\s*['\"]?\w+['\"]?"
            }
            
            for pattern_name, pattern in patterns.items():
                matches = re.finditer(pattern, response.text)
                for match in matches:
                    findings.append({
                        "type": pattern_name,
                        "match": match.group()[:20] + "..." if len(match.group()) > 20 else match.group(),
                        "location": f"Found at position {match.start()}"
                    })
            
            return findings
        except Exception as e:
            return [{"type": "error", "match": str(e), "location": "N/A"}]

    def run_gitleaks_scan(self, repo_url):
        try:
            command = [
                "gitleaks",
                "detect",
                "-v",
                "-r", repo_url,
                "--report-format=json"
            ]
            
            logger.info(f"Running Gitleaks scan: {' '.join(command)}")
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, error = process.communicate()
            
            return {
                "command": " ".join(command),
                "output": output.decode() if output else "",
                "error": error.decode() if error else ""
            }
        except Exception as e:
            return {"error": f"Gitleaks scan error: {str(e)}"}

    def save_results(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{RESULTS_DIR}/security_scan_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        
        logger.info(f"Results saved to {filename}")
        
        try:
            # Convert results to row format for Spark
            row_data = [self.results]
            df = self.spark.createDataFrame(row_data, schema=scan_schema)
            df.write.mode("append").json(f"{RESULTS_DIR}/spark_results")
            logger.info("Results saved to Spark storage")
            
            # Perform basic analysis
            self.analyze_results()
        except Exception as e:
            logger.error(f"Error saving to Spark: {str(e)}")

    def analyze_results(self):
        try:
            df = self.spark.read.schema(scan_schema).json(f"{RESULTS_DIR}/spark_results")
            
            # Basic analysis
            total_scans = df.count()
            logger.info(f"Total scans performed: {total_scans}")
            
            # Analyze port scan results
            if df.select("port_scan").first()[0] is not None:
                port_stats = df.select("port_scan.*").summary()
                logger.info("Port scan statistics completed")
            
            # Analyze vulnerability findings
            if df.select("sensitive_data").first()[0] is not None:
                vuln_stats = df.select("sensitive_data.*").groupBy("type").count()
                logger.info("Vulnerability statistics completed")
                
        except Exception as e:
            logger.error(f"Analysis error: {str(e)}")

def main():
    print_logo()
    scanner = SecurityScanner()
    
    target = input(f"{Colors.BLUE}[*] Enter target URL or IP address: {Colors.ENDC}").strip()
    
    print(f"{Colors.BLUE}[*] Select scan options:{Colors.ENDC}")
    print("1. Port Scan")
    print("2. SQLMap Scan")
    print("3. Hydra Brute Force")
    print("4. Sensitive Data Check")
    print("5. Gitleaks Scan")
    print("6. All Scans")
    
    choice = input(f"{Colors.BLUE}[*] Enter your choice (1-6): {Colors.ENDC}")
    
    scanner.results['target'] = target
    scanner.results['timestamp'] = datetime.now().isoformat()
    
    try:
        if choice in ['1', '6']:
            print(f"{Colors.BLUE}[*] Running port scan...{Colors.ENDC}")
            scanner.results['port_scan'] = scanner.perform_port_scan(target)
            
        if choice in ['2', '6']:
            print(f"{Colors.BLUE}[*] Running SQLMap scan...{Colors.ENDC}")
            scanner.results['sqlmap_scan'] = scanner.run_sqlmap(target)
            
        if choice in ['3', '6']:
            print(f"{Colors.BLUE}[*] Running Hydra scan...{Colors.ENDC}")
            print(f"{Colors.BLUE}[*] Available services: HTTP-POST, HTTP-GET, SSH, FTP, MYSQL{Colors.ENDC}")
            service = input(f"{Colors.BLUE}[*] Enter service type: {Colors.ENDC}")
            scanner.results['hydra_scan'] = scanner.run_hydra_scan(target, service)
            
        if choice in ['4', '6']:
            print(f"{Colors.BLUE}[*] Checking for sensitive data...{Colors.ENDC}")
            scanner.results['sensitive_data'] = scanner.check_sensitive_data(target)
            
        if choice in ['5', '6']:
            print(f"{Colors.BLUE}[*] Running Gitleaks scan...{Colors.ENDC}")
            repo_url = input(f"{Colors.BLUE}[*] Enter repository URL: {Colors.ENDC}")
            scanner.results['gitleaks_scan'] = scanner.run_gitleaks_scan(repo_url)
        
        scanner.save_results()
        print(f"{Colors.GREEN}[+] Scan completed. Results saved in {RESULTS_DIR}{Colors.ENDC}")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[-] Scan interrupted by user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[-] An error occurred: {str(e)}{Colors.ENDC}")
        sys.exit(1)
    finally:
        scanner.spark.stop()
        
# API Routes
@app.route('/scan', methods=['POST'])
def api_scan():
    try:
        data = request.get_json()
        if not data or 'target' not in data:
            return jsonify({'error': 'Target URL is required'}), 400
            
        target = data['target']
        scan_types = data.get('scan_types', ['port_scan'])  # Default to port scan
        
        scanner = SecurityScanner()
        scanner.results['target'] = target
        scanner.results['timestamp'] = datetime.now().isoformat()
        
        # Perform requested scans
        if 'port_scan' in scan_types:
            scanner.results['port_scan'] = scanner.perform_port_scan(target)
            
        if 'sqlmap' in scan_types:
            scanner.results['sqlmap_scan'] = scanner.run_sqlmap(target)
            
        if 'hydra' in scan_types:
            service_type = data.get('service_type', 'HTTP-GET')
            scanner.results['hydra_scan'] = scanner.run_hydra_scan(target, service_type)
            
        if 'sensitive_data' in scan_types:
            scanner.results['sensitive_data'] = scanner.check_sensitive_data(target)
            
        if 'gitleaks' in scan_types:
            repo_url = data.get('repo_url')
            if repo_url:
                scanner.results['gitleaks_scan'] = scanner.run_gitleaks_scan(repo_url)
        
        # Save results
        scanner.save_results()
        
        return jsonify({
            'status': 'success',
            'results': scanner.results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        scanner.spark.stop()

@app.route('/results', methods=['GET'])
def get_results():
    try:
        # Get list of all result files
        result_files = []
        for file in os.listdir(RESULTS_DIR):
            if file.endswith('.json'):
                with open(os.path.join(RESULTS_DIR, file), 'r') as f:
                    result_files.append({
                        'filename': file,
                        'data': json.load(f)
                    })
        
        return jsonify({
            'status': 'success',
            'count': len(result_files),
            'results': result_files
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/results/<filename>', methods=['GET'])
def get_result_by_filename(filename):
    try:
        file_path = os.path.join(RESULTS_DIR, filename)
        if not os.path.exists(file_path):
            return jsonify({'error': 'Result file not found'}), 404
            
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        return jsonify({
            'status': 'success',
            'filename': filename,
            'data': data
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Enhanced Security Testing Framework')
    parser.add_argument('--api', action='store_true', help='Run as API server')
    parser.add_argument('--port', type=int, default=5000, help='Port for API server')
    parser.add_argument('--host', default='0.0.0.0', help='Host for API server')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    try:
        if args.api:
            print(f"{Colors.GREEN}[+] Starting API server on {args.host}:{args.port}{Colors.ENDC}")
            app.run(host=args.host, port=args.port)
        else:
            main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[-] Program terminated by user{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}[-] An error occurred: {str(e)}{Colors.ENDC}")                            