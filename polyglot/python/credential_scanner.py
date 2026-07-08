import os
import re
from typing import List, Dict, Any
from collections import defaultdict
import logging
import json
import subprocess
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class CredentialScanner:
    def __init__(self, root_dir: str = '.', ignore_patterns: List[str] = None):
        self.root_dir = root_dir
        self.ignore_patterns = ignore_patterns or []
        self.credentials_found: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.file_count = 0
        self.line_count = 0

    def scan(self) -> Dict[str, List[Dict[str, Any]]]:
        """Scan the directory for credentials using various methods."""
        self._scan_files()
        self._scan_env_vars()
        self._scan_config_files()
        self._scan_git_credentials()
        return dict(self.credentials_found)

    def _scan_files(self):
        """Scan all files in the root directory for credential patterns."""
        for root, dirs, files in os.walk(self.root_dir):
            for file in files:
                if any(pattern in file for pattern in self.ignore_patterns):
                    continue
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        self._analyze_file_content(content, file_path)
                    self.file_count += 1
                    self.line_count += len(content.splitlines())
                except Exception as e:
                    logging.warning(f"Error reading {file_path}: {str(e)}")

    def _analyze_file_content(self, content: str, file_path: str):
        """Analyze content for credential patterns."""
        if not content:
            return

        # Common credential patterns
        patterns = {
            'password': r'(?i)(password|pass|pwd)[\s=]+["\']?([^"\'\s,]+)["\']?',
            'token': r'(?i)(token|api_key|access_key)[\s=]+["\']?([^"\'\s,]+)["\']?',
            'secret': r'(?i)(secret|key)[\s=]+["\']?([^"\'\s,]+)["\']?',
            'username': r'(?i)(username|user)[\s=]+["\']?([^"\'\s,]+)["\']?',
            'database': r'(?i)(database|db)[\s=]+["\']?([^"\'\s,]+)["\']?',
            'url': r'(https?:\/\/[^"\'\s,]+)',
        }

        for pattern_name, pattern in patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                credential_type = pattern_name
                value = match.group(2) if pattern_name != 'url' else match.group(1)
                self._record_credential(file_path, credential_type, value)

    def _scan_env_vars(self):
        """Scan environment variables for credentials."""
        env_vars = os.environ.copy()
        for key, value in env_vars.items():
            if any(pattern in key.lower() for pattern in ['password', 'token', 'secret', 'key']):
                self._record_credential('env', 'env_var', f"{key}={value}")

    def _scan_config_files(self):
        """Scan common config files like .env, config.yaml, etc."""
        config_patterns = {
            '.env': r'([A-Z_]+)=([^"\'\s,]+)',
            'config.yaml': r'(?m)^(\w+):\s*["\']?([^"\'\s,]+)["\']?',
            'config.json': r'("[^"]+":\s*"([^"]+)")',
        }

        for config_type, pattern in config_patterns.items():
            config_path = os.path.join(self.root_dir, config_type)
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r', errors='ignore') as f:
                        content = f.read()
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            key = match.group(1) if pattern == '.env' else match.group(2)
                            value = match.group(2) if pattern == '.env' else match.group(1)
                            self._record_credential(config_path, 'config_file', f"{key}={value}")
                except Exception as e:
                    logging.warning(f"Error reading {config_path}: {str(e)}")

    def _scan_git_credentials(self):
        """Scan .git/config and .git/credentials for credentials."""
        git_config = os.path.join(self.root_dir, '.git', 'config')
        if os.path.exists(git_config):
            try:
                with open(git_config, 'r', errors='ignore') as f:
                    content = f.read()
                    matches = re.finditer(r'credential\.helper\s*=\s*([^"\'\s,]+)', content)
                    for match in matches:
                        self._record_credential(git_config, 'git_config', match.group(1))
            except Exception as e:
                logging.warning(f"Error reading {git_config}: {str(e)}")

        git_credentials = os.path.join(self.root_dir, '.git', 'credentials')
        if os.path.exists(git_credentials):
            try:
                with open(git_credentials, 'r', errors='ignore') as f:
                    content = f.read()
                    for line in content.splitlines():
                        if '=' in line:
                            key, value = line.split('=', 1)
                            self._record_credential(git_credentials, 'git_credentials', f"{key}={value}")
            except Exception as e:
                logging.warning(f"Error reading {git_credentials}: {str(e)}")

    def _record_credential(self, source: str, credential_type: str, value: str):
        """Record a found credential."""
        self.credentials_found[source].append({
            'timestamp': datetime.now().isoformat(),
            'source': source,
            'type': credential_type,
            'value': value
        })

    def to_json(self) -> str:
        """Convert findings to JSON format."""
        return json.dumps(self.credentials_found, indent=2)

def main():
    scanner = CredentialScanner(root_dir='./', ignore_patterns=['.git', '.venv', '__pycache__'])
    results = scanner.scan()
    if results:
        logging.info(f"Found {sum(len(v) for v in results.values())} credentials across {scanner.file_count} files.")
        logging.info("Credentials found:")
        for source, creds in results.items():
            for cred in creds:
                logging.info(f"  - {cred['type']}: {cred['value']} (Source: {source})")
    else:
        logging.info("No credentials found.")

if __name__ == "__main__":
    main()