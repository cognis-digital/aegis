import os
import json
import logging
from typing import Dict, List, Any
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class CredentialInventory:
    def __init__(self, config_path: str = "config/credential_inventory.json"):
        self.config_path = config_path
        self.credentials: Dict[str, Dict[str, Any]] = {}
        self._load_config()

    def _load_config(self):
        """Load existing credential inventory from config file."""
        if os.path.exists(self.config_path):
            with open(self.config_path, "r") as f:
                try:
                    self.credentials = json.load(f)
                except json.JSONDecodeError as e:
                    logging.error(f"Failed to decode JSON in {self.config_path}: {e}")
                    self.credentials = {}

    def _save_config(self):
        """Save the current credential inventory to config file."""
        with open(self.config_path, "w") as f:
            json.dump(self.credentials, f, indent=4)
        logging.info(f"Saved credential inventory to {self.config_path}")

    def add_credential(self, name: str, type: str, value: str, source: str = "unknown", notes: str = ""):
        """Add a new credential entry to the inventory."""
        if name not in self.credentials:
            self.credentials[name] = {
                "type": type,
                "value": value,
                "source": source,
                "notes": notes,
                "last_seen": datetime.now().isoformat()
            }
            logging.info(f"Added credential '{name}' of type '{type}' from source '{source}'")
        else:
            logging.warning(f"Credential '{name}' already exists in inventory")

    def list_credentials(self):
        """List all credentials in the inventory."""
        if not self.credentials:
            logging.info("No credentials found in inventory.")
            return

        for name, cred in self.credentials.items():
            logging.info(f"Name: {name}")
            logging.info(f"  Type: {cred['type']}")
            logging.info(f"  Value: {cred['value'][:20]}... (truncated)")
            logging.info(f"  Source: {cred['source']}")
            logging.info(f"  Notes: {cred['notes']}")
            logging.info(f"  Last Seen: {cred['last_seen']}")
            logging.info("-" * 40)

    def find_credentials_by_type(self, credential_type: str) -> List[Dict[str, Any]]:
        """Find credentials by type."""
        return [cred for cred in self.credentials.values() if cred.get("type") == credential_type]

    def find_credentials_by_source(self, source: str) -> List[Dict[str, Any]]:
        """Find credentials by source."""
        return [cred for cred in self.credentials.values() if cred.get("source") == source]

def main():
    # Example usage
    inventory = CredentialInventory()
    inventory.add_credential("db_admin", "database", "admin_user:secret123", "config_file", "Database admin credentials")
    inventory.add_credential("api_key", "api", "1234567890abcdef", "codebase", "API key for service endpoint")
    inventory.add_credential("s3_access", "storage", "AKIAXXXXXXXXXXXXXX", "infrastructure", "S3 bucket access key")

    logging.info("Credential Inventory Report:")
    inventory.list_credentials()

if __name__ == "__main__":
    main()