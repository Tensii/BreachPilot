import requests
from pathlib import Path
from ..utils.network import get_stealth_headers
from ..utils.logger import setup_logger

logger = setup_logger("cloud_mapper")

class CloudMapper:
    def __init__(self, target: str):
        self.target = target
        self.found_buckets = []

    def generate_permutations(self) -> list[str]:
        """Generates common bucket name permutations based on target."""
        base = self.target.split('.')[0]
        suffixes = [
            "prod", "dev", "staging", "test", "data", "backup", 
            "assets", "static", "logs", "archive", "public", "private",
            "sql", "db", "files", "docs", "internal"
        ]
        perms = [base]
        for s in suffixes:
            perms.append(f"{base}-{s}")
            perms.append(f"{base}.{s}")
            perms.append(f"{s}-{base}")
            perms.append(f"{s}.{base}")
        return list(set(perms))

    def check_s3_bucket(self, bucket_name: str) -> bool:
        """Checks if an S3 bucket exists and is accessible."""
        url = f"https://{bucket_name}.s3.amazonaws.com"
        try:
            # We use stealth headers to avoid being blocked by simple ACLs
            response = requests.head(url, headers=get_stealth_headers(), timeout=5)
            if response.status_code in [200, 403]: # 403 means it exists but is private
                return True
        except Exception:
            pass
        return False

    def scan(self) -> list[str]:
        """Main entry point for cloud scanning."""
        logger.info(f"Starting cloud bucket discovery for {self.target}")
        permutations = self.generate_permutations()
        
        for name in permutations:
            if self.check_s3_bucket(name):
                logger.info(f"Found S3 Bucket: {name}")
                self.found_buckets.append(f"s3://{name}")
                
        return self.found_buckets
