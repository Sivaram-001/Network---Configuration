import os
import hashlib
import uuid
from pathlib import Path
from typing import Dict, Any
from backend.app.config import UPLOAD_DIR

class StorageManager:
    """
    Abstractions for local file storage, hashing, and access checks.
    """
    def __init__(self, upload_dir: str = UPLOAD_DIR):
        self.upload_dir = Path(upload_dir)
        os.makedirs(self.upload_dir, exist_ok=True)
        # Create reports subfolder
        os.makedirs(self.upload_dir / "reports", exist_ok=True)

    def save_file(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """
        Saves a config file to disk, computing size and SHA256 signature.
        """
        content_str = file_content.decode("utf-8", errors="replace")
        sha256_hash = hashlib.sha256(file_content).hexdigest()
        
        # Save file with unique ID in name to prevent naming collisions
        file_id = str(uuid.uuid4())
        safe_filename = f"{file_id}_{filename}"
        file_path = self.upload_dir / safe_filename
        
        with open(file_path, "wb") as f:
            f.write(file_content)
            
        return {
            "id": file_id,
            "filename": filename,
            "file_path": str(file_path),
            "file_size": len(file_content),
            "sha256": sha256_hash,
            "content": content_str
        }

    def read_file(self, file_path: str) -> str:
        """
        Reads string content of a saved file.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found at path: {file_path}")
            
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    def get_report_path(self, review_id: str, extension: str) -> str:
        """
        Generates structured download path for PDF or Markdown reports.
        """
        filename = f"{review_id}_report.{extension.strip('.')}"
        return str(self.upload_dir / "reports" / filename)

storage_manager = StorageManager()
