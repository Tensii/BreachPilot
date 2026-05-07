import logging
import threading
from pathlib import Path

FILE_APPEND_LOCK = threading.Lock()

def setup_logger(name: str, log_file: Path | None = None, level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    
    # File handler
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        
    return logger

def append_to_file(file_path: Path, content: str):
    with FILE_APPEND_LOCK:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(content + "\n")
