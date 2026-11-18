
# Importojme hashlib per llogaritjen e hash-it SHA-256
import hashlib

# Importojme Path per menaxhimin e fajllave
from pathlib import Path


# Funksioni per gjenerimin e hash-it SHA-256 nga te dhenat
def calculate_sha256(data: bytes) -> str:
    """Llogarit hash-in SHA-256 dhe e kthen ne format hexadecimal."""

    # Krijojme hash-in SHA-256 nga te dhenat e pranuara
    sha256_hash = hashlib.sha256(data)

    # Kthejme hash-in ne format hexadecimal
    return sha256_hash.hexdigest()


# Funksioni per gjenerimin e hash-it SHA-256 nga nje dokument
def calculate_file_sha256(file_path: str | Path) -> str:
    """Llogarit hash-in SHA-256 te nje dokumenti."""

    # Lexojme permbajtjen e dokumentit ne forme bytes
    file_data = Path(file_path).read_bytes()

    # Llogarisim dhe kthejme hash-in SHA-256
    return calculate_sha256(file_data)


# Funksioni per krahasimin e dy hash-eve
def compare_hashes(original_hash: str, current_hash: str) -> bool:
    """Kontrollon nese dy hash-e jane identike."""

    # Kthejme True nese hash-et perputhen, perndryshe False
    return original_hash == current_hash
