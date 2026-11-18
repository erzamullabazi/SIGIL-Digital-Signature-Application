
# Importojme funksionet qe do t'i testojme nga moduli sha256_engine.py
from core.sha256_engine import (
    calculate_sha256,
    calculate_file_sha256,
    compare_hashes,
)


# Testojme funksionin per llogaritjen e hash-it SHA-256 nga te dhenat
def test_calculate_sha256():

    # Percaktojme te dhenat qe do te perdoren per gjenerimin e hash-it
    data = b"SIGIL Digital Signature Application"

    # Gjenerojme hash-in SHA-256 nga te dhenat e percaktuara
    result = calculate_sha256(data)

    # Kontrollojme nese hash-i ka 64 karaktere hexadecimal
    assert len(result) == 64

    # Verifikojme nese te njejtat te dhena gjenerojne gjithmone te njejtin hash
    assert result == calculate_sha256(data)


# Testojme funksionin per llogaritjen e hash-it SHA-256 nga nje fajll
def test_calculate_file_sha256(tmp_path):

    # Krijojme nje fajll testues brenda folderit te perkohshem
    document = tmp_path / "document.txt"

    # Shkruajme permbajtjen ne fajll duke perdorur kodimin UTF-8
    document.write_text("SIGIL original document", encoding="utf-8")

    # Gjenerojme hash-in SHA-256 nga permbajtja e fajllit
    result = calculate_file_sha256(document)

    # Kontrollojme nese hash-i i gjeneruar ka 64 karaktere hexadecimal
    assert len(result) == 64

    # Krahasojme hash-in e fajllit me hash-in e te njejtave te dhena
    assert result == calculate_sha256(
        b"SIGIL original document"
    )


# Testojme funksionin per krahasimin e dy hash-eve
def test_compare_hashes():

    # Gjenerojme hash-in e dokumentit origjinal
    original_hash = calculate_sha256(b"Original document")

    # Gjenerojme hash-in e te njejtit dokument per krahasim
    same_hash = calculate_sha256(b"Original document")

    # Gjenerojme hash-in e nje dokumenti me permbajtje te ndryshuar
    changed_hash = calculate_sha256(b"Modified document")

    # Kontrollojme nese dy hash-et e dokumentit origjinal perputhen
    assert compare_hashes(original_hash, same_hash) is True

    # Kontrollojme nese ndryshimi i dokumentit identifikohet nga hash-i
    assert compare_hashes(original_hash, changed_hash) is False
