#Fillojme me importu Path per menaxhimin e lokacioneve dhe file
from pathlib import Path

#I importojme modulet per algoritmin RSA dhe padding-un PSS
from cryptography.hazmat.primitives.asymmetric import padding

#Tash importojme algoritmin SHA-256
from cryptography.hazmat.primitives import hashes

#Importojme funksionin per ngarkimin e celesit privat
from core.rsa_manager import load_private_key


#Funksioni per nenshkrimin digjital te nje dokumenti
def sign_document(
        document_path: str | Path,
        private_key_path: str | Path,
        password: str,
        signature_path: str | Path,
) -> Path:
    """E krijon nenshkrimin digjital te nje dokumenti duke perdorur RSA-PSS dhe SHA-256."""

    #Krijojme objektin Path per lokacionin e dokumentit 
    document = Path(document_path)

    #Lexojme permbajtjen e dokumentit ne forme bytes
    document_data = document.read_bytes()

    #Ngarkojme celesin privat RSA duke perdor fjalekalimin
    private_key = load_private_key(private_key_path, password)

    #krijojme nenshkrimin digjital duke perdor RSA-PSS edhe SHA-256
    signature = private_key.sign(
        document_data,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),

    )

    #Tash krijojme objektin e radhes pra Path per lokacionin e nenshkrimit
    signature_file = Path(signature_path)

    #E krijojme folderin perkates nese nuk ekziston
    signature_file.parent.mkdir(parents=True, exist_ok=True)

    #E ruajme nenshkrimin digjital ne file
    signature_file.write_bytes(signature)

    #E kthejme lokacionin e file te nenshkrimit 
    return signature_file