#E importojme Path per menaxhimin e lokacioneve dhe file
from pathlib import Path

#E importojme modulet per algoritmin RSA dhe padding-un PSS
from cryptography.hazmat.primitives.asymmetric import padding

#Tash fillojme me importimin e algoritmit SHA-256
from cryptography.hazmat.primitives import hashes

#E importojme gabimin qe paraqitet kur nenshkrimi nuk eshte valid
from cryptography.exceptions import InvalidSignature

#Importojme funksionin per ngarkimin e celesit publik RSA
from core.rsa_manager import load_public_key


#Funksioni per verifikimin e nenshkrimit digjital te dokumentit
def verify_signature(
        document_path: str | Path,
        signature_path: str | Path,
        public_key_path: str | Path,
) -> bool:
    """Verifikon nenshkrimin digjital duke perdore RSA-PSS dhe SHA-256."""

    # Lexojme permbajtjen e dokumentit ne forme bytes
    document_data = Path(document_path).read_bytes()

    # Lexojme nenshkrimin digjital nga fajlli perkates
    signature_data = Path(signature_path).read_bytes()

    # Ngarkojme celesin publik RSA
    public_key = load_public_key(public_key_path)

    try:
        # Verifikojme nenshkrimin me celesin publik, RSA-PSS dhe SHA-256
        public_key.verify(
            signature_data,
            document_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        # Kthejme True nese nenshkrimi eshte valid
        return True

    except InvalidSignature:
        # Kthejme False nese dokumenti ose nenshkrimi nuk perputhet
        return False
