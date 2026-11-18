
# Importojme Path per menaxhimin e lokacioneve dhe fajllave
from pathlib import Path

# Importojme modulet per serializimin dhe gjenerimin e celesave RSA
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# Funksioni per gjenerimin dhe ruajtjen e celesave RSA
def generate_rsa_key_pair(
    private_key_path: str | Path,  # Lokacioni ku do te ruhet celesi privat
    public_key_path: str | Path,   # Lokacioni ku do te ruhet celesi publik
    password: str,                 # Fjalekalimi per mbrojtjen e celesit privat
):
    """Gjeneron dhe ruan celesin privat te enkriptuar dhe celesin publik."""

    # Kontrollojme nese fjalekalimi eshte bosh ose permban vetem hapesira
    if not password or not password.strip():
        raise ValueError("Password cannot be empty.")

    # Krijojme objektet Path per lokacionet e celesave
    private_path = Path(private_key_path)
    public_path = Path(public_key_path)

    # Kontrollojme nese ndonjeri nga fajllat ekziston paraprakisht
    if private_path.exists() or public_path.exists():
        raise FileExistsError("One or both key files already exist.")

    # Gjenerojme celesin privat RSA me madhesi 3072 bit
    # public_exponent 65537 eshte vlere standarde per RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )

    # Pergatisim celesin privat per ruajtje dhe e mbrojme me fjalekalim
    encrypted_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,  # Formati i ruajtjes PEM
        format=serialization.PrivateFormat.PKCS8,  # Formati i celesit privat
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")  # E kthejme fjalekalimin ne bytes
        ),
    )

    # Nxjerrim celesin publik nga celesi privat
    public_key = private_key.public_key()

    # Pergatisim celesin publik per ruajtje ne formatin PEM
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Krijojme folderat e nevojshem nese nuk ekzistojne
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    # Ruajme celesin privat te enkriptuar ne fajll
    private_path.write_bytes(encrypted_private_key)

    # Ruajme celesin publik ne fajll
    public_path.write_bytes(public_key_bytes)

    # Kthejme lokacionet e dy celesave te krijuar
    return private_path, public_path


# Funksioni per ngarkimin e celesit privat nga fajlli
def load_private_key(
    private_key_path: str | Path,  # Lokacioni i celesit privat
    password: str,                 # Fjalekalimi per deshifrimin e tij
):
    """Ngarkon celesin privat te enkriptuar."""

    # Lexojme permbajtjen e fajllit te celesit privat ne bytes
    private_key_data = Path(private_key_path).read_bytes()

    # Ngarkojme celesin privat duke perdorur fjalekalimin perkates
    return serialization.load_pem_private_key(
        private_key_data,
        password=password.encode("utf-8"),
    )


# Funksioni per ngarkimin e celesit publik nga fajlli
def load_public_key(public_key_path: str | Path):
    """Ngarkon celesin publik."""

    # Lexojme permbajtjen e fajllit te celesit publik ne bytes
    public_key_data = Path(public_key_path).read_bytes()

    # Ngarkojme dhe kthejme celesin publik ne program
    return serialization.load_pem_public_key(public_key_data)
