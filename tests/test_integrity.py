
# Importojme funksionet per gjenerimin e celesave RSA
from core.rsa_manager import generate_rsa_key_pair

# Importojme funksionin per nenshkrimin e dokumentit
from core.digital_signer import sign_document

# Importojme funksionin per verifikimin e nenshkrimit
from core.signature_verifier import verify_signature


# Testojme verifikimin e dokumentit origjinal
def test_verify_original_document(tmp_path):
    # Percaktojme lokacionet e celesave RSA
    private_key_path = tmp_path / "private_key.pem"
    public_key_path = tmp_path / "public_key.pem"

    # Percaktojme fjalekalimin e celesit privat
    password = "TestPassword123!"

    # Gjenerojme celesin privat dhe publik
    generate_rsa_key_pair(
        private_key_path,
        public_key_path,
        password,
    )

    # Krijojme dokumentin origjinal
    document_path = tmp_path / "document.txt"
    document_path.write_text(
        "SIGIL Digital Signature Application",
        encoding="utf-8",
    )

    # Krijojme nenshkrimin digjital
    signature_path = tmp_path / "signature.sig"
    sign_document(
        document_path,
        private_key_path,
        password,
        signature_path,
    )

    # Verifikojme nenshkrimin e dokumentit origjinal
    result = verify_signature(
        document_path,
        signature_path,
        public_key_path,
    )

    # Dokumenti origjinal duhet te verifikohet me sukses
    assert result is True


# Testojme zbulimin e ndryshimeve ne dokument
def test_detect_modified_document(tmp_path):
    # Percaktojme lokacionet e celesave RSA
    private_key_path = tmp_path / "private_key.pem"
    public_key_path = tmp_path / "public_key.pem"

    # Percaktojme fjalekalimin e celesit privat
    password = "TestPassword123!"

    # Gjenerojme celesin privat dhe publik
    generate_rsa_key_pair(
        private_key_path,
        public_key_path,
        password,
    )

    # Krijojme dokumentin origjinal
    document_path = tmp_path / "document.txt"
    document_path.write_text(
        "SIGIL Digital Signature Application",
        encoding="utf-8",
    )

    # Nenshkruajme dokumentin origjinal
    signature_path = tmp_path / "signature.sig"
    sign_document(
        document_path,
        private_key_path,
        password,
        signature_path,
    )

    # Ndryshojme permbajtjen e dokumentit pas nenshkrimit
    document_path.write_text(
        "SIGIL Modified Document",
        encoding="utf-8",
    )

    # Provojme te verifikojme dokumentin e ndryshuar
    result = verify_signature(
        document_path,
        signature_path,
        public_key_path,
    )

    # Verifikimi duhet te deshtoje sepse dokumenti eshte ndryshuar
    assert result is False
