
#Importojme modulin RSA per me kontrollu llojin e celesave qe kemi kriju
from cryptography.hazmat.primitives.asymmetric import rsa

#Impotojme funksionet qe kemi me i testu prej file;rsa_manager.py
from core.rsa_manager import (
    generate_rsa_key_pair,
    load_private_key,
    load_public_key,
)

#Testojme gjenerimin edhe ngarkimin e celesave RSA
def test_generate_and_load_rsa_keys(tmp_path):

    #Tash percaktojme lokacionin e celesit privat
    private_path = tmp_path / "private_key.pem"

    #Vazhdojme edhe me percaktimin e celesit publik
    public_path = tmp_path / "public_key.pem"

    #Percaktojme tash fjalekalimin per mbrojtjen e celesit private
    password = "TestPassword123!"

    #E therrasim funksionin per gjenerimin dhe ruajtjen e celesave RSA
    generate_rsa_key_pair(
        private_path,
        public_path,
        password,
    )

    #E ngarkojme celesin private duke perdor fjalekalimin perkates
    private_key = load_private_key(private_path, password)

    #E ngarkojme edhe celesin publik nga file perkates
    public_key = load_public_key(public_path)

    #Kontrollojme nese celesi private eshte i tipit RSA private key
    assert isinstance(private_key, rsa.RSAPrivateKey)

    #Kontrollojme nese celesi publik eshte i tipit RSA public key
    assert isinstance(public_key, rsa.RSAPublicKey)

    #Kontrollojme nese madhesia e celesit private eshte 3072 bit
    assert private_key.key_size == 3072

    #Kontrollojme nese madhesia e celesit publik eshte 3072 bit
    assert public_key.key_size == 3072


#E testojme nese celesi private refuzohet kur perdoret fjalekalimi i gabuar
def test_private_key_requires_correct_password(tmp_path):

    #Percaktojme lokacionin e celesit privat
    private_path = tmp_path / "private_key.pem"

    #Tash percaktojme edhe loakcionin e celesit publik
    public_path = tmp_path / "public_key.pem"

    #Gjenerojme celesat RSA duke perdor fjalekalimin e sakte
    generate_rsa_key_pair(
        private_path,
        public_path,
        "CorrectPassword123!",
    )

    #E provojme ngarkimin e celesit private me nje fjalekalim te gabuar
    try:
        load_private_key(private_path, "WrongPassword123!")

        #Nese celesi ngarkohet pa gabim, testi duhet te deshtoje
        assert False, "An incorrect password should not load the private key."

    #Presim qe python te gjeneroje ValueError ose TypeError
    #sepse fjalekalimi i perdor nuk eshte i sakte
    except (ValueError, TypeError):
        pass
