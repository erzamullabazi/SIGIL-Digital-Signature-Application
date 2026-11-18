#E importojme Path per menaxhimin e file perseri
from pathlib import Path

#Tash radhen e ka importimi i funksionit per gjenerimin e celesave RSA
from core.rsa_manager import generate_rsa_key_pair
#Vazhdojme me importimin e funksionit per nenshkrimin digjital te dokumentit
from core.digital_signer import sign_document

#E testojme krijimin e nenshkrimit digjital te nje dokumenti
def test_sign_document(tmp_path):

 #Krijojme lokacionet e perkohshme per celesat RSA
 private_key_path = tmp_path / "private_key.pem"
 public_key_path = tmp_path / "public_key.pem"

 #E percaktojme fjalekalimin per mbrojtjen e celesit privat
 password = "TestPassword123!"

 #Gjenerojme celesin privat dhe publik RSA
 generate_rsa_key_pair(
  private_key_path,
  public_key_path,
  password,
 )

 #Krijojme nje dokument testues
 document_path = tmp_path / "document.txt"

 #E shkruajme permbajtjen e dokumentit testues
 document_path.write_text("SIGIL Digital Signature Application", encoding = "utf-8",
    )

 #E percaktojme lokacionin ku do te ruhet nenshkrimi
 signature_path = tmp_path / "signature.sig"

 #E krijojme nenshkrimin digjital duke perdore celesin private
 result = sign_document(
  document_path,
  private_key_path,
  password,
  signature_path,
 )

 #Kontrollojme nese funksioni kthen lokacionin e sakte
 assert result == signature_path

 #Kontrollojme nese file i nenshkrimit eshte kriju
 assert signature_path.exists()

 #Kontrollojme nese nenshkrimi permban te dhena
 assert signature_path.stat().st_size > 0

 #Kontrollojme nese dokumenti origjinal nuk eshte ndryshu
 assert document_path.read_text(encoding = "utf-8") == ("SIGIL Digital Signature Application"
)