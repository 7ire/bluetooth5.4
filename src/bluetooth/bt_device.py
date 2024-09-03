from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
import random

class BTDevice:
    def __init__(self, iocap = 4, bt_address=None):
        # Generazione della coppia di chiavi asimmetriche
        self.sK = ec.generate_private_key(ec.SECP256R1(), default_backend())  # Chiave privata
        self.pK = self.sK.public_key()  # Chiave pubblica

        # Estrazione delle coordinate (x, y) dalla chiave pubblica
        coordinate = self.pK.public_numbers()
        self.pK_x = coordinate.x  # Coordinata X
        self.pK_y = coordinate.y  # Coordinata Y

        # Attributi aggiuntivi, inizializzati a 'None' perché
        # valorizzati nelle fasi appropriate.
        self.IOCap = iocap  # Input/Output capacità del dispositivo
        self.dhkey = None   # Chiave Diffie-Hellman
        self.nonce = None   # Valore 128bits randomico per la commit-key

    # Assegna l'indirizzo Bluetooth. Se non fornito, genera un indirizzo casuale.
        if bt_address is None:
            self.address = self.generate_random_bt_address()
        else:
            self.address = bt_address

    def generate_random_bt_address(self):
        # Genera i primi 6 byte dell'indirizzo (XX:XX:XX:XX:XX:XX)
        bt_address_bytes = [random.randint(0, 255) for _ in range(6)]
        
        # Genera il byte più significativo (MSB) con i 7 bit più significativi impostati a 0
        # e il bit meno significativo a 1 per indicare un indirizzo casuale
        msb = random.randint(0, 127) * 2 + 1  # Imposta il bit meno significativo a 1
        
        # Aggiungi l'MSB all'inizio dell'indirizzo
        bt_address_bytes.insert(0, msb)
        
        # Converti in stringa formattata
        return ":".join(f"{byte:02X}" for byte in bt_address_bytes)


    def computeDHKey(self, remote_public_key):
        # Calcolo della chiave Diffie-Hellman utilizzando la chiave privata locale e la chiave pubblica remota
        self.dhkey = self.sK.exchange(ec.ECDH(), remote_public_key)

