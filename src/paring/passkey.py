import os
import random
import hashlib

# Funzione per generare un numero casuale a 128-bit
def generate_random_128_bit():
    return os.urandom(16)  # 16 bytes = 128 bits

# Funzione per simulare il calcolo della funzione c1
def c1(TK, rand, pairing_request, pairing_response, iat, ia, rat, ra):
    # Concatenate all parameters
    p1 = pairing_request + pairing_response + iat + ia
    p2 = rat + ra + rand
    
    # Calcolo dell'hash SHA-256 come esempio di funzione di compressione (in realtà, sarebbe AES-CMAC secondo le specifiche)
    return hashlib.sha256(TK + p1 + p2).digest()

# Funzione per calcolare la STK
def s1(TK, Srand, Mrand):
    # Concatenate TK, Srand and Mrand
    return hashlib.sha256(TK + Srand + Mrand).digest()

# Simulazione dei dispositivi che partecipano al pairing
class Device:
    def __init__(self, name, has_display=False, has_keyboard=False):
        self.name = name
        self.has_display = has_display
        self.has_keyboard = has_keyboard
        self.TK = None
        self.rand = None
        self.confirm = None
    
    def generate_TK(self):
        if self.has_display:
            self.TK = random.randint(0, 999999).to_bytes(6, 'big')
            print(f"{self.name} generated TK: {int.from_bytes(self.TK, 'big')}")
        else:
            self.TK = bytes(6)  # In un caso reale, sarebbe inserito manualmente via keyboard
    
    def generate_rand(self):
        self.rand = generate_random_128_bit()
    
    def calculate_confirm(self, pairing_request, pairing_response, iat, ia, rat, ra):
        self.confirm = c1(self.TK, self.rand, pairing_request, pairing_response, iat, ia, rat, ra)
    
    def verify_confirm(self, received_confirm, received_rand, pairing_request, pairing_response, iat, ia, rat, ra):
        calculated_confirm = c1(self.TK, received_rand, pairing_request, pairing_response, iat, ia, rat, ra)
        return calculated_confirm == received_confirm

# Simulazione del processo di pairing
def pairing_demo():
    # Crea due dispositivi
    initiator = Device("Initiator", has_display=True)
    responder = Device("Responder", has_keyboard=True)
    
    # Step 1: Generazione della TK
    initiator.generate_TK()
    responder.TK = initiator.TK  # Il responder inserisce la TK visualizzata
    
    # Step 2: Generazione di Mrand e Srand
    initiator.generate_rand()
    responder.generate_rand()
    
    # Pairing Request e Response simulati
    pairing_request = b'PAIR_REQ'
    pairing_response = b'PAIR_RSP'
    
    # Address type e indirizzi simulati
    iat = b'01'
    ia = b'INITIATOR_ADDR'
    rat = b'01'
    ra = b'RESPONDER_ADDR'
    
    # Step 3: Calcolo di Mconfirm e Sconfirm
    initiator.calculate_confirm(pairing_request, pairing_response, iat, ia, rat, ra)
    responder.calculate_confirm(pairing_request, pairing_response, iat, ia, rat, ra)
    
    # Step 4: Verifica delle conferme
    print(f"Initiator sends Mconfirm: {initiator.confirm.hex()}")
    print(f"Responder sends Sconfirm: {responder.confirm.hex()}")

    # Initiator verifica il Sconfirm ricevuto da Responder
    if responder.verify_confirm(initiator.confirm, initiator.rand, pairing_request, pairing_response, iat, ia, rat, ra):
        print("Responder verified Initiator's Mconfirm successfully.")
    else:
        print("Responder failed to verify Initiator's Mconfirm. Pairing failed.")
        return

    # Responder verifica il Mconfirm ricevuto da Initiator
    if initiator.verify_confirm(responder.confirm, responder.rand, pairing_request, pairing_response, iat, ia, rat, ra):
        print("Initiator verified Responder's Sconfirm successfully.")
    else:
        print("Initiator failed to verify Responder's Sconfirm. Pairing failed.")
        return
    
    print("Pairing confirmed, proceeding to STK generation.")
    # Step 5: Generazione della STK
    STK = s1(initiator.TK, responder.rand, initiator.rand)
    print(f"Generated STK: {STK.hex()}")

# Esegui la demo
pairing_demo()
