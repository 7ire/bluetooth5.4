from bluetooth.bt_device import BTDevice
from bluetooth.bt_crypto_toolbox import *
from bluetooth.bt_ccm import aes_ccm_encrypt, aes_ccm_decrypt_with_key
import os
import time

mode = "DEBUG"

OOB = 0
AuthReq = 112 # 01110000
MaxKeySize = 1

assert MaxKeySize > 0, "MaxKeySize deve essere > 0"

# Funzione di utilità per convertire un indirizzo Bluetooth da stringa a bytes
def bt_address_to_bytes(bt_address: str) -> bytes:
    # Rimuove i due punti e converte in bytes
    return bytes.fromhex(bt_address.replace(':', ''))

# =========================================
# #   P A I R I N G   P R O T O C O L S   #
# =========================================

def just_work(alice: BTDevice, bob: BTDevice, mitm: bool = False):
    # 1. Scambio delle chiavi pubbliche e calcolo della chiave Diffie-Hellman
    PKa = alice.pK
    PKb = bob.pK

    # Alice calcola la chiave Diffie-Hellman utilizzando la chiave pubblica di Bob
    alice.computeDHKey(PKb)

    # Bob calcola la chiave Diffie-Hellman utilizzando la chiave pubblica di Alice
    bob.computeDHKey(PKa)

    if "DEBUG" == mode: print(f"Alice_DHKey =\t {alice.dhkey.hex()}\nBob_DHKey = \t {bob.dhkey.hex()}")
    assert alice.dhkey == bob.dhkey, "Alice e Bob non condividono la stessa chiave Diffie-Hellman!"

    # 2. Selezionare per Alice e Bob un nonce a 128bits
    bob.nonce = os.urandom(16)
    alice.nonce = os.urandom(16)

    # 3. Calcolare il commit di Bob (Challenge/Response)
    Z = bytes([0x00])  # Z è 0 per Numeric Comparison
    # Convertire pK_x da intero a bytes (32 byte, big endian)
    bob_pK_x_bytes = bob.pK_x.to_bytes(32, byteorder='big')
    alice_pK_x_bytes = alice.pK_x.to_bytes(32, byteorder='big')

    # Calcolare il commit di Bob
    Cb = f4(bob_pK_x_bytes, alice_pK_x_bytes, bob.nonce, Z)

    # 5. Condividere il nonce di Alice
    Na = alice.nonce

    # 6. Condividere il nonce di Bob e controllare il commit di Bob
    Nb = os.urandom(16) if mitm else bob.nonce

    # Simulazione di un attacco MitM da parte di Eve, che sostituisce il commit di Bob
    # con un commit falso Cb_mitm
    Cb_mitm = f4(bob_pK_x_bytes, alice_pK_x_bytes, Nb, Z)

    Cb1 = f4(bob_pK_x_bytes, alice_pK_x_bytes, Nb, Z)

    if "DEBUG" == mode: print(f"Bob_Cb =\t {Cb.hex()}\nAlice_Ca =\t {Cb1.hex()}")
    if mitm: assert Cb1 == Cb_mitm, "Alice e Bob non hanno lo stesso commit!"
    else: assert Cb1 == Cb, "Alice e Bob non hanno lo stesso commit!"

    # In just work non c'è protezione contro attacchi MitM
    # quindi tutti gli step dal 7. in poi non vengono eseguiti.
    
    # Ritorna i nonce per la generazione della LTK (solo per simulare lo scambio dei nonce)
    return Na, Nb

def numeric_comparison(alice: BTDevice, bob: BTDevice, mitm: bool = False):
    # 1. Scambio delle chiavi pubbliche e calcolo della chiave Diffie-Hellman
    PKa = alice.pK
    PKb = bob.pK

    # Alice calcola la chiave Diffie-Hellman utilizzando la chiave pubblica di Bob
    alice.computeDHKey(PKb)

    # Bob calcola la chiave Diffie-Hellman utilizzando la chiave pubblica di Alice
    bob.computeDHKey(PKa)

    if "DEBUG" == mode: print(f"Alice_DHKey =\t {alice.dhkey.hex()}\nBob_DHKey = \t {bob.dhkey.hex()}")
    assert alice.dhkey == bob.dhkey, "Alice e Bob non condividono la stessa chiave Diffie-Hellman!"

    # 2. Selezionare per Alice e Bob un nonce a 128bits
    bob.nonce = os.urandom(16)
    alice.nonce = os.urandom(16)

    # 3. Calcolare il commit di Bob (Challenge/Response)
    Z = bytes([0x00])  # Z è 0 per Numeric Comparison
    # Convertire pK_x da intero a bytes (32 byte, big endian)
    bob_pK_x_bytes = bob.pK_x.to_bytes(32, byteorder='big')
    alice_pK_x_bytes = alice.pK_x.to_bytes(32, byteorder='big')

    # Calcolare il commit di Bob
    Cb = f4(bob_pK_x_bytes, alice_pK_x_bytes, bob.nonce, Z)

    # 5. Condividere il nonce di Alice
    Na = alice.nonce

    # 6. Condividere il nonce di Bob e controllare il commit di Bob
    Nb = os.urandom(16) if mitm else bob.nonce

    # Simulazione di un attacco MitM da parte di Eve, che sostituisce il commit di Bob
    # con un commit falso Cb_mitm
    Cb_mitm = f4(bob_pK_x_bytes, alice_pK_x_bytes, Nb, Z)

    Cb1 = f4(bob_pK_x_bytes, alice_pK_x_bytes, Nb, Z)

    if "DEBUG" == mode: print(f"Bob_Cb =\t {Cb.hex()}\nAlice_Ca =\t {Cb1.hex()}")
    if mitm: assert Cb1 == Cb_mitm, "Alice e Bob non hanno lo stesso commit!"
    else: assert Cb1 == Cb, "Alice e Bob non hanno lo stesso commit!"

    # 7. Generare il valore a 6 cifre da validare ad Alice e a Bob
    Va = g2(alice_pK_x_bytes, bob_pK_x_bytes, alice.nonce, Nb)  # Valore a 6 cifre di Alice
    Vb = g2(alice_pK_x_bytes, bob_pK_x_bytes, Na, bob.nonce)    # Valore a 6 cifre di Bob

    if "DEBUG" == mode: print(f"Alice_Va =\t {Va}\nBob_Vb =\t {Vb}")
    else: print(f"Alice =\t {Va}\nBob =\t {Vb}")

    assert Va == Vb, "Alice e Bob hanno validatori diversi, possimile attaco MitM da parte di Eve!"

    # Ritorna i nonce per la generazione della LTK (solo per simulare lo scambio dei nonce)
    return Na, Nb

# ===================================
# #   K E Y   G E N E R A T I O N   #
# ===================================

def ltk_generation(alice: BTDevice, bob: BTDevice, Na: bytes, Nb: bytes):
    # 8. Scambio di informazioni per il calcolo di LTK
    IOcapA = bytes([AuthReq, OOB, alice.IOCap])  # Capability di Alice
    IOcapB = bytes([AuthReq, OOB, bob.IOCap])    # Capability di Bob
    # Converti gli indirizzi Bluetooth di Alice e Bob in bytes
    A = bt_address_to_bytes(alice.address)  # Indirizzo di Alice
    B = bt_address_to_bytes(bob.address)    # Indirizzo di Bob

    # 9. Generare la LTK
    MacKey_a, LTK_a = f5(alice.dhkey, alice.nonce, Nb, bt_address_to_bytes(alice.address), B) 
    MacKey_b, LTK_b = f5(bob.dhkey, Na, bob.nonce, A, bt_address_to_bytes(bob.address))

    if "DEBUG" == mode: print(f"Alice:\n\t - LTK = {LTK_a.hex()}\n\t - MAC = {MacKey_a.hex()}")
    if "DEBUG" == mode: print(f"Bob:\n\t - LTK = {LTK_b.hex()}\n\t - MAC = {MacKey_b.hex()}")

    # 10. Calcolare le challenges per verificare LTK
    R = bytes(16)  # R è 0 per Numeric Comparison
    EA = f6(MacKey_a, alice.nonce, Nb, R, IOcapA, bt_address_to_bytes(alice.address), B)
    EB = f6(MacKey_b, bob.nonce, Na, R, IOcapB, bt_address_to_bytes(bob.address), A)

    # 11. Controllo incrociato dei valori (simulato)
    assert f6(MacKey_b, Na, bob.nonce, R, IOcapA, A, bt_address_to_bytes(bob.address)) == EA, "La challege ricevuta da Alice non coindice con quella calcolata da Bob!"
    assert f6(MacKey_a, Nb, alice.nonce, R, IOcapB, B, bt_address_to_bytes(alice.address)) == EB, "La challege ricevuta da Bob non coindice con quella calcolata da Alice!"

    return LTK_a

# =====================
# #   A T T A C K s   #
# =====================

def knob(key: bytes, nonce: bytes, auth_data: bytes, plaintext: bytes):
    # Funzione per ridurre l'entropia della chiave AES
    def entropy_reduction(key: bytes, MaxKeySize: int) -> bytes:
        # Taglia la chiave originale alla lunghezza specificata da MaxKeySize
        reduced_key = key[:MaxKeySize]
        
        # Espandi la chiave ridotta a 16 byte ripetendola o aggiungendo padding
        expanded_key = reduced_key.ljust(16, b'\x00')  # Pad con 0x00 fino a 16 byte
        
        if "DEBUG" == mode: 
            print(f"Chiave originale: {key.hex()}")
            print(f"Chiave ridotta (MaxKeySize = {MaxKeySize}): {reduced_key.hex()}")
            print(f"Chiave espansa per AES: {expanded_key.hex()}")
        
        return expanded_key

    # Funzione di brute force per trovare la chiave corretta
    def brute_force_ccm(ciphertext, mac, nonce, auth_data, original_plaintext):
        print("\nInizio brute force per AES-CCM encryption...")
        start_time = time.time()

        found_key = None
        # Proviamo ogni possibile chiave di `MaxKeySize` byte (256^MaxKeySize combinazioni)
        for i in range(256**MaxKeySize):
            test_key = i.to_bytes(MaxKeySize, byteorder='big')
            test_key_expanded = test_key.ljust(16, b'\x00')  # Espandi la chiave per AES

            try:
                # Tentativo di decifratura con la chiave ridotta
                decrypted_text = aes_ccm_decrypt_with_key(test_key_expanded, nonce, ciphertext, auth_data, mac)
                
                # Se la decrittazione ha successo e il testo corrisponde, abbiamo trovato la chiave
                if decrypted_text == original_plaintext:
                    found_key = test_key_expanded
                    break
            except (ValueError, KeyError):
                # Se c'è un errore di autenticazione, continuiamo con la prossima chiave
                continue

        end_time = time.time()
        brute_force_time = end_time - start_time
        if found_key:
            print(f"Chiave trovata: {found_key.hex()}, Tempo brute force: {brute_force_time:.6f} secondi")
        else:
            print("Chiave non trovata.")
        
        return found_key, brute_force_time

    # Riduzione dell'entropia della chiave
    key = entropy_reduction(key, MaxKeySize)

    # Cifratura del messaggio con la chiave ridotta
    ciphertext, mac = aes_ccm_encrypt(key, nonce, plaintext, auth_data)
    print("\t - Plaintext:", plaintext.decode())
    print("\t - Ciphertext:", ciphertext.hex())
    print("\t - MAC:", mac.hex())

    # Esegui brute force per trovare la chiave e decriptare il messaggio
    found_key, brute_force_time = brute_force_ccm(ciphertext, mac, nonce, auth_data, plaintext)

    # Se la chiave è stata trovata, stampa il messaggio in chiaro
    if found_key:
        print("Messaggio decriptato correttamente:", plaintext.decode())



# ============================
# #   M A I N  S C R I P T   #
# ============================

# Creo 2 oggetti Bluetooth - Alice e Bob
alice = BTDevice()  # Creazione di un'istanza di BTDevice per Alice
bob = BTDevice()    # Creazione di un'istanza di BTDevice per Bob

# 1. Pairing - Autenticazione dei dispositivi e generazione della chiave condivisa di sessione

# Just Work
print("==== Just Work ====")
try:
    Na, Nb = just_work(alice, bob)
    LTK = ltk_generation(alice, bob, Na, Nb)
    print(f"Alice e Bob condividono la stessa LTK = {LTK.hex()}")
except AssertionError as e:
    print(e)


# Just Work (MitM Attack)
print("\n\n")
print("==== Just Work (MitM Attack) ====")
try: 
    Na, Nb = just_work(alice, bob, True)
    LTK = ltk_generation(alice, bob, Na, Nb)
    print(f"Alice e Bob condividono la stessa LTK = {LTK.hex()}")
except AssertionError as e:
    print(e)


# Numeric Comparison
print("\n\n")
print("==== Numeric Comparison ====")
try:
    Na, Nb = numeric_comparison(alice, bob)
    LTK = ltk_generation(alice, bob, Na, Nb)
    print(f"Alice e Bob condividono la stessa LTK = {LTK.hex()}")
except AssertionError as e:
    print(e)


# Numeric Comparison (MitM Attack)
print("\n\n")
print("==== Numeric Comparison (MitM Attack) ====")
try:
    Nb = numeric_comparison(alice, bob, True)  # Mi aspetto che l'attacco MitM venga rilevato
    LTK = ltk_generation(alice, bob, Na, Nb)
    print(f"Alice e Bob condividono la stessa LTK = {LTK.hex()}")
except AssertionError as e:
    print(e)


# 2. Pairing - Derivazione delle chiavi partendo da LTK
print("\n\n")
print("==== Derivazione delle chiavi partendo da LTK ====")
# Ripristino il pairing numeric comparison per la demo
Na, Nb = numeric_comparison(alice, bob)
LTK = ltk_generation(alice, bob, Na, Nb)
print(f"Alice e Bob condividono la stessa LTK = {LTK.hex()}")
# BL/EDR - If at least one device sets CT2 = 0
# https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/security-manager-specification.html#UUID-adafa963-422d-a0bf-2808-2711d2f1cbda
ILK = h6(LTK, "tmp1")
BR_EDR_link_key = h6(ILK, "lebr")

# 3. Comunicazione sicura - AES-CCM
print("\n\n")
print("==== Cifratura di un messaggio - AES-CCM ====")
key = LTK  # Utilizzo la chiave di sessione LE-LTK come chiave per AES-CCM
nonce = os.urandom(12)  # CCM usa tipicamente nonce da 12 byte
plaintext = b"Questo e' un messaggio segreto."
auth_data = b"Autenticazione"
ciphertext, mac = aes_ccm_encrypt(key, nonce, plaintext, auth_data)
print("\t - Plaintext:", plaintext.decode())
print("\t - Ciphertext:", ciphertext.hex())
print("\t - MAC:", mac.hex())

# 4. Attacco - Brute Force per trovare la chiave AES-CCM
if 1 == MaxKeySize:
    print("\n\n")
    print("==== KNOB - Brute Force per trovare la chiave AES-CCM ====")
    key = LTK  # Utilizzo la chiave di sessione LE-LTK come chiave per AES-CCM
    nonce = os.urandom(12)  # CCM usa tipicamente nonce da 12 byte
    plaintext = b"Questo e' un messaggio segreto."
    auth_data = b"Autenticazione"
    knob(key, nonce, auth_data, plaintext)




