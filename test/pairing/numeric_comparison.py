import os
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Funzione fittizia per simulare la generazione della chiave DH usando p256
def p256(private_key, public_key):
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    return sha256(shared_key).digest()

# Funzione fittizia per simulare f4 (hash-based confirmation)
def f4(PKa, PKb, Nb, z):
    data = PKa + PKb + Nb + z.to_bytes(1, 'big')
    return sha256(data).digest()

# Funzione fittizia per simulare g2 (numeric comparison)
def g2(PKa, PKb, Na, Nb):
    data = PKa + PKb + Na + Nb
    digest = sha256(data).digest()
    return int.from_bytes(digest[:2], 'big') % 1000000  # 6 digit number

# Funzione per calcolare la Long Term Key (LTK)
def calculate_LTK(DHKey, Na, Nb):
    data = DHKey + Na + Nb
    return sha256(data).digest()

# Funzione per calcolare la Session Key (SK) usando AES-ECB con LTK e SKD
def calculate_session_key(LTK, SKDm, SKDs):
    # Concatenate SKDm e SKDs per formare lo SKD
    SKD = SKDm + SKDs
    
    # Inverte lo SKD (little-endian a big-endian conversion)
    SKD_reversed = SKD[::-1]

    # Crea il cifrario AES in modalità ECB con la LTK come chiave
    cipher = Cipher(algorithms.AES(LTK), modes.ECB())
    encryptor = cipher.encryptor()

    # Cifra lo SKD per ottenere la Session Key
    session_key = encryptor.update(SKD_reversed) + encryptor.finalize()

    return session_key

# Generazione chiavi private e pubbliche
initiator_private_key = ec.generate_private_key(ec.SECP256R1())
initiator_public_key = initiator_private_key.public_key()

responder_private_key = ec.generate_private_key(ec.SECP256R1())
responder_public_key = responder_private_key.public_key()

# Step 1: Exchange of public keys
PKa = initiator_public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
PKb = responder_public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

# Step 2: Calculate DHKey
DHKey_initiator = p256(initiator_private_key, responder_public_key)
DHKey_responder = p256(responder_private_key, initiator_public_key)

# Step 2b: Generate random nonces
Na = os.urandom(16)
Nb = os.urandom(16)

# Step 3: Responder generates confirmation value
Cb = f4(PKb, PKa, Nb, 0)

# Step 4: Responder sends Cb (in real scenario)

# Step 5: Initiator sends Na (in real scenario)

# Step 6: Responder sends Nb (in real scenario)

# Step 6a: Initiator verifies Cb
calculated_Cb = f4(PKb, PKa, Nb, 0)
if calculated_Cb != Cb:
    print("Pairing failed: Confirmation values do not match!")
else:
    print("Pairing phase 1 succeeded: Confirmation values match!")

# Step 7: Both devices compute Va and Vb
Va = g2(PKa, PKb, Na, Nb)
Vb = g2(PKa, PKb, Na, Nb)

# Check if Va == Vb
if Va == Vb:
    print(f"Pairing succeeded: Numeric Comparison values match! (Va = {Va}, Vb = {Vb})")
else:
    print(f"Pairing failed: Numeric Comparison values do not match! (Va = {Va}, Vb = {Vb})")

# Step 8: Calculate the Long Term Key (LTK)
LTK_initiator = calculate_LTK(DHKey_initiator, Na, Nb)
LTK_responder = calculate_LTK(DHKey_responder, Na, Nb)

# Verify if both LTKs match
if LTK_initiator == LTK_responder:
    print(f"LTK calculation succeeded! (LTK = {LTK_initiator.hex()})")
else:
    print("LTK calculation failed: LTK values do not match!")

# Step 9: Calculate the Session Key (SK)
# Generate random 8-byte values for SKDm and SKDs
SKDm = os.urandom(8)
SKDs = os.urandom(8)

# Calculate the Session Key (SK)
session_key_initiator = calculate_session_key(LTK_initiator, SKDm, SKDs)
session_key_responder = calculate_session_key(LTK_responder, SKDm, SKDs)

# Verify if both Session Keys match
if session_key_initiator == session_key_responder:
    print(f"Session Key calculation succeeded! (Session Key = {session_key_initiator.hex()})")
else:
    print("Session Key calculation failed: Session Key values do not match!")
