from cryptography.hazmat.primitives.asymmetric import ec

# Genera la chiave privata e la chiave pubblica
sk = ec.generate_private_key(ec.SECP256R1())
pk = sk.public_key()

# Estrai le coordinate x e y
public_numbers = pk.public_numbers()
x = public_numbers.x
y = public_numbers.y

# Calcola la lunghezza in bit e in byte
x_bit_length = x.bit_length()
y_bit_length = y.bit_length()

x_byte_length = (x_bit_length + 7) // 8  # Arrotonda per eccesso al numero intero più vicino
y_byte_length = (y_bit_length + 7) // 8

print(f"Coordinate x: {x}")
print(f"Lunghezza x in bit: {x_bit_length} bit")
print(f"Lunghezza x in byte: {x_byte_length} byte")

print(f"Coordinate y: {y}")
print(f"Lunghezza y in bit: {y_bit_length} bit")
print(f"Lunghezza y in byte: {y_byte_length} byte")