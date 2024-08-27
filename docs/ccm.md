# Counter with CBC-MAC (CCM)

+ Intro breve
+ Perché la scelta di authenticate-then-encrypt
+ Come viene superato il limite di avere solo 1 chiave
  + Spiegare il processo di CBC-MAC e di come CTR mode diventa un cifrario a flusso

## Intro

- Mode operation for cryptographics block chipers.
- **Authenticated Encryption**, provide:
  - authentication
  - confidentiality
- *Only defined for block length of 128bits*

> The **nonce** of CCM never be used more than once for a given key.
> Because CCM is a derivation of (CTR mode) and the latter is effectively a stream cipher.

## Encryption and authentication

CCM mode combine:

+ **counter (CTR) mode**, for confidentiality
+ **cipher block chaining message authentication code (CBC-MAC)** for authentication

These two primitives are applied in an **authenticate-then-encrypt**:

1. CBC-MAC compute on the message to obtain the **message authentication code (MAC)**
2. [ message + MAC ] == encrypted ==> using **counte mode**

CBC-MAC(Key) == CTR mode(Key)

### Why Encrypt then MAC

Becase ACL link layer only privide 1 session key (to be more specific a SKD - Secret Key Derivation) so is not possible to use MAC then Encrypt and to overcome this problem, the CTR mode is use to create a **strem cipher** that use the same SK BUT it is different each packet.