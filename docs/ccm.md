# Counter with CBC-MAC (CCM)

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
