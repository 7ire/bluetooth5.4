# Sharing Key Material

+ Preve intro nell'implementazione 5.4
+ Intro ACL e fasi di generazione chiave
  + Aspetti di Key Derivation Function + Forward Security
+ Descrizione dell'Encrypted Data Key Material
+ Evidenziare il problema di avere SOLO 1 chiave di sessione come chiave segreta.

There are 2 **GAP (Generic Access Profile)** role:

- **Center**
  - *Must act as a GAP Client*
- **Peripheral**, can accept connection request from another device acting like GAP Center
  > *Must act as a GAP Server*

New characteristic **Encrypted Data Key Material** is defined. Provides the basis by which key material
can be shared with devices that are the intended recipients of encrypted advertising data.

TODO: Encrypted Data Key Material structure description.

**GAP Client** can read this ONLY over an encrypted and authenticated ACL connection.

TODO: Little description of ACL

- **Bluetooth Start** start the communication and the exchange of cryptographics metadata between master and slave.
  - generation of the **Long Term Key** that is used to derivate **SKD**
- **Bluetooth Pause** incapsulate **Bluetooth Start** procedure in case the **Long Term Key** needs to be changed.
