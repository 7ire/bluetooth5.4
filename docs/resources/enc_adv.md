# Encrypted Advertising Data

...

## ACL

In Bluetooth abbiamo 2 tipi di link tra master e slave:

- **(connection-oriented / synchronous) Synchronous Connection-Oriented (SCO) link**, link **point-to-point** tra *un master e uno slave*;
- **(connection-less / asynchronous) Asynchronous Connection Less (ACL) link**, link **poit-to-multipoint** tra *un master e tutti gli slave* che partecipano alla rete.

La scelta per questo contesto specifico ricade proprio in **ACL** per due principali proprietà di esso:

- **connection-less**, perché permette di inviare dati nello slot *master-to-slave* riservato SOLO quando ci sono dei dati da inviare, altrimenti nessuna comunicazione (in quello slot) prenderà luogo.
    
    Conseguenza => **riduzione del consumo energetico** (ricordiamo che stiamo parlando di dispositivi che sono dipendenti da una *batteria*).

- **poit-to-multipoint**, perché il master ha bisogno di interagire con più slave (esempio: sensori, IoT, etc) e i singoli slave hanno bisogno di rispondere ad UNO solo master.

## 