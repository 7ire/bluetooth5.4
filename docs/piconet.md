# Piconet

> Collegabile su come funziona la struttura mesh del **Periodic Adverting**


In Bluetooth, una piconet è una rete wireless, che permette lo scambio di informazioni ai dispositivi che la compongono. Una tale rete è costruita dinamicamente senza alcun intervento esterno man mano che nuovi dispositivi sono ad essa aggiunti.
Una piconet contiene almeno un dispositivo master e al più sette dispositivi slave, con cui il master comunica attivamente.
I dispositivi sono sempre prodotti in modo da poter operare sia da master che da slave. La loro esatta modalità di funzionamento è decisa solo nel momento in cui la piconet è effettivamente costituita.
Tra i vari compiti del dispositivo master troviamo:

- l’assegnamento agli slave, con cui comunica attivamente, di un indirizzo univoco all’interno della piconet, detto active member address (AM_ADDR);
- l’istante di tempo in cui ciascuno slave presente nella rete può iniziare a trasmettere.

Oltre ai dispositivi slave, con il master possono essere registrati anche al più 255 dispositivi parked, cioè dispositivi che possono essere invitati, se necessario, a diventare attivi.
Se un dispositivo Bluetooth non è associato ad una piconet, si dice che è in modalità stand-by.
La figura mostra un esempio di piconet.

Come già detto, le piconet sono reti wireless, cioè reti, che utilizzano per la trasmissione, radio frequenze. Questo comporta, che nel caso di piconet tra loro vicine, uno stesso dispositivo può essere contemporaneamente membro di due o più piconet e in tal caso si parla di scatternet.

### 2.2.3 Link Fisici

Una piconet Bluetooth supporta due tipi di link tra master e slave:
 
- Synchronous Connection-Oriented (SCO) link;
- Asynchronous Connection Less (ACL) link.


In genere, tra un master e uno slave, il tipo di link usato è senza connessione ed asincrono (ACL), ma sono anche supportati fino a tre link orientati alla connessione e sincroni (SCO).
Un link SCO è un link point-to-point tra un master e un singolo slave. 
Il master mantiene un link SCO usando a intervalli regolari slot riservati.
Diversamente, un link ACL è un link poit-to-multipoint tra il master e tutti gli slave che partecipano alla piconet.

#### 2.2.3.2 Link ACL

Negli slot non riservati a link SCO, il master può scambiare pacchetti con qualunque slave.
I link ACL forniscono una connessione packet-switched tra il master e tutti gli slave attivi nella piconet.
Tra il master e uno dato slave può esistere solo un link ACL. Per i pacchetti ACL è permessa anche la ritrasmissione per garantire l'integrità dei dati trasmessi.  

Ad uno slave è permesso inviare un pacchetto ACL nello slot slave-to-master se e solo se è stato indirizzato nel precedente slot master-to-slave.
Se lo slave fallisce nel decodificare l'indirizzo slave nel header del pacchetto, a questo non è permesso trasmettere.
Se un pacchetto non è indirizzato ad uno specifico slave, esso è considerato inviato in broadcast e quindi tutti gli slave possono leggerlo.
Se non ci sono dati da inviare sul link ACL e non è richiesto polling allora nessuna trasmissione prenderà luogo.

## 2.3 Link Manager

Il Link Manager Protocol (LMP) è un protocollo responsabile delle transazioni tra i dispositivi di una piconet. Tra i suoi compiti principali troviamo il settaggio delle proprietà del link esistente tra due dispositivi e l’autenticazione di questi ultimi per permettere la realizzazione di un canale cifrato.  

Come evidenziato dalla figura il protocollo link manager si basa sull'interfaccia fornita dal link control (LC) parte integrante del protocollo baseband, che a sua volta sfrutta l'interfaccia fornita dal sistema di trasmissione radio RF. Per questo il link manager protocol non è responsabile della correzione dell'errore o della ritrasmissione dei pacchetti in caso di errore. 
L’autenticazione dei due dispositivi Bluetooth agli estremi di un link avviene per mezzo di un meccanismo di challenge-response definito da questo protocollo.
Tra i compiti del Link Manager Protocol troviamo l’apprendimento delle funzionalità offerte dal LMP all’altro estremo del link e la verifica periodica della raggiungibilità dell’altro dispositivo per mezzo di operazioni di polling. Un dispositivo per poter comunicare con un altro ha bisogno di conoscere le funzionalità di questo ultimo, come il supporto dei link SCO e la dimensione massima dei pacchetti accettati in input.
I messaggi del Link Manager hanno priorità superiore a qualunque dato utente da trasferire.
Questo comporta, che se il Link Manager ha bisogno di inviare un messaggio, questo non sarà ritardato da traffico L2CAP, anche se può essere ritardato da ritrasmissioni di pacchetti baseband. 

## 3.1 Generazione unit key

Una unit key è generata per mezzo dell'algoritmo E21, in un dispositivo, quando è avviato per la prima volta. 
Una volta creata, essa è memorizzata in una memoria non volatile ed è raramente modificata.
All'algoritmo E21 è passato l'indirizzo Bluetooth del dispositivo, BD_ADDR, e un numero casuale RAND a 128 bit.

 

## 3.2 Generazione initialization key

Quando due dispositivi Bluetooth entrano in contatto per la prima volta, uno dei due (il richiedente, unità B) prova a raggiungere l'altro (il verificatore, unità A).
Il richiedente deve dimostrare al verificatore di essere un dispositivo autorizzato, ovvero condivide con esso uno stesso PIN. Per fare questo viene prima di tutto generata una initialization key in entrambi i dispositivi, sulla base di questo PIN, e poi è avviata la fase di autenticazione in cui A accerta che B condivide con se una stessa link key, che in questa fase coincide con l'initialization key appena generata.
Normalmente i PIN usati sono numeri di 4 cifre decimali, inseriti dall'utente nei dispositivi o via software o per mezzo di una tastiera. Potenzialmente un PIN può essere lungo anche 128 bit. In tale caso, per l'inserimento nei due dispositivi si può ricorrere ad un protocollo come quello di Diffie-Hellmann per lo scambio delle chiavi.
Nel caso peggiore, quando uno dei due dispositivi ha una limitata capacità di memoria il suo PIN può essere fisso, cioè scelto dal produttore in fase di costruzione. Nel caso in cui nessun PIN è disponibile allora  il valore di default è zero.