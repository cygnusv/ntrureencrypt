#Prototype implementation in Java of NTRUReEncrypt

This repository contains a prototype implementation of NTRUReEncrypt, a Proxy Re-Encryption scheme based on NTRU, proposed by Nuñez, Agudo and Lopez, in ACM AsiaCCS 2015 [1].

The proxy re-encryption scheme simply extends the conventional NTRU scheme, adding functions to re-encrypt ciphertexts and to generate re-encryption keys. 

This prototype implementation is built upon the NTRU implementation in [tbuktu/ntru](https://github.com/tbuktu/ntru), version 1.2. Note that this prototype is a mere proof of concept so the implementation is completely monolithic. Modularization and refactoring is WIP.


##Further reading
[1] Nuñez, D., Agudo, I., & Lopez, J. (2015). NTRUReEncrypt: An efficient proxy re-encryption scheme based on NTRU. In Proceedings of the 10th ACM Symposium on Information, Computer and Communications Security (pp. 179-189). ACM. ([link](https://www.nics.uma.es/biblio/citekey/nunez2015ntrureencrypt))


