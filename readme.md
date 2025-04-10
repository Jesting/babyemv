# Baby EMV
## _for Payments101_

Baby EMV is example app illustrating the EMV contact flow.
* Some parts are simplified / absent:
    * Some CVM's 
    * Risk management 
    * SDA 
    * Script processing
    * Tests
* Code supports:
    * Application selection (direct & PSE)
    * GPO
    * CVM: Offline PIN (plain & encrypted), etc..
    * Basic restrictions processing
    * Certificates recovery
    * DDA & CDA
    * Cryptogram generation

## To use the app you need:
- [CLANG] Clang compiler
- [OPENSSL] Open SSL heraders 
- [PCSC] PCSC lite project

## Compile & Run
Only Mac OS with all components is currently supported. However with all components installed the code will compile and run on every system (make file must be updated accordingly).
```sh
make clean
make 
./x
```
## Notes
Your reader may have different name , you need to choose it accordingly
```C++
 c.connectByName("HID Global OMNIKEY 5422 Smartcard Reader 01"); 
```

## License
...

**Free for any use**

[//]: #
   [PCSC]:<https://pcsclite.apdu.fr>
   [OPENSSL]: <https://openssl.org>
   [CLANG]: <https://clang.llvm.org>
 
