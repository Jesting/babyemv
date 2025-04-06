# Baby EMV
## _by Payments101_

Baby EMV is example app illustrating the full EMV contact flow. (Except SDA)

## To use the app you need:
- [CLANG] Clang compiler
- [OPENSSL] Open SSL heraders 
- [PCSC] PCSC lite project

## Compile & Run
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
 
