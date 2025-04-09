#ifndef __READER__
#define __READER__
#include <PCSC/winscard.h>
#include <vector>
#include <iostream>
#include "utils.hpp"

using namespace std;

class Reader {
  public:
    virtual int command(unsigned char* commandData, int len, unsigned char* responseData,
                        unsigned int& responseLen) = 0;

    virtual ~Reader() {};
};

class ScardApiReader : public Reader {
  private:
    SCARDCONTEXT hContext;
    SCARDHANDLE hCard;
    uint32_t dwActiveProtocol;
    int32_t rc;
    char readers[256];

  public:
    ScardApiReader() {
        rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &hContext);
        if (rc != SCARD_S_SUCCESS) {
            std::cerr << "Failed to establish context: " << pcsc_stringify_error(rc) << std::endl;
            throw std::invalid_argument("not initilizes");
        }
    };

    int listReaders() {
        // List connected readers
        uint32_t readersLen = sizeof(readers);
        rc = SCardListReaders(hContext, nullptr, readers, &readersLen);

        if (rc != SCARD_S_SUCCESS) {
            std::cerr << "Failed to list readers: " << pcsc_stringify_error(rc) << std::endl;
            SCardReleaseContext(hContext);
            return 1;
        }

        // Print all available readers
        char* reader = readers;
        while (*reader != '\0') {
            std::cout << "Available reader: " << reader << std::endl;
            reader += strlen(reader) + 1;
        }
        return 0;
    };

    int connectAny() {
        // Connect to card reader
        rc = SCardConnect(hContext, readers, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard,
                          &dwActiveProtocol);
        if (rc != SCARD_S_SUCCESS) {
            std::cerr << "Failed to connect to card reader: " << pcsc_stringify_error(rc) << std::endl;
            SCardReleaseContext(hContext);
            return 1;
        }
        return 0;
    };

    int connectByName(const std::string& readerName) {
        rc = SCardConnect(hContext, readerName.c_str(), SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                          &hCard, &dwActiveProtocol);
        if (rc != SCARD_S_SUCCESS) {
            std::cerr << "Failed to connect to card reader: " << pcsc_stringify_error(rc) << std::endl;
            SCardReleaseContext(hContext);
            return 1;
        }
        return 0;
    }

    int command(unsigned char* data, int len, unsigned char* responseData, unsigned int& responseLen) override {
        cout << endl << "Card exchange:" << endl;
        cout << "CAPDU: ";
        pointerPrint(data, len);

        SCARD_IO_REQUEST pioSendPci;
        pioSendPci.dwProtocol = dwActiveProtocol;
        pioSendPci.cbPciLength = sizeof(pioSendPci);

        rc = SCardTransmit(hCard, &pioSendPci, data, (unsigned)len, &pioSendPci, responseData, &responseLen);
        if (rc != SCARD_S_SUCCESS) {
            std::cerr << "Failed to transmit APDU: " << pcsc_stringify_error(rc) << std::endl;
            return rc;
        } else {
            cout << "RAPDU: ";
            pointerPrint(responseData, responseLen);
            cout << endl;
            return 0;
        }
    };

    ~ScardApiReader() {
        SCardDisconnect(hCard, SCARD_UNPOWER_CARD);
        SCardReleaseContext(hContext);
        
    };
};

#endif