
#ifndef __AIP__
#define __AIP__
#include "../kernel.hpp"
#include <ostream>

const vector<vector<string>> aipCaptions = {
    { "RFU", "SDA supported", "DDA supported", "Cardholder verification supported", "TRM to be performed",
      "Issuer authentication supported", "On device CVM supported", "CDA supported" },
    { "EMV mode selected", "RFU", "RFU", "RFU", "RFU", "RFU", "RFU", "RRP supported" }
};

class AIP : public TransactionObject {
  public:
    using TransactionObject::TransactionObject;

    bool sdaSupported;
    bool ddaSupported;
    bool cardholderVerificationSupported;
    bool trmIsToBePerformed;
    bool issuerAuthenticationSupported;
    bool onDeviceCVMSupported;
    bool cdaSupported;
    bool emvModeSelected;
    bool rrpSupported;

    AIP(vector<unsigned char>& _value) : TransactionObject(_value) {
        sdaSupported = (value[0] & 0x40) == 0x40;
        ddaSupported = (value[0] & 0x20) == 0x20;
        cardholderVerificationSupported = (value[0] & 0x10) == 0x10;
        trmIsToBePerformed = (value[0] & 0x08) == 0x08;
        issuerAuthenticationSupported = (value[0] & 0x04) == 0x04;
        onDeviceCVMSupported = (value[0] & 0x02) == 0x02;
        cdaSupported = (value[0] & 0x01) == 0x01;
        emvModeSelected = (value[1] & 0x80) == 0x80;
        rrpSupported = (value[1] & 0x01) == 0x01;
    }

    void toStream(ostream& ss) {
        toStreamUniversal(ss, "AIP", aipCaptions, value);
    }
};

#endif