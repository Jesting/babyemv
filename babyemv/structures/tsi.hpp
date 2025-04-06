#ifndef __TSI__
#define __TSI__

#include "../kernel.hpp"
#include <ostream>

const vector<vector<string>> tsiCaptions = {
    { "Offline value authentication was performed",
      "Cardholder verification was performed",
      "Card risk management was performed",
      "Issuer authentication was performed",
      "Terminal risk management was performed",
      "Issuer script processing was performed" }
};

class TSI : public TransactionObject {
  public:
    TSI(vector<unsigned char>& _value) : TransactionObject(_value) {
        if (value.size() != 2) {
            throw runtime_error("TSI value != 2");
        }
    }
    void setOfflinevalueAuthenticationWasPerformed() {
        value[0] |= 0x80;
    }
    void setCardholderVerificationWasPerformed() {
        value[0] |= 0x40;
    }
    void setCardRiskManagementWasPerformed() {
        value[0] |= 0x20;
    }
    void setIssuerAuthenticationWasPerformed() {
        value[0] |= 0x10;
    }
    void setTerminalRiskManagementWasPerformed() {
        value[0] |= 0x08;
    }
    void setIssuerScriptProcessingWasPerformed() {
        value[0] |= 0x04;
    }

    void toStream(ostream& ss) {
        toStreamUniversal(ss, "TSI", tsiCaptions, value);
    }
};

#endif