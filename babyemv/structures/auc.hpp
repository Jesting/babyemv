
#ifndef __AUC__
#define __AUC__

#include "../kernel.hpp"
#include <ostream>

const vector<vector<string>> aucCaptions = { {
    "Valid for domestic cash",
    "Valid for international cash",
    "Valid for domestic goods",
    "Valid for international goods",
    "Valid for domestic services",
    "Valid for international services",
    "Valid at ATMs",
    "Valid for other than ATMs",
},
{ "Valid for domestic cashback", "Valid for international cashback" } };

class AUC : TransactionObject {

  public:
    bool validForDomesticCash;
    bool validForInternationalCash;
    bool validForDomesticGoods;
    bool validForInternationalGoods;
    bool validForDomesticServices;
    bool validForInternationalServices;
    bool validAtATMs;
    bool validForOtherThanAtms;
    bool validForDomesticCashback;
    bool validForInternationalCashback;

    AUC(vector<unsigned char>& _value) : TransactionObject(_value) {
        if (value.size() != 2)
            throw runtime_error("AUC data != 2");
        validForDomesticCash = (value[0] & 0x80) == 0x80;
        validForInternationalCash = (value[0] & 0x40) == 0x40;
        validForDomesticGoods = (value[0] & 0x20) == 0x20;
        validForInternationalGoods = (value[0] & 0x10) == 0x10;
        validForDomesticServices = (value[0] & 0x08) == 0x08;
        validForInternationalServices = (value[0] & 0x04) == 0x04;
        validAtATMs = (value[0] & 0x02) == 0x02;
        validForOtherThanAtms = (value[0] & 0x01) == 0x01;
        validForDomesticCashback = (value[1] & 0x80) == 0x80;
        validForInternationalCashback = (value[1] & 0x40) == 0x40;
    }

    void toStream(ostream& ss) {
        toStreamUniversal(ss, "AUC", aucCaptions, value);
    }
};

#endif