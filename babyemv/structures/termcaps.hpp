#ifndef __TERMINALCAPABILITIES__
#define __TERMINALCAPABILITIES__
#include "../kernel.hpp"
#include "cvm.hpp"
#include <ostream>

using namespace std;
const vector<vector<string>> terminalCapabilitiesCaptions = {
    { "Manual key entry", "Magnetic stripe", "IC with contacts" },
    { "Plaintext PIN for offline ICC verification", "Enciphered PIN for online verification", "Signature paper",
      "Enciphered PIN for offline verification", "No CVM required" },
    { "Static data authentication", "Dynamic data authentication", "Capture card", "RFU",
      "Combined DDA/Application cryptogram generation" }
};

class TerminalCapabilities : public TransactionObject {
  public:
    bool manualKeyEntry;
    bool magneticStripe;
    bool icWithContacts;

    bool plaintextPINForOfflineICCVerification;
    bool encipheredPINForOnlineVerification;
    bool signaturePaper;
    bool encipheredPINForOfflineVerification;
    bool noCVMRequired;

    bool sdaSupport;
    bool ddaSupport;
    bool captureCard;

    bool cdaSupport;

    TerminalCapabilities(vector<unsigned char>& _value) : TransactionObject(_value) {
        if (value.size() != 3)
            throw runtime_error("TerminalCapabilities value != 3");

        manualKeyEntry = (value[0] & 0x80) == 0x80;
        magneticStripe = (value[0] & 0x40) == 0x40;
        icWithContacts = (value[0] & 0x20) == 0x20;

        plaintextPINForOfflineICCVerification = (value[1] & 0x80) == 0x80;
        encipheredPINForOnlineVerification = (value[1] & 0x40) == 0x40;
        signaturePaper = (value[1] & 0x20) == 0x20;
        encipheredPINForOfflineVerification = (value[1] & 0x10) == 0x10;
        noCVMRequired = (value[1] & 0x08) == 0x08;

        sdaSupport = (value[2] & 0x80) == 0x80;
        ddaSupport = (value[2] & 0x40) == 0x40;
        captureCard = (value[2] & 0x20) == 0x20;
        cdaSupport = (value[2] & 0x08) == 0x08;
    }

    bool supportCvm(const CVM& cvm) {
        switch (cvm) {
            case CVM::PlaintextPINVerificationperformedICC:
                return plaintextPINForOfflineICCVerification;
            case CVM::EncipheredPINVerifiedOnline:
                return encipheredPINForOnlineVerification;
            case CVM::PlaintextPINVerificationPerformedByICCAndSignature:
                return plaintextPINForOfflineICCVerification && signaturePaper;
            case CVM::EncipheredPINVerificationPerformedByICC:
                return encipheredPINForOfflineVerification;
            case CVM::EncipheredPINVerificationPerformedByICCAndSignature:
                return encipheredPINForOfflineVerification && signaturePaper;
            case CVM::Signature:
                return signaturePaper;
            case CVM::NoCVM:
                return noCVMRequired;
            case CVM::FailCVMProcessing:
                return true;
            default:
                return false;
        }
    }

    void toStream(ostream& ss) {
        toStreamUniversal(ss, "TerminalCapabilities", terminalCapabilitiesCaptions, value);
    }
};

const vector<vector<string>> additionalTerminalCapabilities = {
    { "Cash", "Goods", "Services", "Cashback", "Inquiry", "Transfer", "Payment", "Administrative" },
    { "Cash deposit" },
    { "Numeric keys", "Alpha numeric keys", "Command keys", "Function keys" },
    { "Print attendant", "Print cardholder", "Display attendant", "Display cardholder", "RFU", "RFU", "Code table 10",
      "Code table 9" },
    { "Code table 8", "Code table 7", "Code table 6", "Code table 5", "Code table 4", "Code table 3", "Code table 2",
      "Code table 1" }
};

class AdditionalTerminalCapabilities : TransactionObject {
  public:
    bool cash;
    bool goods;
    bool services;
    bool cashback;
    bool inquiry;
    bool transfer;
    bool payment;
    bool administrative;

    bool cashDeposit;

    bool numericKeys;
    bool alphaNumericKeys;
    bool commandKeys;
    bool functionKeys;

    bool printAttendant;
    bool printCardholder;
    bool displayAttendant;
    bool displayCardholder;
    bool codeTable10;
    bool codeTable9;
    bool codeTable8;
    bool codeTable7;
    bool codeTable6;
    bool codeTable5;
    bool codeTable4;
    bool codeTable3;
    bool codeTable2;
    bool codeTable1;

    AdditionalTerminalCapabilities(vector<unsigned char>& _value) : TransactionObject(_value) {
        if (value.size() != 5)
            throw runtime_error("AdditionalTerminalCapabilities data != 5");

        cash = (value[0] & 0x80) == 0x80;
        goods = (value[0] & 0x40) == 0x40;
        services = (value[0] & 0x20) == 0x20;
        cashback = (value[0] & 0x10) == 0x10;
        inquiry = (value[0] & 0x08) == 0x08;
        transfer = (value[0] & 0x04) == 0x04;
        payment = (value[0] & 0x02) == 0x02;
        administrative = (value[0] & 0x01) == 0x01;

        cashDeposit = (value[1] & 0x80) == 0x80;

        numericKeys = (value[2] & 0x80) == 0x80;
        alphaNumericKeys = (value[2] & 0x40) == 0x40;
        commandKeys = (value[2] & 0x20) == 0x20;
        functionKeys = (value[2] & 0x10) == 0x10;

        printAttendant = (value[3] & 0x80) == 0x80;
        printCardholder = (value[3] & 0x40) == 0x40;
        displayAttendant = (value[3] & 0x20) == 0x20;
        displayCardholder = (value[3] & 0x10) == 0x10;
        codeTable10 = (value[3] & 0x02) == 0x02;
        codeTable9 = (value[3] & 0x01) == 0x01;

        codeTable8 = (value[4] & 0x80) == 0x80;
        codeTable7 = (value[4] & 0x40) == 0x40;
        codeTable6 = (value[4] & 0x20) == 0x20;
        codeTable5 = (value[4] & 0x10) == 0x10;
        codeTable4 = (value[4] & 0x08) == 0x08;
        codeTable3 = (value[4] & 0x04) == 0x04;
        codeTable2 = (value[4] & 0x02) == 0x02;
        codeTable1 = (value[4] & 0x01) == 0x01;
    }

    void toStream(ostream& ss) {
        toStreamUniversal(ss, "Additional terminal capabilities", additionalTerminalCapabilities, value);
    }
};

#endif