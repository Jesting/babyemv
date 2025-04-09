#ifndef __CVM__
#define __CVM__
enum CVM {
    FailCVMProcessing = 0b00000000,
    PlaintextPINVerificationperformedICC = 0b00000001,
    EncipheredPINVerifiedOnline = 0b00000010,
    PlaintextPINVerificationPerformedByICCAndSignature = 0b00000011,
    EncipheredPINVerificationPerformedByICC = 0b00000100,
    EncipheredPINVerificationPerformedByICCAndSignature = 0b00000101,
    Signature = 0b00011110,
    NoCVM = 0b00011111,
    NoCVMPeformed = 0b00111111
};

struct CVRule {
    bool nextOnUnsuccess;
    CVM cvm;
    static CVRule parse(unsigned char b) {
        return CVRule{ static_cast<bool>(b & 0x40), static_cast<CVM>(b & 0b00111111) };
    }
};

enum CVCondition {
    Always = 0x00,
    IfUnattendedCash = 0x01,
    IfNotUnattendedCashAndNotManualCashAndNotNurchaseWithCashback = 0x02,
    IfTerminalSupportsTheCVM = 0x03,
    IfManualCash = 0x04,
    IfPurchaseWithCashback = 0x05,
    IfAppCurrencyAndAmountUnderX = 0x06,
    IfAppCurrencyAndAmountOverX = 0x07,
    IfAppCurrencyAndAmountUnderY = 0x08,
    IfAppCurrencyAndAmountOverY = 0x09,
};

struct CVMEntry {
    CVRule rule;
    CVCondition condition;

    static CVMEntry parse(uint8_t brule, uint8_t bcondition) {
        return CVMEntry{ CVRule::parse(brule), static_cast<CVCondition>(bcondition) };
    }
};

class CVMList : TransactionObject {
  public:
    unsigned int X;
    unsigned int Y;
    vector<CVMEntry> entries;

    CVMList(vector<uint8_t>& _value) : TransactionObject(_value) {
        int c = 0;
        
        while (c < 4) {
            X = X << 8 | value[c++];
        }
        
        while (c < 8) {
            Y = Y << 8 | value[c++];
        }

        while (c < value.size()) {
            uint8_t code = value[c++];
            uint8_t condition = value[c++];

            entries.push_back(CVMEntry::parse(code, condition));
        }
    }
};

string CVMToString(CVM cvm) {
    switch (cvm) {
        case CVM::FailCVMProcessing:
            return "Fail CVM";
        case CVM::PlaintextPINVerificationperformedICC:
            return "Plain PIN ICC";
        case CVM::EncipheredPINVerifiedOnline:
            return "Enc PIN online";
        case CVM::PlaintextPINVerificationPerformedByICCAndSignature:
            return "Plain PIN + Signature";
        case CVM::EncipheredPINVerificationPerformedByICC:
            return "Enc PIN ICC";
        case CVM::EncipheredPINVerificationPerformedByICCAndSignature:
            return "EMC PIN ICC + Signature";
        case CVM::Signature:
            return "Signature (paper)";
        case CVM::NoCVM:
            return "No CVM required";
        case CVM::NoCVMPeformed:
            return "No CVM peformed";

        default:
            return "UNKNOWN";
    }
}

string CVConditionToString(CVCondition c) {
    switch (c) {
        case CVCondition::Always:
            return "Always";
        case CVCondition::IfUnattendedCash:
            return "Unattended Cash";
        case CVCondition::IfNotUnattendedCashAndNotManualCashAndNotNurchaseWithCashback:
            return "Not Cash/Purchase + Cashback";
        case CVCondition::IfTerminalSupportsTheCVM:
            return "If Terminal Supports The CVM";
        case CVCondition::IfManualCash:
            return "If Manual Cash";
        case CVCondition::IfPurchaseWithCashback:
            return "If Purchase With Cashback";
        case CVCondition::IfAppCurrencyAndAmountUnderX:
            return "If App Currency And Amount UnderX";
        case CVCondition::IfAppCurrencyAndAmountOverX:
            return "If App CurrencycAndcAmountcOver X";
        case CVCondition::IfAppCurrencyAndAmountUnderY:
            return "If App Currency And Amount UnderY";
        case CVCondition::IfAppCurrencyAndAmountOverY:
            return "If App Currency And Amount Over Y";

        default:
            return "UNKNOWN";
    }
}

enum CvmResult {
    Unknown = 0,
    Failed = 1,
    Success = 2,
};

string CvmResultToString(CvmResult r) {
    if (r == CvmResult::Unknown)
        return "Unknown";
    if (r == CvmResult::Failed)
        return "Failed";
    if (r == CvmResult::Success)
        return "Success";
    throw runtime_error("Unknow CVM handling needs to be implemented");    
}

struct CvmResults : TransactionObject {
  public:
    using TransactionObject::TransactionObject;

    void setCvmPerformed(CVM cvm) {
        value[0] = cvm;
    }
    void setCvmCondition(CVCondition cvCondition) {
        value[1] = cvCondition;
    }
    void setCvmResult(CvmResult cvmResult) {
        value[2] = cvmResult;
    }
    CVM getCvmPerformed() {
        return static_cast<CVM>(value[0]);
    }
    CVCondition getCvmCondition() {
        return static_cast<CVCondition>(value[1]);
    }
    CvmResult getCvmResult() {
        return static_cast<CvmResult>(value[2]);
    }
    void toStream(ostream& ss) {
        ss << "┌─CvmResults──────────────────────────────────────" << endl;
        ss << "├─" << "CVM Performed                : " << CVMToString(getCvmPerformed()) << endl;
        ss << "├─" << "CVM Condition                : " << CVConditionToString(getCvmCondition()) << endl;
        ss << "└─" << "CVM Result                   : " << CvmResultToString(getCvmResult()) << endl;
    }
};

string cvmListPrint(const CVMList& cvmList) {
    stringstream ss;

    // format("")
    ss << "┌───────────────────────────────────────────────────────────────────────────────────────────────" << endl;
    ss << "|X:" << cvmList.X << ", Y:" << cvmList.Y << endl;
    ss << "|N|CVM" << string(72, ' ') << "|CODE" << endl;

    for (auto& e : cvmList.entries) {
        auto cvm = CVMToString(e.rule.cvm);

        ss << "|" << e.rule.nextOnUnsuccess << "|" << cvm << string(75 - cvm.size(), ' ') << "|"
           << CVConditionToString(e.condition) << endl;
    }

    return ss.str();
}

#endif