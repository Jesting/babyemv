#ifndef __TVR__
#define __TVR__
#include "../kernel.hpp"

const vector<vector<string>> tvrCaptions = { {
    "Offline data authentication was not performed",
    "SDA failed",
    "ICC data missing",
    "Card appears on terminal exception file",
    "DDA failed",
    "CDA failed",
},
{
    "ICC and terminal have different application versions",
    "Expired application",
    "Application not yet effective",
    "Service not allowed for card product",
    "New card",
},
{
    "Cardholder verification was not successful",
    "Unrecognised CVM",
    "PIN try limit exceeded",
    "PIN required, PIN pad not present/not working",
    "PIN required, PIN pad present, PIN was not entered",
    "Online PIN entered",
},
{
    "Transaction exceeds floor limit",
    "Lower consecutive offline limit exceeded",
    "Upper consecutive offline limit exceeded",
    "Transaction selected randomly for online processing",
    "Merchant forced transaction online",
},
{
    "Default DDOL used",
    "Issuer authentication failed",
    "Script processing failed before final generate AC",
    "Script processing failed after final generate AC",
    "RRP threshold exceeded",
    "RRP time limit exceeded",
    "RRP not supported",
} };


class TVR : public TransactionObject {
  public:
    using TransactionObject::TransactionObject;

    void setOfflineDataAuthenticationWasNotPerformed() {
        value[0] |= 0x80;
    }
    void setSDAFailed() {
        value[0] |= 0x40;
    }
    void setICCDataMissing() {
        value[0] |= 0x20;
    }
    void setCardAppearsOnTerminalExceptionFile() {
        value[0] |= 0x10;
    }
    void setDdaFailed() {
        value[0] |= 0x08;
    }
    void setCdaFailed() {
        value[0] |= 0x04;
    }

    void setICCAndTerminalHaveDifferentApplicationVersions() {
        value[1] |= 0x80;
    }

    void setExpiredApplication() {
        value[1] |= 0x40;
    }
    void setApplicationNotYetEffective() {
        value[1] |= 0x20;
    }
    void setServiceNotAllowedForCardProduct() {
        value[1] |= 0x10;
    }
    void setNewCard() {
        value[1] |= 0x08;
    }

    void setCardholderVerificationWasNotSuccessful() {
        value[2] |= 0x80;
    }
    void setUnrecognisedCVM() {
        value[2] |= 0x40;
    }
    void setPINTryLimitExceeded() {
        value[2] |= 0x20;
    }
    void setPINEntryRequiredAndPinPadNotPresentOrNotWorking() {
        value[2] |= 0x10;
    }
    void setPINEntryRequiredPINPadPresentButPinWasNotEntered() {
        value[2] |= 0x08;
    }
    void setOnlinePINEntered() {
        value[2] |= 0x04;
    }
    // B3
    void setTransactionExceedsFloorLimit() {
        value[3] |= 0x80;
    }
    void setLowerConsecutiveOfflineLimitExceeded() {
        value[3] |= 0x40;
    }
    void setUpperConsecutiveOfflineLimitExceeded() {
        value[3] |= 0x20;
    }
    void setTransactionSelectedRandomlyForOnlineProcessing() {
        value[3] |= 0x10;
    }
    void setMerchantForcedTransactionOnline() {
        value[3] |= 0x08;
    }

    void setDefaultDDOLUsed() {
        value[4] |= 0x80;
    }
    void setIssuerAuthenticationFailed() {
        value[4] |= 0x40;
    }
    void setScriptProcessingFailedBeforeFinalGenerateAC() {
        value[4] |= 0x20;
    }
    void setScriptProcessingFailedAfterFinalGenerateAC() {
        value[4] |= 0x10;
    }
    void setRRPThresholdExceeded() {
        value[4] |= 0x08;
    }
    void setRRPTimeLimitExceeded() {
        value[4] |= 0x04;
    }
    void setRRPnotSupported() {
        value[4] |= 0x02;
        value[4] |= 0x01;
    }

    void toStream(ostream& ss) {
        toStreamUniversal(ss, "TVR", tvrCaptions, value);
    }
};

#endif