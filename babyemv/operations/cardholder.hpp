#ifndef __CARDHOLDER__
#define __CARDHOLDER__

#include "operation.hpp"
#include "../settings.hpp"
#include "../structures/dol.hpp"
#include "../structures/tvr.hpp"
#include "../structures/auc.hpp"
#include "../structures/termcaps.hpp"
#include "../structures/enums.hpp"
#include "../structures/certs.hpp"
#include "../structures/aip.hpp"
#include "../rsautils.hpp"
#include "crypto.hpp"

class Cardholder : public Operation {
  private:
    CertsCache certs;
    Crypto& crypto;
    function<vector<uint8_t>()>& plainPinEntry;

  public:
    Cardholder(TransactionObjects& _transactionObjects, Command* _command, Crypto& _crypto,
               function<vector<uint8_t>()>& _plainPinEntry)
      : Operation(_transactionObjects, _command), crypto(_crypto), plainPinEntry(_plainPinEntry) {
    }
    // CN PP PP P/F P/F P/F P/F P/F P/F P/F P/F FF
    vector<uint8_t> constructISO2Pinblock(vector<uint8_t> pin) {
        vector<uint8_t> pinblock;
        if (pin.size() < 4 || pin.size() > 12)
            throw runtime_error("wrong size");

        pinblock.clear();
        pinblock.push_back(0b00100000 | pin.size());
        int c = 0;
        int d = 0x00;

        while (c < pin.size()) {
            d = pin[c++];
            if (c < pin.size())
                d = d << 4 | pin[c++];
            else
                d = d << 4 | 0xF;
            pinblock.push_back(d);
        }
        while (pinblock.size() < 8) {
            pinblock.push_back(0xFF);
        }
        return pinblock;
    }

    vector<uint8_t> constructPinblockForCrypto(vector<uint8_t>& pinBlock, vector<uint8_t>& un, int keyLen) {
        cout << "PIN block:";
        vectorPrint(pinBlock);
        cout << "Unpredictable number:";
        vectorPrint(un);
        
        cout << "keyLen:" << keyLen << endl;
        cout << "Pin block size:" << pinBlock.size() << endl;
        cout << "Unpredictable number size:" << un.size() << endl;

        vector<unsigned char> res;
        res.push_back(0x7F);

        if (pinBlock.size() != 8)
            throw runtime_error("pb size != 8");
        if (un.size() != 8)
            throw runtime_error("un size != 8");

        for (auto& b : pinBlock)
            res.push_back(b);

        for (auto& b : un)
            res.push_back(b);

        while (res.size() < keyLen)
            res.push_back(crypto.getRandomByte());

        return res;
    }

    int getPinTryCounter() {
        vector<uint8_t> data;
        if (command->getData(0x9F17, data) == 0x9000) {
            auto t = TLV::parseTlv(data);
            transactionObjects.put(t);
            cout << tlvPrint(t) << endl;
            return t.V()[0];
        }
        return 0;
    }

    vector<uint8_t> prepareEncryptedPinBlock(vector<uint8_t>& pinBlock) {
        vector<uint8_t> challenge;

        auto sw1sw2 = command->getChallenge(challenge);
        cout << "Challenge: ";
        vectorPrint(challenge);

        if (sw1sw2 != 0x9000 || challenge.size() != 8)
            throw runtime_error("getChallenge failed");

        vector<uint8_t> un;
        for (int i = 0; i < 8; i++) {
            un.push_back(challenge[i]);
        }

        cout << "Retrieving PIN PK certificate" << endl;
        auto cert = crypto.retrievePinPKCertificate();
        if (cert == 0) {
            cout << "Retrieving ICC PK certificate" << endl;
            cert = crypto.retrieveIccPKCertificate();
        }

        cout << "Constructing pin block for encryption" << endl;
        auto pbc = constructPinblockForCrypto(pinBlock, un, cert->iccPK.size());

        vectorPrint(pinBlock);
        vectorPrint(pbc);
        vectorPrint(cert->iccPK);

        cout << "Encrypting pin:" << endl;

        auto pbEnc = crypto.recover(pbc, cert->iccPK);

        cout << "pbEnc" << endl;
        vectorPrint(pbEnc);

        return pbEnc;
    }

    bool offlinePin(bool plain) {
        int ptc = getPinTryCounter();
        auto tvr = transactionObjects.get<TVR>(0x95);

        cout << "PIN TRY COUNTER:" << ptc << endl;
        if (ptc == 0) {
            tvr->setPINTryLimitExceeded();
            cout << "PIN TRIES EXCEEDED" << endl;
            return false;
        }

        auto digits = plainPinEntry();
        auto pinblock = constructISO2Pinblock(digits);

        if (!plain) {
            try {
                pinblock = prepareEncryptedPinBlock(pinblock);
            } catch (const exception& e) {
                cout << "PIN ENCRYPTION ERROR:" << e.what() << endl;
                throw e;
            }
        }

        auto res = command->verify(plain, pinblock);

        if (res == 0x9000) {
            cout << "PIN VERIFIED" << endl;
            return true;
        }

        // 63CX
        if ((res & 0x63C0) == 0x63C0) {
            cout << "PIN TRIES LEFT:" << (res & 0x0F) << endl;
            
            if((res & 0x0F) == 0){
                tvr->setPINTryLimitExceeded(); 
            }
            //idealy need to retry in case of attempts still available, however for this demo it is not required
            return false;
        }

        if (res == 0x6983 || res == 0x6984) {
            tvr->setPINTryLimitExceeded();
            return false;
        }

        throw runtime_error(format("PIN VERIFY ERROR:0x{:X}", res));
    }

    bool onlinePin() {
        return true;
    }  // since we do just an example, we don't actually need pin to be entered

    void peformCVM() {
        auto aip = transactionObjects.get<AIP>(0x82);
        auto tvr = transactionObjects.get<TVR>(0x95);
        auto tsi = transactionObjects.get<TSI>(0x9B);
        auto cvmResult = transactionObjects.put<CvmResults>(0x9F34, { 0x3F, 0x00, 0x00 });

        if (!aip->cardholderVerificationSupported) {
            cout << "Cardholder verification not supported" << endl;
            return;
        }

        auto cvmListParsed = transactionObjects.get<CVMList>(0x8E);
        if (!cvmListParsed) {
            cout << "CVM list not found" << endl;
            tvr->setICCDataMissing();
            return;
        }

        cout << cvmListPrint(*cvmListParsed) << endl;

        auto terminalCapabilities = transactionObjects.get<TerminalCapabilities>(0x9F33);
        terminalCapabilities->toStream(cout);

        auto terminalType = (*transactionObjects.get(0x9F33))[0];
        auto tranctionType = (*transactionObjects.get(0x9C))[0];

        bool unattendedCash =
            (terminalType == 0x12 || (terminalType >= 0x24 && terminalType <= 0x26)) &&
            (tranctionType == TransactionType::CashAdvance || tranctionType == TransactionType::PurchaseWithCashBack ||
             tranctionType == TransactionType::CashWithdrawal);

        cout << "Unattended cash: " << (unattendedCash ? "true" : "false") << endl;

        auto transactionCurrecyCode = transactionObjects.get(0x5F2A);
        auto applicationCurrencyCode = transactionObjects.get(0x9F42);
        auto transactionAmountVector = transactionObjects.get(0x9F02);

        if (!transactionAmountVector)
            throw runtime_error("transactionAmountVector is empty");
        if (!transactionCurrecyCode)
            throw runtime_error("transactionCurrecyCode is empty");

        bool currencyIsTheSame = true;

        if (applicationCurrencyCode) {
            currencyIsTheSame =
                equal(transactionCurrecyCode->begin(), transactionCurrecyCode->end(), applicationCurrencyCode->begin());
        }

        long transactionAmount = bcdToLong(*transactionAmountVector);

        for (auto& cvmEntry : cvmListParsed->entries) {
            cout << "Considering CVM:" << CVMToString(cvmEntry.rule.cvm) << endl;

            bool cvmConditionSatisfied = false;
            bool cvmConditionSupported = terminalCapabilities->supportCvm(cvmEntry.rule.cvm);

            switch (cvmEntry.condition) {
                case CVCondition::Always: {
                    cvmConditionSatisfied = true;
                    break;
                }
                case CVCondition::IfUnattendedCash: {
                    cvmConditionSatisfied = unattendedCash;
                    break;
                }
                case CVCondition::IfNotUnattendedCashAndNotManualCashAndNotNurchaseWithCashback: {
                    cvmConditionSatisfied = !unattendedCash;
                    break;
                }
                case CVCondition::IfTerminalSupportsTheCVM: {
                    cvmConditionSatisfied = cvmConditionSupported;
                    break;
                }
                case CVCondition::IfManualCash: {
                    cvmConditionSatisfied = tranctionType == TransactionType::CashAdvance;
                    break;
                }
                case CVCondition::IfPurchaseWithCashback: {
                    cvmConditionSatisfied = tranctionType == TransactionType::PurchaseWithCashBack;
                    break;
                }
                case CVCondition::IfAppCurrencyAndAmountUnderX: {
                    cvmConditionSatisfied = currencyIsTheSame && transactionAmount < cvmListParsed->X;
                    break;
                }
                case CVCondition::IfAppCurrencyAndAmountOverX: {
                    cvmConditionSatisfied = currencyIsTheSame && transactionAmount >= cvmListParsed->X;
                    break;
                }
                case CVCondition::IfAppCurrencyAndAmountUnderY: {
                    cvmConditionSatisfied = currencyIsTheSame && transactionAmount < cvmListParsed->Y;
                    break;
                }
                case CVCondition::IfAppCurrencyAndAmountOverY: {
                    cvmConditionSatisfied = currencyIsTheSame && transactionAmount >= cvmListParsed->Y;
                    break;
                }
                default:
                    break;
            }

            if (cvmConditionSatisfied && !cvmConditionSupported) {
                cout << "Condition is satisfied, but terminal does not support CVM:" << CVMToString(cvmEntry.rule.cvm) << endl;

                if (cvmEntry.rule.cvm == CVM::EncipheredPINVerifiedOnline) {
                    tvr->setPINEntryRequiredAndPinPadNotPresentOrNotWorking();
                }
                if (cvmEntry.rule.cvm == CVM::EncipheredPINVerificationPerformedByICC ||
                    cvmEntry.rule.cvm == CVM::PlaintextPINVerificationPerformedByICCAndSignature ||
                    cvmEntry.rule.cvm == CVM::PlaintextPINVerificationperformedICC) {
                    if (!(terminalCapabilities->supportCvm(CVM::EncipheredPINVerificationPerformedByICC) ||
                          terminalCapabilities->supportCvm(CVM::EncipheredPINVerificationPerformedByICC))) {
                        tvr->setPINEntryRequiredAndPinPadNotPresentOrNotWorking();
                    }
                }
            }

            bool cvmSucceeded = false;

            if (cvmConditionSatisfied && cvmConditionSupported) {
                cout << "Condition satisfied & supported" << cvmConditionSatisfied << endl;
                cvmResult->setCvmPerformed(cvmEntry.rule.cvm);
                cvmResult->setCvmCondition(cvmEntry.condition);
                cvmResult->setCvmResult(CvmResult::Unknown);

                switch (cvmEntry.rule.cvm) {
                    case CVM::FailCVMProcessing: {
                        cvmSucceeded = false;
                        break;  
                    }
                    case CVM::PlaintextPINVerificationperformedICC: {
                        cvmSucceeded = offlinePin(true);
                        if (cvmSucceeded)
                            cvmResult->setCvmResult(CvmResult::Success);
                        break;
                    }
                    case CVM::EncipheredPINVerifiedOnline: {
                        cvmSucceeded = onlinePin();
                        if (cvmSucceeded) {
                            tvr->setOnlinePINEntered();
                            cvmSucceeded = true;
                        }
                        break;
                    }
                    case CVM::PlaintextPINVerificationPerformedByICCAndSignature: {
                        cvmSucceeded = offlinePin(true);
                        break;
                    }
                    case CVM::EncipheredPINVerificationPerformedByICC: {
                        cvmSucceeded = offlinePin(false);
                        if (cvmSucceeded)
                            cvmResult->setCvmResult(CvmResult::Success);
                        break;
                    }
                    case CVM::EncipheredPINVerificationPerformedByICCAndSignature: {
                        cvmSucceeded = offlinePin(false);
                        break;
                    }
                    case CVM::Signature: {
                        cvmSucceeded = true;
                        break;
                    } break;
                    case CVM::NoCVM: {
                        cvmResult->setCvmResult(CvmResult::Success);
                        cvmSucceeded = true;
                        break;
                    }
                    default:
                        break;
                }
                if (cvmSucceeded) {
                    break;
                } else {
                    cvmResult->setCvmResult(CvmResult::Failed);
                    if (!cvmEntry.rule.nextOnUnsuccess) {
                        break;
                    }
                }
            } else {
                cvmResult->setCvmResult(CvmResult::Failed);
            }
        }
        if (cvmResult->getCvmResult() == CvmResult::Failed) {
            tvr->setCardholderVerificationWasNotSuccessful();
        }
        tsi->setCardholderVerificationWasPerformed();
        
        cvmResult->toStream(cout);
        tvr->toStream(cout);
    }

    ExecutionResult execute() override{
        cout << "*************************" << endl;
        cout << "[CARDHOLDER VERIFICATION]" << endl;
        cout << "*************************" << endl;

        try {
            peformCVM();
        } catch (const exception& e) {
            cerr << "Exception caught in Cardholder::execute: " << e.what() << endl;
            return ExecutionResult::Terminate;
        } catch (...) {
            cerr << "Unknown exception caught in Cardholder::execute" << endl;
            return ExecutionResult::Terminate;
        }

        return ExecutionResult::Success;
    }

    ~Cardholder() override {};
};
#endif