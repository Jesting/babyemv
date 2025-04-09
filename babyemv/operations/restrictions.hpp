#ifndef __RESTRICTIONS__
#define __RESTRICTIONS__
#include "operation.hpp"
#include "../settings.hpp"
#include "../structures/dol.hpp"
#include "../structures/tvr.hpp"
#include "../structures/auc.hpp"
#include "../structures/termcaps.hpp"
#include "../structures/enums.hpp"
#include <format>

class Restrictions : public Operation {
  public:
    using Operation::Operation;

    void checkCriticalDataPresence() {
        vector<uint32_t> tags = {
            0x5A, 0x5F24, 0x8C, 0x8D, 0x9F08, 0x9A, 0x9F35, 0x9F40, 0x9C, 0x9F1A
        };  // terminal tags from here
        for_each(tags.begin(), tags.end(), [&](uint32_t t) {
            if (!transactionObjects.get(t))
                throw runtime_error(format("Critical TAG absent({:X})", t));
        });
    }

    void appVersionCheck() {  // no natter what is the version, we search for a difference
        cout << "[APP VERSION CHECK]" << endl;

        auto avnCard = transactionObjects.get(0x9F08);
        auto avnTerminal = transactionObjects.get(0x9F09);
        if (avnCard && avnCard->size() != 2)
            return;

        if (!equal(avnCard->begin(), avnCard->end(), avnTerminal->begin())) {
            auto tvr = transactionObjects.get<TVR>(0x95);
            tvr->setICCAndTerminalHaveDifferentApplicationVersions();
        }
    }

    void expirationCheck() {
        cout << "[EXPIRATION CHECK]" << endl;
        auto transactionDate = transactionObjects.get(0x9A);  // YYMMDD
        auto tvr = transactionObjects.get<TVR>(0x95);

        auto applicationEffectiveDate = transactionObjects.get(0x5F25);  // YYMMDD
        auto applicationExpiryDate = transactionObjects.get(0x5F24);     // YYMMDD

        auto trxDate = bcdToLong(*transactionDate);

        if (applicationEffectiveDate) {
            auto appEffectiveDate = bcdToLong(*applicationEffectiveDate);
            if (trxDate < appEffectiveDate) {
                tvr->setApplicationNotYetEffective();
            }
        }

        if (applicationExpiryDate) {
            auto appExpiryDate = bcdToLong(*applicationExpiryDate);
            if (trxDate > appExpiryDate) {
                tvr->setExpiredApplication();
            }
        }
    }

    bool isAllowedForATMorTerminal(uint8_t terminalType, shared_ptr<AUC> auc) {
        auto additionalTerminalCapabilities = transactionObjects.get<AdditionalTerminalCapabilities>(0x9F40);

        additionalTerminalCapabilities->toStream(cout);

        bool isAtm = (terminalType >= 0x14 && terminalType <= 0x16) && additionalTerminalCapabilities->cash;

        if (isAtm) {
            return auc->validAtATMs && isAtm;
        } else {
            return auc->validForOtherThanAtms;
        }
    }

    bool isDomestic(vector<uint8_t>* issuerCountryCode) {
        auto terminalCountryCode = transactionObjects.get(0x9F1A);

        return equal(issuerCountryCode->begin(), issuerCountryCode->end(), terminalCountryCode->begin());
    }

    bool isAllowedIfCashWithdrawal(uint8_t tranctionType, bool domestic, shared_ptr<AUC> auc) {
        if (tranctionType == 0x01 || (tranctionType >= 17 && tranctionType <= 19)) {
            if (domestic) {
                return auc->validForDomesticCash;
            } else {
                return auc->validForInternationalCash;
            }
        }
        return true;
    }

    bool isAllowedIfPurchase(uint8_t tranctionType, bool domestic, shared_ptr<AUC> auc) {
        if (tranctionType == TransactionType::Purchase) {
            if (domestic) {
                return auc->validForDomesticGoods;
            } else {
                return auc->validForInternationalGoods;
            }
        }
        return true;
    }

    bool isAllowedIfBillPayment(uint8_t tranctionType, bool domestic, shared_ptr<AUC> auc) {
        if (tranctionType == TransactionType::PaymentBillPayment) {
            if (domestic) {
                return auc->validForDomesticServices;
            } else {
                return auc->validForInternationalServices;
            }
        }
        return true;
    }

    bool isAllowedIfBillPaymentAndPurchase(uint8_t tranctionType, bool domestic, shared_ptr<AUC> auc) {
        if (tranctionType == TransactionType::PurchaseWithCashBack) {
            if (domestic) {
                return auc->validForDomesticCashback;
            } else {
                return auc->validForInternationalCashback;
            }
        }
        return true;
    }

    void applicationUsageControl() {
        cout << "applicationUsageControl>>>" << endl;
        auto auc = transactionObjects.get<AUC>(0x9F07);
        if (!auc) {
            cout << "AUC absent, control skipped" << endl;
            return;
        }

        auto tvr = transactionObjects.get<TVR>(0x95);
        auc->toStream(cout);
        tvr->toStream(cout);

        auto terminalType = transactionObjects.get(0x9F35)->at(0);
        auto additionalTerminalCapabilities = transactionObjects.get<AdditionalTerminalCapabilities>(0x9F40);
        auto tranctionType = transactionObjects.get(0x9C)->at(0);
        auto amountOther = transactionObjects.get(0x9F04);

        if (!isAllowedForATMorTerminal(terminalType, auc)) {
            tvr->setServiceNotAllowedForCardProduct();
            return;
        }

        auto issuerCountryCode = transactionObjects.get(0x5F28);
        if (!issuerCountryCode)
            return;
        auto terminalCountryCode = transactionObjects.get(0x9F1A);
        bool domestic = isDomestic(issuerCountryCode);

        if (!isAllowedIfCashWithdrawal(tranctionType, domestic, auc)) {
            tvr->setServiceNotAllowedForCardProduct();
            return;
        }
        if (!isAllowedIfPurchase(tranctionType, domestic, auc)) {
            tvr->setServiceNotAllowedForCardProduct();
            return;
        }

        if (!isAllowedIfBillPayment(tranctionType, domestic, auc)) {
            tvr->setServiceNotAllowedForCardProduct();
            return;
        }

        if (!isAllowedIfBillPaymentAndPurchase(tranctionType, domestic, auc)) {
            tvr->setServiceNotAllowedForCardProduct();
            return;
        }
    }

    ExecutionResult execute() override{
        cout << "*************************" << endl;
        cout << "[PROCESSING RESTRICTIONS]" << endl;
        cout << "*************************" << endl;
        try{
            appVersionCheck();
            expirationCheck();
            applicationUsageControl();
        }catch (const exception& e) {
            cout << "Error: " << e.what() << endl;
            return ExecutionResult::Terminate;
        }
        return ExecutionResult::Success;
    }

    ~Restrictions() override {};
};
#endif