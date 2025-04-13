#ifndef __AC1__
#define __AC1__

#include "operation.hpp"
#include "../settings.hpp"
#include "../structures/tvr.hpp"
#include "../structures/auc.hpp"
#include "../structures/termcaps.hpp"
#include "../structures/enums.hpp"
#include "../structures/certs.hpp"
#include "../structures/aip.hpp"
#include "../structures/actype.hpp"
#include "../structures/dol.hpp"
#include "../rsautils.hpp"
#include "oda.hpp"

class AC1 : public Operation {
  private:
    Crypto& crypto;
    Oda& oda;

  public:
    AC1(TransactionObjects& _transactionObjects, Command* _command, Oda& _oda, Crypto& _crypto)
      : Operation(_transactionObjects, _command), oda(_oda), crypto(_crypto) {
    }

    AC riskManagement() {
        auto tvr = transactionObjects.get(0x95);

        auto iacDenial = transactionObjects.getOrDefault(0x9F0E, { 0, 0, 0, 0, 0 });
        auto iacDefault = transactionObjects.getOrDefault(0x9F0D, { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
        auto iacOnline = transactionObjects.getOrDefault(0x9F0F, { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });

        auto tacDefault = transactionObjects.get(TAC_DEFAULT);
        auto tacDenial = transactionObjects.get(TAC_DENIAL);
        auto tacOnline = transactionObjects.get(TAC_ONLINE);

        uint8_t denial = 0;
        uint8_t online = 0;
        uint8_t deflt = 0;
        for (int i = 0; i < 5; i++) {
            denial |= (iacDenial->at(i) & tvr->at(i)) | (tacDenial->at(i) & tvr->at(i));
            online |= (iacOnline->at(i) & tvr->at(i)) | (tacOnline->at(i) & tvr->at(i));
            deflt |= (iacDefault->at(i) & tvr->at(i)) | (tacDefault->at(i) & tvr->at(i));
        }

        if (denial) {
            cout << "Denial check (IAC/TAC/TVR)" << endl;
            vectorPrint(*iacDenial);
            vectorPrint(*tacDefault);
            vectorPrint(*tvr);
        }
        if (online) {
            cout << "Online check (IAC/TAC/TVR)" << endl;
            vectorPrint(*iacOnline);
            vectorPrint(*tacOnline);
            vectorPrint(*tvr);
        }
        if ((!online) & deflt) {
            cout << "Default check (IAC/TAC/TVR)" << endl;
            vectorPrint(*iacDefault);
            vectorPrint(*tacDefault);
            vectorPrint(*tvr);
        }

        if (denial)
            return AC::AAC;
        else if (online)
            return AC::ARQC;
        else if (deflt)
            return AC::TC;
        return AC::AAC;
    }

    AC ac1(bool& cdaFailed) {
        auto tvr = transactionObjects.get<TVR>(0x95);

        auto ac = riskManagement();
        
        crypto.genUN();
        
        auto cdol1 = transactionObjects.get<DOL>(0x8C);
        crypto.calculateTCHash();

        vector<unsigned char> response;
        auto res = command->genAc(ac, oda.cdaRequired, cdol1->build(), response);

        auto tlv = TLV::parseTlv(response);
        transactionObjects.put(tlv);
        cout << tlvPrint(tlv) << endl;

        AC acResult = static_cast<AC>(transactionObjects.get(0x9F27)->at(0));
        
        if (acResult != AC::AAC) {
            if (oda.cdaRequired) {
                cdaFailed = oda.makeCDA(tlv, 1);
            }
        }
        
        return acResult;
    }

    ExecutionResult execute() override{
        cout << "**************************" << endl;
        cout << "[APPLICATION CRYPTOGRAM 1]" << endl;
        cout << "**************************" << endl;
        try {
            bool cdaFailed;
            AC ac = ac1(cdaFailed);
            if (ac == AC::AAC) {
                return ExecutionResult::Denied;
            }
            if (ac == AC::TC) {
                return ExecutionResult::Approved;
            }
            if (ac == AC::ARQC) {
                if(cdaFailed){ 
                    return ExecutionResult::OnlineButCdaFailed;
                } else{
                    return ExecutionResult::Online;
                }
            }
        } catch (const char* e) {
            cout << "AC1 error:" << e << endl;
            return ExecutionResult::Terminate;
        }
        return ExecutionResult::Terminate;
    }

    ~AC1() override {};
};
#endif