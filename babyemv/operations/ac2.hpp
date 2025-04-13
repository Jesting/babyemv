#ifndef __AC2__
#define __AC2__

#include "operation.hpp"
#include "../settings.hpp"
#include "../structures/dol.hpp"
#include "../structures/tvr.hpp"
#include "../structures/auc.hpp"
#include "../structures/termcaps.hpp"
#include "../structures/enums.hpp"
#include "../structures/certs.hpp"
#include "../structures/aip.hpp"
#include "../structures/actype.hpp"
#include "../rsautils.hpp"
#include "crypto.hpp"

class AC2 : public Operation {
  private:
    Crypto& crypto;
    Oda& oda;

  public:
    AC2(TransactionObjects& _transactionObjects, Command* _command, Oda& _oda, Crypto& _crypto)
      : Operation(_transactionObjects, _command), oda(_oda), crypto(_crypto) {
    }
    // IAD 91 var8-16
    // Authorisation Response Code (ARC) - an2 8A
    // 9f37 Unpredictable Number (UN)
    // 9f4C ICC Dynamic Number
    AC ac2() {
        auto cdol2 = transactionObjects.get<DOL>(0x8D);

        crypto.calculateTCHash();
        // crypto.genUN();

        vector<unsigned char> response;
        auto tag8A = transactionObjects.get(0x8A);
        
        AC ac = AC::AAC;
        if(tag8A && (tag8A->at(0) == 0x30 &&  tag8A->at(1) == 0x30)){
            ac = AC::TC;
        }

        auto res = command->genAc(ac, oda.cdaRequired, cdol2->build(), response);

        auto tlv = TLV::parseTlv(response);
        transactionObjects.put(tlv);
        cout << tlvPrint(tlv) << endl;

        AC acResult = static_cast<AC>(transactionObjects.get(0x9F27)->at(0));

        if (acResult != AC::AAC) {
            if (oda.cdaRequired) {
                oda.makeCDA(tlv, 2);
            }
        }

        return acResult;
    }

    ExecutionResult execute() override{
        cout << "**************************" << endl;
        cout << "[APPLICATION CRYPTOGRAM 2]" << endl;
        cout << "**************************" << endl;
        try {
            AC ac = ac2();
            if (ac == AC::AAC) {
                return ExecutionResult::Denied;
            }
            if (ac == AC::TC) {
                return ExecutionResult::Approved;
            }
        } catch (const char* e) {
            cout << "AC2 error:" << e << endl;
            return ExecutionResult::Terminate;
        }
        return ExecutionResult::Terminate;
    }

    ~AC2() override {};
};
#endif