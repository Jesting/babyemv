#ifndef __ODA__
#define __ODA__

#include "operation.hpp"
#include "../settings.hpp"
#include "../structures/dol.hpp"
#include "../structures/tvr.hpp"
#include "../structures/auc.hpp"
#include "../structures/termcaps.hpp"
#include "../structures/enums.hpp"
#include "../structures/certs.hpp"
#include "../structures/aip.hpp"
#include "../structures/tsi.hpp"
#include "../rsautils.hpp"
#include "crypto.hpp"

struct DRSDAD {
    uint8_t header;
    uint8_t signedDataFormat;
    uint8_t hashAlgorithmIndicator;
    uint8_t iddLength;
    vector<uint8_t> idd;
    vector<uint8_t> hash;
    uint8_t trailer;

    void toStream(ostream& ss) {
        ss << "┌─DRSDAD──────────────────────────────────" << endl;
        ss << "├─" << "Header                      : " << hex << (int)header << endl;
        ss << "├─" << "Signed data format          : " << hex << (int)signedDataFormat << endl;
        ss << "├─" << "Hash algorithm indicator    : " << hex << (int)hashAlgorithmIndicator << endl;
        ss << "├─" << "IDD Length                  : " << hex << (int)iddLength << endl;
        ss << "├─" << "IDD                         : " << hex << vectorPrint(idd, ss) << endl;
        ss << "├─" << "Hash                        : " << hex << vectorPrint(hash, ss) << endl;
        ss << "├─" << "Trailer                     : " << hex << (int)trailer << endl;
    }
};

struct IccDynamicDataCDA {
    vector<unsigned char> idn;
    unsigned char cid;
    vector<unsigned char> ac;
    vector<unsigned char> hashCode;
    void toStream(ostream& ss) {
        ss << "┌─IccDynamicDataCDA─────────────────────────" << endl;
        ss << "├─" << "IDN                         : " << hex << vectorPrint(idn, ss) << endl;
        ss << "├─" << "CID                         : " << hex << (int)cid << endl;
        ss << "├─" << "AC                          : " << hex << vectorPrint(ac, ss) << endl;
        ss << "├─" << "Hash Code                   : " << hex << vectorPrint(hashCode, ss) << endl;
    }
};

class Oda : public Operation {
  private:
    Crypto& crypto;

    IccDynamicDataCDA parseIccDynamicDataCDA(vector<unsigned char>& data) {
        IccDynamicDataCDA iddCda;
        int c = 0;
        iddCda.idn.insert(iddCda.idn.end(), data.begin() + 1, data.begin() + 1 + data[c]);
        c = 1 + data[0];
        iddCda.cid = data[c++];

        for (int i = 0; i < 8; i++)
            iddCda.ac.push_back(data[c++]);

        for (int i = 0; i < 20; i++)
            iddCda.hashCode.push_back(data[c++]);
        return iddCda;
    }

    DRSDAD parseDRSDAD(vector<unsigned char>& data) {
        int c = 0;

        DRSDAD dads;

        dads.header = data[c++];

        dads.signedDataFormat = data[c++];

        dads.hashAlgorithmIndicator = data[c++];

        dads.iddLength = data[c++];

        auto l = dads.iddLength;
        while (l--)
            dads.idd.push_back(data[c++]);

        for (int i = 0; i < 20; i++)
            dads.hash.push_back(data[data.size() - 21 + i]);
        dads.trailer = data[data.size() - 1];

        return dads;
    }

    void makeDDA() {
        auto tvr = transactionObjects.get<TVR>(0x95);
        auto tsi = transactionObjects.get<TSI>(0x9B);

        auto ddol = transactionObjects.get<DOL>(0x9F49);
        crypto.genUN();
        crypto.calculateTCHash();

        vector<unsigned char> response;

        const vector<uint8_t> ddolData = ddol->build();
        int res = command->internalAuthenticate(ddolData, response);

        auto tlv = TLV::parseTlv(response);
        transactionObjects.put(tlv);
        cout << tlvPrint(tlv) << endl;
        cout << "Internal auth returned: " << hex << res << endl;

        auto sdad = transactionObjects.get(0x9F4B);
        if (!sdad)
            return;

        auto recovered = crypto.recoverIccPKData(*sdad);

        bool ddaFailed = false;
        auto drsdad = parseDRSDAD(recovered);
        drsdad.toStream(cout);

        if (drsdad.header != 0x6A) {
            ddaFailed = true;
        }
        if (drsdad.signedDataFormat != 0x05) {
            ddaFailed = true;
        }
        if (drsdad.hashAlgorithmIndicator != 0x01) {
            ddaFailed = true;
        }

        if (!ddaFailed) {
            vector<uint8_t> dataForHash;
            dataForHash.insert(dataForHash.end(), recovered.begin() + 1, recovered.end() - 21);
            dataForHash.insert(dataForHash.end(), ddolData.begin(), ddolData.end());

            vector<uint8_t> hash;
            hash.insert(hash.end(), recovered.end() - 21, recovered.end() - 1);
            auto hashCalculated = crypto.sha1hash(dataForHash);

            ddaFailed = !equal(hash.begin(), hash.end(), hashCalculated.begin());
            cout << "HASH VERIFIED: " << (!ddaFailed ? "true" : "false") << endl;
        }

        if (ddaFailed) {
            tvr->setDdaFailed();
        } else {
            vector<uint8_t> idn;
            idn.insert(idn.end(), drsdad.idd.begin() + 1, drsdad.idd.begin() + 1 + drsdad.idd[0]);
            cout << "IDN:";
            vectorPrint(idn);

            transactionObjects.put(0x9f4c, idn);
            tsi->setOfflinevalueAuthenticationWasPerformed();
        }
    }

    vector<uint8_t> tagsFromResponse(TLV& responseTags) {
        vector<uint8_t> res;

        for (auto& t : responseTags.tags) {
            if (t.T != 0x9F4B)
                res.insert(res.end(), t.data.begin(), t.data.end());
        }
        return res;
    }

    void makeSDA() {
        throw runtime_error("SDA not implemented");
    }

    void makeODA() {
        auto caps = transactionObjects.get<TerminalCapabilities>(0x9F33);
        auto aip = transactionObjects.get<AIP>(0x82);
        auto tvr = transactionObjects.get<TVR>(0x95);
        auto terminalType = (*transactionObjects.get(0x9F35))[0];

        if (terminalType == 11 || terminalType == 21 || terminalType == 14 || terminalType == 24) {
            tvr->setOfflineDataAuthenticationWasNotPerformed();
            return;
        }
        if (aip->cdaSupported && caps->cdaSupport) {
            cout << "CDA selected" << endl;
            cdaRequired = true;

        } else if (aip->ddaSupported && caps->ddaSupport) {
            cout << "DDA selected" << endl;
            makeDDA();

        } else if (aip->sdaSupported && caps->sdaSupport) {
            cout << "SDA selected" << endl;
            makeSDA();
        } else {
            tvr->setOfflineDataAuthenticationWasNotPerformed();
        }
    }
    vector<uint8_t> cdol1;

  public:
    Oda(TransactionObjects& _transactionObjects, Command* _command, Crypto& _crypto)
      : Operation(_transactionObjects, _command), crypto(_crypto) {
    }
    bool cdaRequired = false;

    bool makeCDA(TLV& responseTags, int acNo) {
        auto tvr = transactionObjects.get<TVR>(0x95);
        auto tsi = transactionObjects.get<TSI>(0x9B);

        
        auto sdad = transactionObjects.get(0x9F4B);
        if (!sdad){
            tvr->setCdaFailed();
            return false;
        }

        bool cdaFailed = false;
        auto recovered = crypto.recoverIccPKData(*sdad);
        auto drsdad = parseDRSDAD(recovered);
        drsdad.toStream(cout);

        if (drsdad.header != 0x6A) {
            cdaFailed = true;
        }
        if (drsdad.signedDataFormat != 0x05) {
            cdaFailed = true;
        }
        if (drsdad.hashAlgorithmIndicator != 0x01) {
            cdaFailed = true;
        }

        if (!cdaFailed) {
            vector<uint8_t> dataForHash;

            auto un = *transactionObjects.get(0x9f37);

            dataForHash.insert(dataForHash.end(), recovered.begin() + 1, recovered.end() - 21);

            dataForHash.insert(dataForHash.end(), un.begin(), un.end());

            vector<uint8_t> hash;
            hash.insert(hash.end(), recovered.end() - 21, recovered.end() - 1);
            auto hashCalculated = crypto.sha1hash(dataForHash);

            cdaFailed = !equal(hash.begin(), hash.end(), hashCalculated.begin());
            cout << "HASH VERIFIED: " << (!cdaFailed ? "true" : "false") << endl;
        }

        if (!cdaFailed) {
            auto pdolObj = transactionObjects.get<DOL>(0x9f38);
            vector<uint8_t> pdol = {};

            if (pdolObj)
                pdol = pdolObj->build();

            if (acNo == 1)
                cdol1 = transactionObjects.get<DOL>(0x8C)->build();

            auto tags = tagsFromResponse(responseTags);

            vector<uint8_t> dataForhash;

            dataForhash.insert(dataForhash.end(), pdol.begin(), pdol.end());
            dataForhash.insert(dataForhash.end(), cdol1.begin(), cdol1.end());

            if (acNo == 2) {
                auto cdol2 = transactionObjects.get<DOL>(0x8D)->build();
                dataForhash.insert(dataForhash.end(), cdol2.begin(), cdol2.end());
            }
            dataForhash.insert(dataForhash.end(), tags.begin(), tags.end());

            auto hashCalculated = crypto.sha1hash(dataForhash);

            auto iddCda = parseIccDynamicDataCDA(drsdad.idd);

            iddCda.toStream(cout);

            cdaFailed = !equal(iddCda.hashCode.begin(), iddCda.hashCode.end(), hashCalculated.begin());
            cout << "HASH VERIFIED: " << (!cdaFailed ? "true" : "false") << endl;

            if (!cdaFailed)
                transactionObjects.put(0x9f4c, iddCda.idn);
        }
        
        if (cdaFailed) {
            tvr->setCdaFailed();
            cdaRequired = false;
        } else {
            tsi->setOfflinevalueAuthenticationWasPerformed();
        }

        return cdaFailed;
    }

    ExecutionResult execute() override{
        cout << "*****************************" << endl;
        cout << "[OFFLINE DATA AUTHENTICATION]" << endl;
        cout << "*****************************" << endl;
        try {
            makeODA();
        } catch (const exception& e) {
            cout << "ODA ERROR: " << e.what() << endl;
            return ExecutionResult::Terminate;
        }
        return ExecutionResult::Success;
    }

    ~Oda() override {};
};
#endif