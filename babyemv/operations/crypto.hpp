#ifndef __CRYPTO__
#define __CRYPTO__

#include "operation.hpp"
#include "../settings.hpp"
#include "../structures/tvr.hpp"
#include "../structures/auc.hpp"
#include "../structures/termcaps.hpp"
#include "../structures/enums.hpp"
#include "../structures/certs.hpp"
#include "../rsautils.hpp"
#include "../structures/dol.hpp"
#include <random>

class Crypto : public Operation {
  private:
    CertsCache certs;
    Setttings& settings;
    mt19937 gen;
    uniform_int_distribution<size_t> dist;

  public:
    Crypto(TransactionObjects& _transactionObjects, Command* _command, Setttings& _settings)
      : Operation(_transactionObjects, _command), settings(_settings), gen(random_device{}()) {
    }

    shared_ptr<CAPK> retrieveCAPK() {
        if (certs.capk) {
            return certs.capk;
        }
        if (!certs.capk) {
            auto aid = transactionObjects.get(0x84);
            auto caplkIdx = transactionObjects.get(0x8F);

            if (!aid || !caplkIdx)
                return 0;
                
            certs.capk = make_shared<CAPK>(settings.getCapk(*aid, caplkIdx->at(0)));
        }
        return certs.capk;
    }

    shared_ptr<IssuerPKCertificate> retrieveIssuerPKCertificate() {
        if (certs.issuer)
            return certs.issuer;
        auto issuerPKCertificate = transactionObjects.get(0x90);
        if (!issuerPKCertificate)
            return 0;
        auto capk = retrieveCAPK();
        if (capk == 0)
            return 0;
        
        auto recovered = recover(*issuerPKCertificate, capk->modulus);
        
        certs.issuer = make_shared<IssuerPKCertificate>(IssuerPKCertificate(recovered, *transactionObjects.get(0x92)));
        return certs.issuer;
    }

    shared_ptr<ICCPKCertificate> retrieveIccPKCertificate() {
        if (certs.icc)
            return certs.icc;
    
        auto issuer = retrieveIssuerPKCertificate();
        if (issuer == 0)
            return 0;
        
        auto iccPKCertificate = transactionObjects.get(0x9F46);
        if (!iccPKCertificate)
            return 0;

        auto recovered = recover(*iccPKCertificate, issuer->issuerPK);
        
        vectorPrint(recovered);
        certs.icc = make_shared<ICCPKCertificate>(ICCPKCertificate(recovered, *transactionObjects.get(0x9F48)));
        return certs.icc;
    }

    shared_ptr<ICCPKCertificate> retrievePinPKCertificate() {
        if (certs.pin)
            return certs.pin;
        auto issuer = retrieveIssuerPKCertificate();
        if (issuer == 0)
            return 0;

        auto pinPKCertificate = transactionObjects.get(0x9F2D);
        if (!pinPKCertificate)
            return 0;

        auto recovered = recover(*pinPKCertificate, issuer->issuerPK);
        certs.pin = make_shared<ICCPKCertificate>(ICCPKCertificate(recovered, *transactionObjects.get(0x9F2F)));
        return certs.pin;
    }

    vector<unsigned char> calculateTCHash() {
        auto tdol = transactionObjects.get<DOL>(0x97);
        if (!tdol)
            return {};
        auto tdolData = tdol->build();
        transactionObjects.put(0x98, tdolData);
        return sha1(tdolData);
    }

    vector<uint8_t> recoverIccPKData(vector<uint8_t>& sdad) {
        auto iccPKcert = retrieveIccPKCertificate();
        return recover(sdad, iccPKcert->iccPK);
    }

    vector<uint8_t> recover(vector<uint8_t>& data, vector<uint8_t>& key){
        return rsa_recover(data, key);
    }

    vector<uint8_t> sha1hash(vector<uint8_t>& dataForHash) {
        return sha1(dataForHash);
    }

    vector<uint8_t>* genUN() {
        vector<unsigned char> un(4);
        for (auto& byte : un) {
            byte = dist(gen);
        }
        transactionObjects.put(0x9f37, un);
        return transactionObjects.get(0x9f37);
    }

    uint8_t getRandomByte() {
        return dist(gen);
    }

    ExecutionResult execute() override{
        cout << "************************" << endl;
        cout << "[CRYPTO CERTS RETRIEVAL]" << endl;
        cout << "************************" << endl;
        try{
            
            
            retrieveIccPKCertificate();
            
            retrievePinPKCertificate();
            
            
            if(certs.capk!=nullptr){
                certs.capk->toStream(cout);
                cout<< endl <<endl;
            }
            
            if(certs.issuer!=nullptr){
                certs.issuer->toStream(cout);
                cout<< endl <<endl;
            }
            
            if(certs.icc!=nullptr){
                certs.icc->toStream(cout);
                cout<< endl <<endl;
            }
            
            if(certs.pin!=nullptr){
                certs.pin->toStream(cout);
                cout<< endl <<endl;
            }
            
        } catch (const exception& e) {
            cerr << "Exception caught in Crypto::execute: " << e.what() << endl;
            return ExecutionResult::Terminate;
        } catch (...) {
            cerr << "Unknown exception caught in Crypto::execute" << endl;
            return ExecutionResult::Terminate;
        }
        return ExecutionResult::Success;
    }

    ~Crypto() override {};
};
#endif