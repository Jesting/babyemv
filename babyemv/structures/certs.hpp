#ifndef __CERTS__
#define __CERTS__

#include "../kernel.hpp"
#include <ostream>

using namespace std;
template <std::size_t SIZE>
string vectorPrint(array<unsigned char, SIZE>& arr, ostream& ss) {
    for (auto& x : arr) {
        ss << format("{:02X}", x);
    }
    return string("");
}

string vectorPrint(vector<unsigned char>& v, ostream& ss) {
    for (auto& x : v) {
        ss << format("{:02X}", x);
    }
    return string("");
}

struct CAPK {
    array<unsigned char, 5> rid;
    unsigned char index;
    vector<unsigned char> modulus;
    vector<unsigned char> exponent;
    array<unsigned char, 3> expiry;
    array<unsigned char, 20> sha;
    void toStream(ostream& ss) {
        ss << "┌─CAPK────────────────────────────────────" << endl;
        ss << "├─" << "RID        : " << hex << vectorPrint(rid, ss) << endl;
        ss << "├─" << "Index      : " << hex << (int)index << endl;
        ss << "├─" << "Modulus    : " << hex << vectorPrint(modulus, ss) << endl;
        ss << "├─" << "Exponent   : " << hex << vectorPrint(exponent, ss) << endl;
        ss << "├─" << "Expiry     : " << hex << vectorPrint(expiry, ss) << endl;
        ss << "└─" << "SHA        : " << hex << vectorPrint(sha, ss) << endl;
    }
};

struct IssuerPKCertificate {
    unsigned char recoveredDataHeader;
    unsigned char certificateFormat;
    array<unsigned char, 4> issuerIdentifier;
    array<unsigned char, 2> certificateExpiry;
    array<unsigned char, 3> certificateSN;
    unsigned char hashAlgorithmIndicator;
    unsigned char issuerPKAlgorithmIndicator;
    unsigned char issuerPKLength;
    unsigned char issuerPKExponentLength;
    vector<unsigned char> issuerPK;
    array<unsigned char, 20> hashResult;
    unsigned char recoveredDataTrailer;

    IssuerPKCertificate(vector<unsigned char>& recovered, vector<unsigned char>& reminder) {
        int c = 0;
        recoveredDataHeader = recovered[c++];
        certificateFormat = recovered[c++];

        copy(recovered.begin() + c, recovered.begin() + c + 4, issuerIdentifier.begin());
        c += 4;
        copy(recovered.begin() + c, recovered.begin() + c + 2, certificateExpiry.begin());
        c += 2;
        copy(recovered.begin() + c, recovered.begin() + c + 3, certificateSN.begin());
        c += 3;

        hashAlgorithmIndicator = recovered[c++];
        issuerPKAlgorithmIndicator = recovered[c++];
        issuerPKLength = recovered[c++];
        issuerPKExponentLength = recovered[c++];

        int start = 15;
        int end = recovered.size() - 1 - 20;

        copy(recovered.begin() + end, recovered.begin() + end + 20, hashResult.begin());
        recoveredDataTrailer = recovered[recovered.size() - 1];

        bool needReminder = true;
        if (end - start >= issuerPKLength) {
            end = start + issuerPKLength;
            needReminder = false;
        }
        for (int i = start; i < end; i++)
            issuerPK.push_back(recovered[i]);

        if (needReminder) {
            for (auto x : reminder) {
                issuerPK.push_back(x);
            }
        }
    }

    void toStream(ostream& ss) {
        ss << "┌─IssuerPKCertificate──────────────────────" << endl;
        ss << "├─" << "Recovered data header        : " << hex << (int)recoveredDataHeader << endl;
        ss << "├─" << "Certificate format           : " << hex << (int)certificateFormat << endl;
        ss << "├─" << "Issuer identifier            : " << hex << vectorPrint(issuerIdentifier, ss) << endl;
        ss << "├─" << "Certificate expiry           : " << hex << vectorPrint(certificateExpiry, ss) << endl;
        ss << "├─" << "Certificate SN               : " << hex << vectorPrint(certificateSN, ss) << endl;
        ss << "├─" << "Hash algorithm indicator     : " << hex << (int)hashAlgorithmIndicator << endl;
        ss << "├─" << "Issuer PK algorithm indicator: " << hex << (int)issuerPKAlgorithmIndicator << endl;
        ss << "├─" << "Issuer PK length             : " << hex << (int)issuerPKLength << endl;
        ss << "├─" << "Issuer PK exponent length    : " << hex << (int)issuerPKExponentLength << endl;
        ss << "├─" << "Issuer PK                    : " << hex << vectorPrint(issuerPK, ss) << endl;
        ss << "├─" << "Hash result                  : " << hex << vectorPrint(hashResult, ss) << endl;
        ss << "└─" << "Recovered data trailer       : " << hex << (int)recoveredDataTrailer << endl;
    }
};

struct ICCPKCertificate {
    unsigned char recoveredDataHeader;
    unsigned char certificateFormat;
    array<unsigned char, 10> appPan;
    array<unsigned char, 2> certificateExpiry;
    array<unsigned char, 3> certificateSN;
    unsigned char hashAlgorithmIndicator;
    unsigned char iccPKAlgorithmIndicator;
    unsigned char iccPKLength;
    unsigned char iccPKExponentLength;
    vector<unsigned char> iccPK;
    array<unsigned char, 20> hashResult;
    unsigned char recoveredDataTrailer;

    ICCPKCertificate(vector<unsigned char>& recovered, vector<unsigned char>& reminder) {
        int c = 0;
        recoveredDataHeader = recovered[c++];
        certificateFormat = recovered[c++];
        copy(recovered.begin() + c, recovered.begin() + c + 10, appPan.begin());
        c += 10;

        copy(recovered.begin() + c, recovered.begin() + c + 2, certificateExpiry.begin());
        c += 2;

        copy(recovered.begin() + c, recovered.begin() + c + 3, certificateSN.begin());
        c += 3;

        hashAlgorithmIndicator = recovered[c++];
        iccPKAlgorithmIndicator = recovered[c++];
        iccPKLength = recovered[c++];

        iccPKExponentLength = recovered[c++];

        int start = 21;
        int end = recovered.size() - 1 - 20;

        copy(recovered.begin() + end, recovered.begin() + end + 20, hashResult.begin());
        recoveredDataTrailer = recovered[recovered.size() - 1];

        bool needReminder = true;
        if (end - start >= iccPKLength) {
            end = start + iccPKLength;
            needReminder = false;
        }
        for (int i = start; i < end; i++)
            iccPK.push_back(recovered[i]);

        if (needReminder) {
            for (auto x : reminder) {
                iccPK.push_back(x);
            }
        }
    }

    void toStream(ostream& ss) {
        ss << "┌─ICCPKCertificate──────────────────────" << endl;
        ss << "├─" << "Recovered data header        : " << hex << (int)recoveredDataHeader << endl;
        ss << "├─" << "Certificate format           : " << hex << (int)certificateFormat << endl;
        ss << "├─" << "App PAN                      : " << hex << vectorPrint(appPan, ss) << endl;
        ss << "├─" << "Certificate expiry           : " << hex << vectorPrint(certificateExpiry, ss) << endl;
        ss << "├─" << "Certificate SN               : " << hex << vectorPrint(certificateSN, ss) << endl;
        ss << "├─" << "Hash algorithm indicator     : " << hex << (int)hashAlgorithmIndicator << endl;
        ss << "├─" << "ICC PK algorithm indicator   : " << hex << (int)iccPKAlgorithmIndicator << endl;
        ss << "├─" << "ICC PK length                : " << hex << (int)iccPKLength << endl;
        ss << "├─" << "ICC PK exponent length       : " << hex << (int)iccPKExponentLength << endl;
        ss << "├─" << "ICC PK                       : " << hex << vectorPrint(iccPK, ss) << endl;
        ss << "├─" << "Hash result                  : " << hex << vectorPrint(hashResult, ss) << endl;
        ss << "└─" << "Recovered data trailer       : " << hex << (int)recoveredDataTrailer << endl;
    }
};

struct CertsCache {
    shared_ptr<CAPK> capk = nullptr;
    shared_ptr<IssuerPKCertificate> issuer = nullptr;
    shared_ptr<ICCPKCertificate> icc = nullptr;
    shared_ptr<ICCPKCertificate> pin = nullptr;
};



#endif