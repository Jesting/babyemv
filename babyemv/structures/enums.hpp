#ifndef __ENUMS__
#define __ENUMS__

struct TransactionType{
    static const unsigned char Purchase = 0x00;
    static const unsigned char CashWithdrawal = 0x01;
    static const unsigned char PurchaseWithCashBack = 0x02;
    static const unsigned char Balance = 0x03;
    static const unsigned char Transfer = 0x04;
    static const unsigned char Load = 0x05;
    static const unsigned char Deposit = 0x06;
    static const unsigned char PaymentBillPayment = 0x07;
    static const unsigned char Administrative = 0x07;
    static const unsigned char CashAdvance = 0x09;
    static const unsigned char PurchaseWithLaterUpdate = 0x10;
    static const unsigned char CashWithdrawalCC = 0x19;
    static const unsigned char Refund = 0x20;
};




#endif