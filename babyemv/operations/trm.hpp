#ifndef __TRM__
#define __TRM__
#include "operation.hpp"
#include "../settings.hpp"
#include "../structures/dol.hpp"
#include "../structures/tvr.hpp"
#include "../structures/auc.hpp"
#include "../structures/termcaps.hpp"
#include "../structures/enums.hpp"
#include <format>

class TRM : public Operation {
  public:
    using Operation::Operation;

    void floorLimitCheck(){
        auto amount = transactionObjects.get(0x9F02);
        auto floorLimit = transactionObjects.get(FLOOR_LIMIT);

        if(!amount || !floorLimit) throw runtime_error("amount || floor limit is not set");
        
        auto amountL = bcdToLong(*amount);
        auto floorLimitL = bcdToLong(*floorLimit);

        if(amountL<floorLimitL) throw runtime_error("Offline currently not supported");
            else
        transactionObjects.get<TVR>(0x95)->setTransactionExceedsFloorLimit();
    }

    ExecutionResult execute() override{
        try
        {
            floorLimitCheck();    
        }
        catch(const std::exception& e)
        {   
            ExecutionResult::Terminate;
        }
        
        
        return ExecutionResult::Success;
    }

    ~TRM() override {};
};
#endif