#ifndef __OPERATION__
#define __OPERATION__
#include "../kernel.hpp"
#include "../command.hpp"
#include <ostream>

enum class ExecutionResult { Success, Terminate, Denied, Online, Approved, OnlineButCdaFailed };

class Operation {
  protected:
    TransactionObjects& transactionObjects;
    Command* command;

  public:
    explicit Operation(TransactionObjects& _transactionObjects, Command* _command = nullptr)
      : transactionObjects(_transactionObjects), command(_command) {
    }

    virtual ExecutionResult execute() {
        return ExecutionResult::Terminate;
    }

    virtual ~Operation() {
    }
};

#endif