#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"

struct VEHBreakerPass : llvm::PassInfoMixin<VEHBreakerPass>
{
    llvm::PreservedAnalyses run(llvm::Module& m, llvm::ModuleAnalysisManager&);
};

bool RunVEHBreaker(llvm::Module& m);

extern llvm::cl::opt<bool> VEHBreakerEnable;