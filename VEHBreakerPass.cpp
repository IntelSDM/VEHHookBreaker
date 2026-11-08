#include "VEHBreakerPass.h"

#include "llvm/ADT/APInt.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/CommandLine.h"

#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

using namespace llvm;

llvm::cl::opt<bool> VEHBreakerEnable("obfvehbreaker", llvm::cl::init(true), llvm::cl::desc("Master Toggle"));

static std::mt19937_64 VehbRng((uint64_t)std::random_device{}() ^ (uint64_t)std::chrono::high_resolution_clock::now().time_since_epoch().count());

static constexpr unsigned StashOffset = 0x200;
static constexpr unsigned PerFnCap = 256;

static bool HasAnnotationTag(Function& f, const char* tag)
{
    Module* m = f.getParent();
    GlobalVariable* ga = m->getGlobalVariable("llvm.global.annotations");
    if (!ga) return false;
    ConstantArray* ca = dyn_cast<ConstantArray>(ga->getOperand(0));
    if (!ca) return false;
    for (unsigned i = 0; i < ca->getNumOperands(); ++i)
    {
        ConstantStruct* cs = dyn_cast<ConstantStruct>(ca->getOperand(i));
        if (!cs) continue;
        if (cs->getOperand(0)->stripPointerCasts() != &f) continue;
        auto* strgv = dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
        if (!strgv || !strgv->hasInitializer()) continue;
        auto* cds = dyn_cast<ConstantDataSequential>(strgv->getInitializer());
        if (!cds || !cds->isString()) continue;
        if (strcmp(cds->getAsString().str().c_str(), tag) == 0) return true;
    }
    return false;
}

static bool HasVEHBreakerAnnotation(Function& f)
{
    return HasAnnotationTag(f, "vehbreaker");
}

static bool HasNoVEHBreakerAnnotation(Function& f)
{
    return HasAnnotationTag(f, "novehbreaker");
}

static bool HasObfuscateAnnotation(Function& f)
{
    return HasAnnotationTag(f, "obfus");
}

static bool HasNoObfuscateAnnotation(Function& f)
{
    return HasAnnotationTag(f, "noobfus");
}

struct Site
{
    Instruction* Use;
    unsigned OpIdx;
    ConstantInt* Ci;
};

static uint64_t Rotl64(uint64_t x, unsigned n)
{
    n &= 63;
    if (n == 0) return x;
    return (x << n) | (x >> (64 - n));
}

static uint64_t Rotr64(uint64_t x, unsigned n)
{
    n &= 63;
    if (n == 0) return x;
    return (x >> n) | (x << (64 - n));
}

static uint64_t VehArxEncrypt(uint64_t v, uint64_t k, unsigned val1, unsigned val2)
{
    uint64_t r = v;
    r = r + k;
    r = Rotl64(r, val1);
    r ^= k;
    r = r + k;
    r = Rotr64(r, val2);
    return r;
}

static uint64_t VehArxDecrypt(uint64_t ct, uint64_t k, unsigned val1, unsigned val2)
{
    uint64_t r = ct;
    r = Rotl64(r, val2);
    r = r - k;
    r ^= k;
    r = Rotr64(r, val1);
    r = r - k;
    return r;
}

static uint64_t RandomKey()
{
    std::uniform_int_distribution<uint64_t> d;
    uint64_t k = d(VehbRng);
    while (k == 0 || k == 1 || k == UINT64_MAX) k = d(VehbRng);
    return k;
}

static unsigned RandomRotAmount()
{
    std::uniform_int_distribution<unsigned> d(1, 63);
    return d(VehbRng);
}

static bool IsUnsafeOperandSlot(Instruction* i, unsigned opidx)
{
    if (isa<SwitchInst>(i)) return true;
    if (auto* ai = dyn_cast<AllocaInst>(i))
    {
        if (i->getOperand(opidx) == ai->getArraySize()) return true;
    }
    if (isa<IntrinsicInst>(i)) return true;
    if (auto* cb = dyn_cast<CallBase>(i))
    {
        if (cb->isCallee(&i->getOperandUse(opidx))) return true;
    }
    if (isa<PHINode>(i)) return true;

    if (auto* gep = dyn_cast<GetElementPtrInst>(i))
    {
        if (opidx == 0) return false;
        unsigned step = opidx - 1;
        auto gti = gep_type_begin(gep);
        auto gte = gep_type_end(gep);
        for (unsigned n = 0; n < step && gti != gte; ++n) ++gti;
        if (gti != gte && gti.isStruct()) return true;
    }

    return false;
}

static void CollectSites(Function& f, LoopInfo& li, std::vector<Site>& out)
{
    for (BasicBlock& bb : f)
    {
        bool inloop = (li.getLoopFor(&bb) != nullptr);

        for (Instruction& i : bb)
        {
            if (auto* cb = dyn_cast<CallBase>(&i))
            {
                if (cb->isInlineAsm()) continue;
            }

            for (unsigned o = 0, e = i.getNumOperands(); o < e; ++o)
            {
                auto* ci = dyn_cast<ConstantInt>(i.getOperand(o));
                if (!ci) continue;

                Type* t = ci->getType();
                if (!t->isIntegerTy()) continue;
                unsigned bw = t->getIntegerBitWidth();
                if (bw != 32 && bw != 64) continue;

                if (ci->isZero()) continue;
                if (IsUnsafeOperandSlot(&i, o)) continue;
                if (inloop) continue;

                out.push_back({&i, o, ci});
            }
        }
    }
}

static void CollectUserCalls(Function& f, std::vector<CallInst*>& out)
{
    for (BasicBlock& bb : f)
    {
        for (Instruction& i : bb)
        {
            auto* ci = dyn_cast<CallInst>(&i);
            if (!ci) continue;
            if (ci->isInlineAsm()) continue;
            out.push_back(ci);
        }
    }
}

static Value* EmitArxDecrypt(IRBuilder<>& b, LLVMContext& c, uint64_t ct, uint64_t aux, unsigned val1, unsigned val2)
{
    FunctionType* ft = FunctionType::get(Type::getInt64Ty(c), {}, false);

    char buf[512];
    std::snprintf(buf, sizeof(buf),
        "movabsq $$0x%016llx, $0\n\trolq $$%u, $0\n\tmovabsq $$0x%016llx, %%rcx\n\tsubq %%rcx, $0\n\txorq %%rcx, $0\n\trorq $$%u, $0\n\tsubq %%rcx, $0",
        (unsigned long long)ct, val2, (unsigned long long)aux, val1);

    InlineAsm* a = InlineAsm::get(ft, std::string(buf), "=r,~{rcx},~{dirflag},~{fpsr},~{flags}", true, false, InlineAsm::AD_ATT);

    return b.CreateCall(ft, a, {}, "VehbKey");
}

static void EmitStashWrite(IRBuilder<>& b, LLVMContext& c, Value* keyval)
{
    FunctionType* ft = FunctionType::get(Type::getVoidTy(c), {Type::getInt64Ty(c)}, false);

    char buf[64];
    std::snprintf(buf, sizeof(buf), "movq $0, -%u(%%rsp)", (unsigned)StashOffset);

    InlineAsm* a = InlineAsm::get(ft, std::string(buf), "r,~{memory}", true, false, InlineAsm::AD_ATT);

    b.CreateCall(ft, a, {keyval}, "");
}

static Value* EmitStashLoad(IRBuilder<>& b, LLVMContext& c)
{
    FunctionType* ft = FunctionType::get(Type::getInt64Ty(c), {}, false);

    char buf[64];
    std::snprintf(buf, sizeof(buf), "movq -%u(%%rsp), $0", (unsigned)StashOffset);

    InlineAsm* a = InlineAsm::get(ft, std::string(buf), "=r,~{memory}", true, false, InlineAsm::AD_ATT);

    return b.CreateCall(ft, a, {}, "VehbStash");
}

static unsigned TransformFunction(Function& f, LoopInfo& li)
{
    uint64_t kf = RandomKey();
    uint64_t aux = RandomKey();
    unsigned val1 = RandomRotAmount();
    unsigned val2 = 64 - val1;
    uint64_t ct = VehArxEncrypt(kf, aux, val1, val2);

    assert(VehArxDecrypt(ct, aux, val1, val2) == kf && "VEHBreaker: ARX forward/inverse round-trip mismatch");

    // inserting inline asm before collecting user calls would make the loop iterate over our own emits
    std::vector<CallInst*> usercalls;
    CollectUserCalls(f, usercalls);

    std::vector<Site> sites;
    CollectSites(f, li, sites);

    if (sites.empty()) return 0;

    if (sites.size() > PerFnCap)
    {
        sites.resize(PerFnCap);
    }

    LLVMContext& c = f.getContext();
    Type* i32 = Type::getInt32Ty(c);
    Type* i64 = Type::getInt64Ty(c);

    BasicBlock& entry = f.getEntryBlock();

    IRBuilder<> ab(&entry, entry.getFirstInsertionPt());
    AllocaInst* keyslot = ab.CreateAlloca(i64, 0, nullptr, "VehbKeyStore");

    Instruction* ip = entry.getFirstNonPHIOrDbg();
    while (ip && isa<AllocaInst>(ip)) ip = ip->getNextNode();
    if (!ip) ip = entry.getTerminator();

    IRBuilder<> b(ip);
    Value* keyval = EmitArxDecrypt(b, c, ct, aux, val1, val2);
    b.CreateStore(keyval, keyslot);
    EmitStashWrite(b, c, keyval);

    // sub calls allocate frames that overlap [rsp - StashOffset], so without a refresh the next load sees scrambled bytes
    for (CallInst* ci : usercalls)
    {
        Instruction* after = ci->getNextNode();
        if (!after) continue;

        IRBuilder<> rb(after);
        Value* reloaded = rb.CreateLoad(i64, keyslot, "VehbKeyRefresh");
        EmitStashWrite(rb, c, reloaded);
    }

    unsigned ni32 = 0, ni64 = 0;
    for (const Site& s : sites)
    {
        IRBuilder<> sb(s.Use);

        Value* key64 = EmitStashLoad(sb, c);

        Type* ptxtype = s.Ci->getType();
        uint64_t plaintext = s.Ci->getZExtValue();
        Value* decrypted = nullptr;

        if (ptxtype == i64)
        {
            uint64_t cipher = plaintext ^ kf;
            Value* cipherv = ConstantInt::get(i64, cipher);
            decrypted = sb.CreateXor(key64, cipherv, "VehbDec");
            ++ni64;
        }
        else if (ptxtype == i32)
        {
            Value* key32 = sb.CreateTrunc(key64, i32, "VehbKey32");
            uint32_t k32 = (uint32_t)kf;
            uint32_t ptx32 = (uint32_t)plaintext;
            uint32_t cipher = ptx32 ^ k32;
            Value* cipherv = ConstantInt::get(i32, cipher);
            decrypted = sb.CreateXor(key32, cipherv, "VehbDec");
            ++ni32;
        }
        else
        {
            continue;
        }

        s.Use->setOperand(s.OpIdx, decrypted);
    }

    return ni32 + ni64;
}

static bool HasInBodyReentryAfterUnwind(Function& f)
{
    for (BasicBlock& bb : f)
    {
        for (Instruction& i : bb)
        {
            if (isa<InvokeInst>(&i)) return true;
            if (isa<LandingPadInst>(&i)) return true;
            if (isa<CatchPadInst>(&i)) return true;
            if (isa<CleanupPadInst>(&i)) return true;
            if (isa<CatchSwitchInst>(&i)) return true;
            if (isa<CatchReturnInst>(&i)) return true;
            if (isa<CleanupReturnInst>(&i)) return true;

            if (auto* cb = dyn_cast<CallBase>(&i))
            {
                if (Function* callee = cb->getCalledFunction())
                {
                    if (callee->hasFnAttribute(Attribute::ReturnsTwice)) return true;
                }
            }
        }
    }
    return false;
}

static bool IsEligibleFunction(Function& f)
{
    if (f.isDeclaration()) return false;
    if (f.empty()) return false;

    if (HasNoVEHBreakerAnnotation(f)) return false;
    if (HasNoObfuscateAnnotation(f)) return false;

    bool optedin = HasVEHBreakerAnnotation(f) || HasObfuscateAnnotation(f);
    if (!optedin) return false;

    if (HasInBodyReentryAfterUnwind(f)) return false;

    return true;
}

bool RunVEHBreaker(Module& m)
{
    if (!VEHBreakerEnable) return false;

    bool changed = false;

    for (Function& f : m)
    {
        if (!IsEligibleFunction(f)) continue;

        DominatorTree dt(f);
        LoopInfo li(dt);

        unsigned n = TransformFunction(f, li);
        if (n > 0) changed = true;
    }

    return changed;
}

PreservedAnalyses VEHBreakerPass::run(Module& m, ModuleAnalysisManager&)
{
    if (!RunVEHBreaker(m)) return PreservedAnalyses::all();
    return PreservedAnalyses::none();
}
