# region -------------------------------------- IMPORTS --------------------------------------
import binascii
import random
import sys
import time

# endregion

# region --------------------------------------  GLOBAL --------------------------------------
sys.setrecursionlimit(5000)
ASM_ARITHMETIC_LOGIC_INSTRUCTIONS = ["aaa", "aad", "aas", "adc", "add", "addpd", "addps", "addsd", "addss", "addsubpd",
                                     "addsubps", "and", "andpd", "andps", "andnpd", "andnps", "bsf", "bsr", "bswap",
                                     "bt", "btc", "btr", "bts", "daa", "das", "dec", "div", "divpd", "divps", "divsd",
                                     "divss", "emms", "f2xm1", "fabs", "fadd", "faddp", "fiadd", "fchs", "fcos",
                                     "fdecstp", "fdiv", "fdivp", "fidiv", "fdivr", "fdivrp", "fidivr", "fmul", "fmulp",
                                     "fimul", "fpatan", "fprem", "fprem1", "fptan", "frndint", "fscale", "fsin",
                                     "fsincos", "fsqrt", "fsub", "fsubp", "fisub", "fsubr", "fsubrp", "fisubr", "fyl2x",
                                     "fyl2xp1", "haddpd", "haddps", "hsubpd", "hsubps", "idiv", "imul", "inc", "maxpd",
                                     "maxps", "maxsd", "maxss", "minpd", "minps", "minsd", "minss", "mul", "mulpd",
                                     "mulps", "mulsd", "mulss", "neg", "not", "or", "orpd", "orps", "paddb", "paddw",
                                     "paddd", "paddq", "paddsb", "paddsw", "paddusb", "paddusw", "pand", "pandn",
                                     "pavgb", "pavgw", "pmaddwd", "pmaxsw", "pmaxub", "pminsw", "pminub", "pmovmskb",
                                     "pmulhuw", "pmulhw", "pmullw", "pmuludq", "por", "psadbw", "pslldq", "psllw",
                                     "pslld", "psllq", "psraw", "psrad", "psrldq", "psrlw", "psrld", "psrlq", "psubb",
                                     "psubw", "psubd", "psubq", "psubsb", "psubsw", "psubusb", "psubusw", "pxor", "rcl",
                                     "rcr", "rol", "ror", "rcpps", "rcpss", "rsqrtps", "rsqrtss", "sal", "sar", "shl",
                                     "shr", "sbb", "shld", "shrd", "sqrtpd", "sqrtps", "sqrtsd", "sqrtss", "sub",
                                     "subpd", "subps", "subsd", "subss", "xadd", "xchg", "xor", "xorpd", "xorps"]


# ASM_ARITHMETIC_INSTRUCTIONS = ["add", "sub", "inc", "dec", "mul", "div", "adc", "xadd", "sdb", "imul", "idiv", "neg"]
# ASM_LOGIC_INSTRUCTIONS = ["and", "or", "xor", "not"]
# ASM_SHIFT_INSTRUCTIONS = ["shl", "shr", "shld", "shrd", "sal", "sar"]
# ASM_JMP_INSTRUCTIONS = ["JMP", "JA", "JNBE", "JAE", "JB", "JNAE", "JBE", "JNA", "JE", "JZ", "JNE", "JNZ", "JG", "JNLE",
#                         "JGE", "JNL", "JL", "JNGE", "JLE", "JNG", "JC", "JNC", "JNO", "JNP", "JPO", "JNS", "JO", "JP",
#                         "JPE", "JS", "LOOP", ]


# endregion

# region -------------------------------------- CLASSES --------------------------------------
class Function:
    def __init__(self, name, start, end):
        self.name = name
        self.start = start
        self.end = end
        self.disassembled = self.disassembleFunction()

    def __str__(self):
        res = self.name + " (" + transformPosition(self.start) + ", " + transformPosition(self.end) + ")\n"
        for disassembledInstruction in self.disassembled:
            res += str(disassembledInstruction) + " : " + bytesToHex(disassembledInstruction.getOpCode()) + "\n"
        return res

    def disassembleFunction(self):
        res = []
        for head in Heads(self.start, self.end):
            res.append(Disassembled(head))
        return res


class Disassembled:
    def __init__(self, position):
        self.position = position
        self.instruction = GetDisasm(position)

    def __str__(self):
        return transformPosition(self.position) + " : " + self.instruction

    def OpCode(self):
        return GetManyBytes(self.position, ItemSize(self.position))

    def Instruction(self):
        return GetMnem(self.position)

    def Operand(self, i):
        return GetOpnd(self.position, i)

    def OperandValue(self, i):
        return GetOperandValue(self.position, i)

    def OperandType(self, i):
        return GetOpType(self.position, i)


class LoopFunction:
    def __init__(self, function_, loopInstructions):
        self.function = function_
        self.loopInstructions = loopInstructions

    def __str__(self):
        res = "Function: " + self.function.name + "(" + transformPosition(
            self.function.start) + ", " + transformPosition(self.function.end) + ")\n"
        for loopInstruction in self.loopInstructions:
            res += "\t" + str(loopInstruction) + "\n"
        return res + "\n"

    def isVerified(self):
        for loopInstruction in self.loopInstructions:
            if loopInstruction.verified:
                return True
        return False

    class LoopInstruction:
        def __init__(self, instruction, verified=False):
            self.instruction = instruction
            self.verified = verified

        def loopStart(self):
            return self.instruction.OperandValue(0)

        def loopEnd(self):
            return self.instruction.position

        def verify(self):
            self.verified = True

        def __str__(self):
            return "[Verified: " + str(self.verified) + "] " + "Start: " + transformPosition(
                self.loopStart()) + " End: " + transformPosition(self.loopEnd())


# endregion

# region -------------------------------------- CODE --------------------------------------
def getListOfFunctions():
    res = []
    for segea in Segments():
        for funcea in Functions(segea, SegEnd(segea)):
            functionName = GetFunctionName(funcea)
            for (startea, endea) in Chunks(funcea):
                res.append(Function(functionName, startea, endea))
    return res


def checkJmpDestination(function, jmpInstruction):
    if jmpInstruction.OperandValue(0) >= jmpInstruction.position:
        return False
    else:
        return isJmpInTheFunction(function, jmpInstruction.OperandValue(0))
        # for instruction in instructions:
        #     if instruction.position == jmpInstruction.OperandValue(0):
        #         return True
        # return False
    pass


def getListOfPossibleLoops(functions):
    loopFunctions = []
    for function in functions:
        loopInstructions = []
        for instruction in function.disassembled:
            mnemonicName = instruction.Instruction()
            if mnemonicName.startswith("j") and checkJmpDestination(function, instruction):
                loopInstructions.append(LoopFunction.LoopInstruction(instruction))
            elif "loop" in mnemonicName:
                loopInstructions.append(LoopFunction.LoopInstruction(instruction, True))
            elif "call" in mnemonicName and function.name == instruction.Operand(0):
                loopInstructions.append(LoopFunction.LoopInstruction(instruction, True))
        if len(loopInstructions) != 0:
            loopFunctions.append(LoopFunction(function, loopInstructions))
    return loopFunctions


def getSetOfLoops(start, end, stack=set()):
    res = set()
    ea = start
    stack2 = cpSet(stack, ea)
    while ea != idaapi.BADADDR:
        if ea == end or GetMnem(ea).startswith("ret"):
            break
        elif GetMnem(ea).startswith("j"):
            jumpDst = GetOperandValue(ea, 0)
            if jumpDst in stack2:
                # if GetOperandValue(ea, 0) == start:
                res.add(str(jumpDst) + "," + str(ea))
                break
            else:
                res.update(getSetOfLoops(jumpDst, end, stack2))
                if GetMnem(ea) == "jmp":
                    return res
        ea = NextHead(ea, idaapi.cvar.inf.maxEA)
        stack2.add(ea)
    return res


def checkLoop(start, end, endOfFunction, stack=set()):
    ea = start
    stack2 = cpSet(stack, start)
    while ea != idaapi.BADADDR:
        mnem = GetMnem(ea)
        if ea == end:
            return True
        elif mnem.startswith("ret") or ea == endOfFunction:
            return False
        elif mnem.startswith("j"):
            jumpDst = GetOperandValue(ea, 0)
            if jumpDst in stack2:
                return False
            elif mnem == "jmp":
                return checkLoop(jumpDst, end, endOfFunction, stack2)
            else:
                if checkLoop(jumpDst, end, endOfFunction, stack2):
                    return True
        ea = NextHead(ea, idaapi.cvar.inf.maxEA)
        stack2.add(ea)
    return False


def verifyLoops(possibleLoopFunctions):
    for possibleLoopFunction in possibleLoopFunctions:
        for loopInstruction in possibleLoopFunction.loopInstructions:
            if checkLoop(loopInstruction.loopStart(), loopInstruction.loopEnd(), possibleLoopFunction.function.end):
                loopInstruction.verify()
    return possibleLoopFunctions


# endregion

# region -------------------------------------- UTILS --------------------------------------
def isJmpInTheFunction(function, jumpDst):
    return function.start <= jumpDst <= function.end


def cpSet(list, item_=None):
    res = set()
    res.update(list)
    if item_:
        res.add(item_)
    return res


def cpArray(list, item_=None):
    res = []
    for item in list:
        res.append(item)
    if item_:
        res.append(item_)
    return res


def transformPosition(position):
    return "0x%08x" % (position)


def bytesToHex(bytes):
    return binascii.hexlify(bytearray(bytes))


def printLoops(loops):
    verified = 0
    notVerified = 0
    for possibleLoop in loops:
        for loopInstruction in possibleLoop.loopInstructions:
            if loopInstruction.verified:
                verified += 1
            else:
                notVerified += 1
        if len(possibleLoop.loopInstructions) > 0:
            print possibleLoop
    print "Not verified loops: " + str(notVerified)
    print "Verified loops: " + str(verified)


def printVerifiedLoops(functionLoops):
    for functionLoop in functionLoops:
        res = None
        if functionLoop.isVerified():
            res = "Function: " + functionLoop.function.name + "(" + transformPosition(
                functionLoop.function.start) + ", " + transformPosition(functionLoop.function.end) + ")\n"
            for loopInstruction in functionLoop.loopInstructions:
                if loopInstruction.verified:
                    res += "\t" + "Start: " + transformPosition(
                        loopInstruction.loopStart()) + " End: " + transformPosition(loopInstruction.loopEnd()) + "\n"
        if res:
            print res + "\n"


def printFunction(functionName, functions):
    for function in functions:
        if functionName == function.name:
            print function.name, transformPosition(function.start), transformPosition(function.end)
            for asm in function.disassembled:
                print transformPosition(asm.position), ": ", asm.instruction, "#", asm.Instruction(), asm.Operand(
                    0), asm.OperandType(0), asm.OperandValue(0), bytesToHex(asm.OpCode())


def contains(list, filter):
    for item in list:
        if filter(item):
            return item
    return None

# endregion

# region Testing Phase 2
def checkResults():
    temp = getListOfPossibleLoops(getListOfFunctions())
    loopFunctionsMethod1 = []
    for possibleLoopFunction in temp:
        loopInstructions = []
        check_loop = getSetOfLoops(possibleLoopFunction.function.start, possibleLoopFunction.function.end)
        for a in possibleLoopFunction.loopInstructions:
            if a.verified:
                loopInstructions.append(a)
        for a in check_loop:
            loopInstructions.append(LoopFunction.LoopInstruction(Disassembled(int(a.split(",")[1])), verified=True))
        if len(loopInstructions) != 0:
            loopFunctionsMethod1.append(LoopFunction(possibleLoopFunction.function, loopInstructions))
    temp = getListOfPossibleLoops(getListOfFunctions())
    loopFunctionsMethod2 = []
    for possibleLoopFunction in temp:
        loopInstructions = []
        for loopInstruction in possibleLoopFunction.loopInstructions:
            if checkLoop(loopInstruction.loopStart(), loopInstruction.loopEnd(),
                         possibleLoopFunction.function.end):
                loopInstruction.verify()
            if loopInstruction.verified:
                loopInstructions.append(loopInstruction)
        if len(loopInstructions) != 0:
            loopFunctionsMethod2.append(LoopFunction(possibleLoopFunction.function, loopInstructions))
    print "Method1 result checking in method2 result"
    for x in loopFunctionsMethod1:
        item = contains(loopFunctionsMethod2, lambda z: z.function.name == x.function.name)
        if item:
            for a in x.loopInstructions:
                if not contains(item.loopInstructions,
                                lambda z: z.loopStart() == a.loopStart() and z.loopEnd() == a.loopEnd()):
                    print "Method 1: ", x.function.name, str(a)
        else:
            print str(x)
    print "Method2 result checking in method1 result"
    for x in loopFunctionsMethod2:
        item = contains(loopFunctionsMethod1, lambda z: z.function.name == x.function.name)
        if item:
            for a in x.loopInstructions:
                if not contains(item.loopInstructions,
                                lambda z: z.loopStart() == a.loopStart() and z.loopEnd() == a.loopEnd()):
                    print "Method 2: ", x.function.name, str(a)
        else:
            print str(x)


def TimeStamp():
    method1Time = 0
    method2Time = 0
    for x in xrange(0, 10):
        possibleLoopFunctions = getListOfPossibleLoops(getListOfFunctions())
        timestamp = 0
        loopFunctions = []
        for possibleLoopFunction in possibleLoopFunctions:
            loopInstructions = []
            ts = time.time()
            check_loop = getSetOfLoops(possibleLoopFunction.function.start, possibleLoopFunction.function.end)
            ts = time.time() - ts
            timestamp += ts
            for a in possibleLoopFunction.loopInstructions:
                if a.verified:
                    loopInstructions.append(a)
            for a in check_loop:
                loopInstructions.append(LoopFunction.LoopInstruction(Disassembled(int(a.split(",")[1])), verified=True))
            if len(loopInstructions) != 0:
                loopFunctions.append(LoopFunction(possibleLoopFunction.function, loopInstructions))
        method1Time += timestamp

        possibleLoopFunctions = getListOfPossibleLoops(getListOfFunctions())
        timestamp = 0
        for possibleLoopFunction in possibleLoopFunctions:
            for loopInstruction in possibleLoopFunction.loopInstructions:
                ts = time.time()
                check_loop_ = checkLoop(loopInstruction.loopStart(), loopInstruction.loopEnd(),
                                        possibleLoopFunction.function.end)
                ts = time.time() - ts
                timestamp += ts
                if check_loop_:
                    loopInstruction.verify()
        method2Time += timestamp
    print "Method 1 average timestamp: ", method1Time / 10
    print "Method 2 average timestamp: ", method2Time / 10


# endregion

# region -------------------------------------- MAIN --------------------------------------
def weighInstruction(ea, numberOfInstructions):
    if possibleCipherXOR(ea, GetMnem(ea)):
        return numberOfInstructions / 2
    if GetMnem(ea) in ASM_ARITHMETIC_LOGIC_INSTRUCTIONS:
        return 1
    return 0


def main():
    # printVerifiedLoops(verifyLoops(getListOfPossibleLoops(getListOfFunctions())))
    loopFunctions = getListOfPossibleLoops(getListOfFunctions())
    i = 0
    for loopFunction in loopFunctions:
        # if "__nptl_setxid" not in loopFunction.function.name:
        #     continue
        # print loopFunction.function.name
        for loop in loopFunction.loopInstructions:
            # printProgressBar(i + 1, total, prefix='Progress:', suffix='Complete', length=50)
            # print str(loop)
            res = getLoopInstructions(loop.loopStart(), loop.loopEnd(), loopFunction.function.end)
            if len(res) != 0 or loop.verified:
                arith_log_ins = 0
                bonus = 0
                buffer_inc = False
                for ea in sorted(res):
                    if not buffer_inc and bufferInc(ea, GetMnem(ea)):
                        buffer_inc = True
                    weigh_instruction = weighInstruction(ea, len(res))
                    if weigh_instruction != 0:
                        bonus += 1
                    else:
                        bonus = (bonus - 1, 0)[bonus == 0]
                    arith_log_ins += (weigh_instruction * bonus)
                # print arith_log_ins, len(res), float(arith_log_ins) / len(res)
                # print "-------------"
                # for x in sorted(res): print transformPosition(x)
                i += 1
                if float(arith_log_ins) / len(res) >= 0.55 and buffer_inc:
                    print str(arith_log_ins) + " / " + str(len(res)) + " = " + str(float(arith_log_ins) / len(res)) + " pt \n" + printPossibleCipher(loopFunction)
                    print ""
                    break


def printPossibleCipherXOR(ea, loopFunction):
    print "XOR:", transformPosition(
        ea), "Function: ", loopFunction.function.name, transformPosition(
        loopFunction.function.start), transformPosition(loopFunction.function.end)


def printPossibleCipher(loopFunction):
    return "Possible Cipher Function: " + loopFunction.function.name +" "+ transformPosition(
        loopFunction.function.start) +" "+transformPosition(loopFunction.function.end)


# NOT xor R1, R1 / XOR Value, Value
def possibleCipherXOR(ea, mnem):
    return mnem == "xor" and GetOpnd(ea, 0) != GetOpnd(ea, 1) and GetOpType(ea, 0) != 5 and GetOpType(ea, 1) != 5


# inc REG / add [addr], 1
def bufferInc(ea, mnem):
    return mnem == "inc" or mnem == "add" and GetOpType(ea, 1) == 5 and GetOperandValue(ea, 1) == 1 and GetOpType(ea,
                                                                                                                  0) == 4


def getLoopInstructions(startOfLoop, endOfLoop, endOfFunction, stack=set()):
    ea = startOfLoop
    stack2 = cpSet(stack, ea)
    res = set()
    while ea != idaapi.BADADDR:
        mnem = GetMnem(ea)
        if ea == endOfLoop:
            if len(res) != 0:
                stack2.update(res)
            return stack2
        elif mnem.startswith("ret") or ea == endOfFunction:
            return res
        elif mnem.startswith("j"):
            jumpDst = GetOperandValue(ea, 0)
            if mnem == "jmp":
                if jumpDst in stack2:
                    return res
                res2 = getLoopInstructions(jumpDst, endOfLoop, endOfFunction, stack2)
                if len(res2) != 0:
                    res.update(res2)
                    res.update(stack2)
                return res
            else:
                if jumpDst not in stack2:
                    res2 = getLoopInstructions(jumpDst, endOfLoop, endOfFunction, stack2)
                    if len(res2) != 0:
                        res.update(res2)
                        res.update(stack2)
        ea = NextHead(ea, idaapi.cvar.inf.maxEA)
        stack2.add(ea)
    if len(res) != 0:
        stack2.update(res)
        return stack2
    return set()
    # print "Stack:", sorted([transformPosition(x) for x in stack2]), "Res:", sorted([transformPosition(x) for x in res]), "Len:", len(res)


if __name__ == "__main__":
    main()
# endregion
# def checkLoop(start, end, stack=[]):
#     ea = start
#     while ea != idaapi.BADADDR:
#         if ea == end:
#             return True
#         elif GetMnem(ea).startswith("j"):
#             jumpDst = GetOperandValue(ea, 0)
#             if ea in stack:
#                 return False
#             elif GetMnem(ea) == "jmp":
#                 return checkLoop(jumpDst, end, cpArray(stack, ea))
#             else:
#                 if checkLoop(jumpDst, end, cpArray(stack, ea)):
#                     return True
#         elif GetMnem(ea) == "retn":
#             return False
#         ea = NextHead(ea, idaapi.cvar.inf.maxEA)
#     return False


# def getSetOfLoops(start, end, stack=[]):
#     res = set()
#     ea = start
#     while ea != idaapi.BADADDR:
#         if ea == end:
#             break
#         elif GetMnem(ea).startswith("j"):
#             jumpDst = GetOperandValue(ea, 0)
#             if ea in stack:
#                 if GetOperandValue(ea, 0) == start:
#                     res.add(str(start) + "," + str(ea))
#                 break
#             else:
#                 res.update(getSetOfLoops(jumpDst, end, cpArray(stack, ea)))
#                 if GetMnem(ea) == "jmp":
#                     return res
#         elif GetMnem(ea).startswith("ret"):
#             break
#         ea = NextHead(ea, idaapi.cvar.inf.maxEA)
#     return res
