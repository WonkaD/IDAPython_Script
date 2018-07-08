# region -------------------------------------- IMPORTS --------------------------------------
import binascii
import time
import idaapi
import idautils
import idc
from SignalHandler import getTimerFromTimeout

# endregion

# region --------------------------------------  GLOBAL --------------------------------------
BADADDR = idaapi.BADADDR
MAX_EA = idaapi.cvar.inf.maxEA

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
        for head in idautils.Heads(self.start, self.end):
            res.append(Disassembled(head))
        return res


class Disassembled:
    def __init__(self, position):
        self.position = position
        self.instruction = Disasm(position)

    def __str__(self):
        return transformPosition(self.position) + " : " + self.instruction

    def Instruction(self):
        return Instruction(self.position)

    def Operand(self, i):
        return Operand(self.position, i)

    def OperandValue(self, i):
        return OperandValue(self.position, i)

    def OperandType(self, i):
        return OperandType(self.position, i)


class LoopFunction:
    def __init__(self, function_, loop_instructions):
        self.function = function_
        self.loopInstructions = loop_instructions

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

# region -------------------------------------- Wrapper --------------------------------------
"""
type of the i^th operand:
    o_void  =      0  # No Operand               
    o_reg  =       1  # General Register (al,ax,es,ds...)    reg
    o_mem  =       2  # Direct Memory Reference  (DATA)      addr
    o_phrase  =    3  # Memory Ref [Base Reg + Index Reg]    phrase
    o_displ  =     4  # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
    o_imm  =       5  # Immediate Value                      value
    o_far  =       6  # Immediate Far Address  (CODE)        addr
    o_near  =      7  # Immediate Near Address (CODE)        addr
"""


def OperandType(ea, i):
    return idc.GetOpType(ea, i)


# value of the i^th operand:
def OperandValue(ea, i):
    return idc.GetOperandValue(ea, i)


# the i^th operand, as string
def Operand(ea, i):
    return idc.GetOpnd(ea, i)


# just the mnemonics of the instruction, without the conditional suffix and other stuff
def Instruction(ea):
    return idc.GetMnem(ea)


# just the mnemonics of the instruction, without the conditional suffix and other stuff
def NextHead(ea, limit):
    return idc.NextHead(ea, limit)


# a string containing the human-readable ASM line
def Disasm(ea):
    return idc.GetDisasm(ea)


# endregion

# region -------------------------------------- CODE --------------------------------------
def getListOfFunctions():
    res = []
    for segea in idautils.Segments():
        for funcea in idautils.Functions(segea, idc.SegEnd(segea)):
            functionName = idc.GetFunctionName(funcea)
            for (startea, endea) in idautils.Chunks(funcea):
                res.append(Function(functionName, startea, endea))
    return res


def checkJmpDestination(function_, jmp_instruction):
    if jmp_instruction.OperandValue(0) >= jmp_instruction.position:
        return False
    else:
        return isJmpInTheFunction(function_, jmp_instruction.OperandValue(0))
    pass


def getListOfPossibleLoops(functions):
    loopFunctions = []
    for function_ in functions:
        loopInstructions = []
        for instruction in function_.disassembled:
            mnemonicName = instruction.Instruction()
            if mnemonicName.startswith("j") and checkJmpDestination(function_, instruction):
                loopInstructions.append(LoopFunction.LoopInstruction(instruction))
            elif "loop" in mnemonicName:
                loopInstructions.append(LoopFunction.LoopInstruction(instruction, True))
            elif "call" in mnemonicName and function_.name == instruction.Operand(0):
                loopInstructions.append(LoopFunction.LoopInstruction(instruction, True))
        if len(loopInstructions) != 0:
            loopFunctions.append(LoopFunction(function_, loopInstructions))
    return loopFunctions


def getSetOfLoops(start, end, stack=set()):
    res = set()
    ea = start
    stack2 = cpSet(stack, ea)
    while ea != BADADDR:
        if ea == end or Instruction(ea).startswith("ret"):
            break
        elif Instruction(ea).startswith("j"):
            jumpDst = OperandValue(ea, 0)
            if jumpDst in stack2:
                res.add(str(jumpDst) + "," + str(ea))
                break
            else:
                res.update(getSetOfLoops(jumpDst, end, stack2))
                if Instruction(ea) == "jmp":
                    return res
        ea = NextHead(ea, MAX_EA)
        stack2.add(ea)
    return res


def checkLoop(start, end, end_of_function, stack=set()):
    ea = start
    stack2 = cpSet(stack, start)
    while ea != BADADDR:
        mnem = Instruction(ea)
        if ea == end:
            return True
        elif mnem.startswith("ret") or ea == end_of_function:
            return False
        elif mnem.startswith("j"):
            jumpDst = OperandValue(ea, 0)
            if jumpDst in stack2:
                return False
            elif mnem == "jmp":
                return checkLoop(jumpDst, end, end_of_function, stack2)
            else:
                if checkLoop(jumpDst, end, end_of_function, stack2):
                    return True
        ea = NextHead(ea, MAX_EA)
        stack2.add(ea)
    return False


def verifyLoops(possible_loop_functions):
    for possibleLoopFunction in possible_loop_functions:
        for loopInstruction in possibleLoopFunction.loopInstructions:
            if checkLoop(loopInstruction.loopStart(), loopInstruction.loopEnd(), possibleLoopFunction.function.end):
                loopInstruction.verify()
    return possible_loop_functions


# endregion

# region -------------------------------------- UTILS --------------------------------------
def isJmpInTheFunction(function_, jump_dst):
    return function_.start <= jump_dst <= function_.end


def cpSet(list_, item_=None):
    res = set()
    res.update(list_)
    if item_:
        res.add(item_)
    return res


def cloneArray(list_, item_=None):
    res = []
    res.extend(list_)
    if item_:
        res.append(item_)
    return res


def transformPosition(position):
    return "0x%08x" % position


def bytesToHex(bytes_):
    return binascii.hexlify(bytearray(bytes_))


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


def printVerifiedLoops(function_loops):
    for functionLoop in function_loops:
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


def printFunction(function_name, functions):
    for function_ in functions:
        if function_name == function_.name:
            print function_.name, transformPosition(function_.start), transformPosition(function_.end)
            for asm in function_.disassembled:
                print transformPosition(asm.position), ": ", asm.instruction, "#", asm.Instruction(), asm.Operand(
                    0), asm.OperandType(0), asm.OperandValue(0), bytesToHex(asm.OpCode())


def contains(list_, filter_):
    for item in list_:
        if filter_(item):
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

def main():
    loopFunctions = getListOfPossibleLoops(getListOfFunctions())

    for loopFunction in loopFunctions:
        # if "encry" not in loopFunction.function.name:
        #     continue
        # print loopFunction.function.name
        for loop in loopFunction.loopInstructions:
            ways = getAllTheWaysOfLoopWithTimeout(loop, loopFunction, timeout=2)
            if ways or (loop.verified and ways):
                buffer_op, call_op, total, xor_op = analyzeLoopsInstructions(ways)

                result = formaThetResultOfTheAnalysis(buffer_op, call_op, loopFunction, total, ways, xor_op)
                if len(result) != 0:
                    print result
                    break


def formaThetResultOfTheAnalysis(buffer_op, call_op, loop_function, total, ways, xor_op):
    result = ""
    if buffer_op != -1:
        if xor_op != -1:
            result += "\tXOR -->\t\t\t" + transformPosition(xor_op) + "\n"
        if call_op != -1:
            result += "\tCALL --> \t\t\t" + transformPosition(call_op) + "\n"
        if max(total) >= 0.50:
            result += "\tArithmeticological --> \tAverage: " + str(sum(total)) + " / " + str(len(ways)) + " = " + str(
                float(sum(total)) / len(ways)) + " Max: " + str(max(total)) + "\n"
        if len(result) != 0:
            result = "Possible Cipher Function: " + loop_function.function.name + " (" + transformPosition(
                loop_function.function.start) + ", " + transformPosition(loop_function.function.end) + ")\n" + result
    return result


def getAllTheWaysOfLoopWithTimeout(loop, loop_function, timeout=10):
    ways = None
    timer = getTimerFromTimeout(timeout)
    timer.start()
    try:
        ways = getAllWaysOfTheLoop(loop.loopStart(), loop.loopEnd(), loop_function.function.end)
        timer.cancel()
    except RuntimeError:
        print "Timeout getting all execute instructions of the next loop:", transformPosition(
            loop.loopStart()), transformPosition(loop.loopEnd())
    return ways


def analyzeLoopsInstructions(ways):
    total = []
    buffer_op = -1
    xor_op = -1
    call_op = -1
    for way in ways:
        arith_log_ins = 0.0
        buffer_op = -1
        xor_op = -1
        call_op = -1
        bonus = 1
        no_arith_log_ins = len(way)
        for ea in way:
            if Instruction(ea) in ASM_ARITHMETIC_LOGIC_INSTRUCTIONS:
                arith_log_ins += 1 * bonus
                bonus += 1
                no_arith_log_ins -= 1
            else:
                bonus = (bonus - 1, 1)[bonus == 0]
            if buffer_op == -1 and bufferInc(ea, Instruction(ea)):
                buffer_op = ea
            elif buffer_op == -1 and possibleCipherXOR(ea, Instruction(ea)):
                xor_op = ea
            elif call_op == -1 and Instruction(ea) == "call":
                call_op = ea

        total.append(arith_log_ins / float(no_arith_log_ins))
    return buffer_op, call_op, total, xor_op


def print_ways(ways):
    for way in ways:
        print "Way:"
        for x in way:
            print transformPosition(x)


# NOT xor R1, R1 / XOR Value, Value
def possibleCipherXOR(ea, mnem):
    return mnem == "xor" and Operand(ea, 0) != Operand(ea, 1) and OperandType(ea, 0) != 5 and OperandType(
        ea, 1) != 5


# inc REG mnem == "inc" or / add [addr], 1
def bufferInc(ea, mnem):
    return mnem == "inc" or mnem == "add" and OperandType(ea, 1) == 5 and OperandValue(ea, 1) == 1


def getAllWaysOfTheLoop(start_of_loop, end_of_loop, end_of_function, stack=None):
    if stack is None:
        stack = []
    ea = start_of_loop
    ways = []
    stack = cloneArray(stack)
    while ea != BADADDR:
        stack.append(ea)
        mnem = Instruction(ea)
        if ea == end_of_loop:
            ways.append(cloneArray(stack))
            return cloneArray(ways)
        elif mnem.startswith("ret") or ea == end_of_function:
            break
        elif mnem.startswith("j"):
            jumpDst = OperandValue(ea, 0)
            if mnem == "jmp":
                if jumpDst not in stack:
                    ways2 = getAllWaysOfTheLoop(jumpDst, end_of_loop, end_of_function, cloneArray(stack))
                    if ways2:
                        ways.extend(ways2)
                        return cloneArray(ways)
                break
            else:
                if jumpDst not in stack:
                    ways2 = getAllWaysOfTheLoop(jumpDst, end_of_loop, end_of_function, cloneArray(stack))
                    if ways2:
                        ways.extend(ways2)
        ea = NextHead(ea, MAX_EA)

    if len(ways) != 0:
        return cloneArray(ways)
    return None


def getLoopInstructions(start_of_loop, end_of_loop, end_of_function, stack=set()):
    ea = start_of_loop
    stack2 = cpSet(stack, ea)
    res = set()
    while ea != BADADDR:
        mnem = Instruction(ea)
        if ea == end_of_loop:
            if len(res) != 0:
                stack2.update(res)
            return stack2
        elif mnem.startswith("ret") or ea == end_of_function:
            return res
        elif mnem.startswith("j"):
            jumpDst = OperandValue(ea, 0)
            if mnem == "jmp":
                if jumpDst in stack2:
                    return res
                res2 = getLoopInstructions(jumpDst, end_of_loop, end_of_function, stack2)
                if len(res2) != 0:
                    res.update(res2)
                    res.update(stack2)
                return res
            else:
                if jumpDst not in stack2:
                    res2 = getLoopInstructions(jumpDst, end_of_loop, end_of_function, stack2)
                    if len(res2) != 0:
                        res.update(res2)
                        res.update(stack2)
        ea = NextHead(ea, MAX_EA)
        stack2.add(ea)
    if len(res) != 0:
        stack2.update(res)
        return stack2
    return set()


if __name__ == "__main__":
    main()

# endregion
