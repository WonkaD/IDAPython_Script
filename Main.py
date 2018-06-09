# -------------------------------------- IMPORTS --------------------------------------


import binascii
import random
import sys
import time

# -------------------------------------- GLOBAL --------------------------------------

sys.setrecursionlimit(5000)
ASM_JMP_INSTRUCTIONS = ["JMP", "JA", "JNBE", "JAE", "JB", "JNAE", "JBE", "JNA", "JE", "JZ", "JNE", "JNZ", "JG", "JNLE",
                        "JGE", "JNL", "JL", "JNGE", "JLE", "JNG", "JC", "JNC", "JNO", "JNP", "JPO", "JNS", "JO", "JP",
                        "JPE", "JS", "LOOP", ]


# -------------------------------------- CLASSES --------------------------------------


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

    def __init__(self, function_, loopInstructions):
        self.function = function_
        self.loopInstructions = loopInstructions

    def __str__(self):
        res = "Function: " + self.function.name + "(" + transformPosition(
            self.function.start) + ", " + transformPosition(self.function.end) + ")\n"
        for loopInstruction in self.loopInstructions:
            res += "\t" + str(
                loopInstruction) + "\n"  # "\t [Verified: " + str(loopInstruction.verified) + "] " + str(loopInstruction.instruction) + "\n"
        return res + "\n"

    def isVerified(self):
        for loopInstruction in self.loopInstructions:
            if not loopInstruction.verified:
                return False
        return True


# -------------------------------------- CODE --------------------------------------


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


def isJmpInTheFunction(function, jumpDst):
    return function.start <= jumpDst <= function.end


def getListOfPossibleLoops(functions):
    loopFunctions = []
    for function in functions:
        loopInstructions = []
        for instruction in function.disassembled:
            mnemonicName = instruction.Instruction()
            if mnemonicName.startswith("j") and checkJmpDestination(function, instruction):
                loopInstructions.append(LoopFunction.LoopInstruction(instruction))
                # print "Salto hacia arriba", function.name, str(instruction)
            elif "loop" in mnemonicName:
                loopInstructions.append(LoopFunction.LoopInstruction(instruction, True))
                # print "Bucle", function.name, str(instruction)
            elif "call" in mnemonicName and function.name == instruction.Operand(0):
                loopInstructions.append(LoopFunction.LoopInstruction(instruction, True))
                # print "Operacion recursiva", function.name, str(instruction)
        if len(loopInstructions) != 0:
            loopFunctions.append(LoopFunction(function, loopInstructions))
    return loopFunctions


# -------------------------------------- UTILS --------------------------------------


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


# -------------------------------------- MAIN --------------------------------------

def getSetOfLoops(start, end, stack=[]):
    res = set()
    ea = start
    while ea != idaapi.BADADDR:
        if ea == end:
            break
        elif GetMnem(ea).startswith("j"):
            jumpDst = GetOperandValue(ea, 0)
            if ea in stack:
                if GetOperandValue(ea, 0) == start:
                    res.add(str(start) + "," + str(ea))
                break
            else:
                res.update(getSetOfLoops(jumpDst, end, cpArray(stack, ea)))
                if GetMnem(ea) == "jmp":
                    return res
        elif GetMnem(ea).startswith("ret"):
            break
        ea = NextHead(ea, idaapi.cvar.inf.maxEA)
    return res


def getSetOfLoops_2(start, end, stack=set()):
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
                res.update(getSetOfLoops_2(jumpDst, end, stack2))
                if GetMnem(ea) == "jmp":
                    return res
        ea = NextHead(ea, idaapi.cvar.inf.maxEA)
        stack2.add(ea)
    return res


def cpSet(list, item_=None):
    res = set()
    for item in list:
        res.add(item)
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


def checkLoop2(start, end, endOfFunction, stack=set()):
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
                return checkLoop2(jumpDst, end, endOfFunction, stack2)
            else:
                if checkLoop2(jumpDst, end, endOfFunction, stack2):
                    return True
        ea = NextHead(ea, idaapi.cvar.inf.maxEA)
        stack2.add(ea)
    return False


def checkLoop(start, end, stack=[]):
    ea = start
    while ea != idaapi.BADADDR:
        if ea == end:
            return True
        elif GetMnem(ea).startswith("j"):
            jumpDst = GetOperandValue(ea, 0)
            if ea in stack:
                return False
            elif GetMnem(ea) == "jmp":
                return checkLoop(jumpDst, end, cpArray(stack, ea))
            else:
                if checkLoop(jumpDst, end, cpArray(stack, ea)):
                    return True
        elif GetMnem(ea) == "retn":
            return False
        ea = NextHead(ea, idaapi.cvar.inf.maxEA)

    return False


def main():
    TimeStamp()
    checkResults()


def checkResults():
    temp = getListOfPossibleLoops(getListOfFunctions())
    loopFunctionsMethod1 = []
    for possibleLoopFunction in temp:
        loopInstructions = []
        check_loop = getSetOfLoops_2(possibleLoopFunction.function.start, possibleLoopFunction.function.end)
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
            if checkLoop2(loopInstruction.loopStart(), loopInstruction.loopEnd(),
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
            check_loop = getSetOfLoops_2(possibleLoopFunction.function.start, possibleLoopFunction.function.end)
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
                check_loop_ = checkLoop2(loopInstruction.loopStart(), loopInstruction.loopEnd(),
                                         possibleLoopFunction.function.end)
                ts = time.time() - ts
                timestamp += ts
                if check_loop_:
                    loopInstruction.verify()
        method2Time += timestamp
    print "Method 1 average timestamp: ", method1Time / 10
    print "Method 2 average timestamp: ", method2Time / 10


if __name__ == "__main__":
    main()
