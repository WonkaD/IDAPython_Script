# -------------------------------------- IMPORTS --------------------------------------


import binascii
import random
import sys

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
        res = self.name + " (" + transformPossition(self.start) + ", " + transformPossition(self.end) + ")\n"
        for disassembledInstruction in self.disassembled:
            res += str(disassembledInstruction) + " : " + bytesToHex(disassembledInstruction.getOpCode()) + "\n"
        return res

    def disassembleFunction(self):
        res = []
        for head in Heads(self.start, self.end):
            res.append(Disassembled(head, GetDisasm(head)))
        return res


class Disassembled:
    def __init__(self, possition, instruction):
        self.possition = possition
        self.instruction = instruction

    def __str__(self):
        return transformPossition(self.possition) + " : " + self.instruction

    def OpCode(self):
        return GetManyBytes(self.possition, ItemSize(self.possition))

    def Instruction(self):
        return GetMnem(self.possition)

    def Operand(self, i):
        return GetOpnd(self.possition, i)

    def OperandValue(self, i):
        return GetOperandValue(self.possition, i)

    def OperandType(self, i):
        return GetOpType(self.possition, i)


class Loop:
    class LoopInstruction:
        def __init__(self, instruction, verified=False):
            self.instruction = instruction
            self.verified = verified

        def loopStart(self):
            return self.instruction.OperandValue(0)

        def loopEnd(self):
            return self.instruction.possition

        def verify(self):
            self.verified = True

        def __str__(self):
            return "[Verified: " + str(self.verified) + "] " + str(self.instruction)

    def __init__(self, function_, loopInstructions):
        self.function = function_
        self.loopInstructions = loopInstructions

    def __str__(self):
        res = "Function: " + self.function.name + "(" + transformPossition(
            self.function.start) + ", " + transformPossition(self.function.end) + ")\n"
        for loopInstruction in self.loopInstructions:
            res += "\t[Verified: " + str(loopInstruction.verified) + "] " + str(loopInstruction.instruction) + "\n"
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
    if jmpInstruction.OperandValue(0) >= jmpInstruction.possition:
        return False
    else:
        return isJmpInTheFunction(function, jmpInstruction.OperandValue(0))
        # for instruction in instructions:
        #     if instruction.possition == jmpInstruction.OperandValue(0):
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
                loopInstructions.append(Loop.LoopInstruction(instruction))
                # print "Salto hacia arriba", function.name, str(instruction)
            elif "loop" in mnemonicName:
                loopInstructions.append(Loop.LoopInstruction(instruction, True))
                # print "Bucle", function.name, str(instruction)
            elif "call" in mnemonicName and function.name == instruction.Operand(0):
                loopInstructions.append(Loop.LoopInstruction(instruction, True))
                # print "Operacion recursiva", function.name, str(instruction)
        if len(loopInstructions) != 0:
            loopFunctions.append(Loop(function, loopInstructions))
    return loopFunctions


# -------------------------------------- UTILS --------------------------------------


def transformPossition(possition):
    return "0x%08x" % (possition)


def bytesToHex(bytes):
    return binascii.hexlify(bytearray(bytes))


def printLoops(loops):
    verified = 0
    notVerified = 0
    print "------------------------------------ START ------------------------------------"
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
    print "------------------------------------  END  ------------------------------------"


def printFunction(functionName, functions):
    for function in functions:
        if functionName == function.name:
            print function.name, transformPossition(function.start), transformPossition(function.end)
            for asm in function.disassembled:
                print transformPossition(asm.possition), ": ", asm.instruction, "#", asm.Instruction(), asm.Operand(
                    0), asm.OperandType(0), asm.OperandValue(0), bytesToHex(asm.OpCode())


def contains(loopInstructions, jumpDst):
    for loopInstruction in loopInstructions:
        if loopInstruction.loopStart() == jumpDst:
            # print "Contains \t" + str(loopInstruction)
            return loopInstruction.verified
    return None


# -------------------------------------- MAIN --------------------------------------

def advancedCheckLoop(start, end, stack):
    ea = start
    while ea != idaapi.BADADDR:
        if ea == end:
            break
        elif GetMnem(ea).startswith("j"):
            jumpDst = GetOperandValue(ea, 0)
            if ea in stack:
                print transformPossition(start), transformPossition(ea)
                break
            else:
                if GetMnem(ea) == "jmp":
                    return advancedCheckLoop(jumpDst, end, cpArray(stack, ea))
                else:
                    advancedCheckLoop(jumpDst, end, cpArray(stack, ea))
        elif GetMnem(ea) == "retn":
            break
        ea = NextHead(ea, idaapi.cvar.inf.maxEA)
    return


def cpArray(lista, item_):
    res = []
    for item in lista:
        res.append(item)
    if item_:
        res.append(item_)
    return res


def checkLoop(start, end, loop):
    print "Start: " + transformPossition(start) + ", End: " + transformPossition(end)
    ea = start
    while ea != idaapi.BADADDR:
        if ea == end:
            return True
        elif GetMnem(ea).startswith("j"):
            jumpDst = GetOperandValue(ea, 0)
            if isJmpInTheFunction(loop.function, jumpDst):
                value_ = contains(loop.loopInstructions, jumpDst)
                if value_ == True:
                    None
                elif value_ == False:
                    return None
                else:
                    if GetMnem(ea) == "jmp":
                        return checkLoop(jumpDst, end, loop)
                    else:
                        if checkLoop(jumpDst, end, loop):
                            return True
        elif GetMnem(ea) == "retn":
            return False
        ea = NextHead(ea, idaapi.cvar.inf.maxEA)

    return False


def main():
    loops = getListOfPossibleLoops(getListOfFunctions())
    for loop in loops:
        Function_start = loop.function.start
        Function_end = loop.function.end
        print loop.function.name, Function_start,transformPossition(Function_start), Function_end, transformPossition(Function_end)
        print str(advancedCheckLoop(loop.function.start, loop.function.end, []))
        print "-------------------------------------------------------"

    # print"-------------------------------- STRAT --------------------------------"
    # loops = getListOfPossibleLoops(getListOfFunctions())
    # for loop in loops:
    #     print "--------------------------------------------------------------------"
    #     while not loop.isVerified():
    #         loopInstruction = random.choice(loop.loopInstructions)
    #         if loopInstruction.verified:
    #             continue
    #         print str(loop)
    #         print "LoopInstructions: " + str(len(loop.loopInstructions))
    #         print "LoopInstruction to check: " + str(loopInstruction)
    #         loop.loopInstructions.remove(loopInstruction)
    #         check = checkLoop(loopInstruction.loopStart(), loopInstruction.loopEnd(), loop)
    #         if check == True:
    #             loopInstruction.verify()
    #         elif check == False:
    #             del loopInstruction
    #             print "Is A Loop: " + str(check) + "\n"
    #             continue
    #         loop.loopInstructions.append(loopInstruction)
    #         print "Is A Loop: " + str(check) + "\n"
    #
    # printLoops(loops)
    # print"-------------------------------- END --------------------------------"


if __name__ == "__main__":
    main()
