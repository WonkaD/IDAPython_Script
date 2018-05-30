# -------------------------------------- IMPORTS --------------------------------------


import binascii


# -------------------------------------- GLOBAL --------------------------------------


ASM_JMP_INSTRUCTIONS = ["JMP", "JA", "JNBE", "JAE", "JB", "JNAE", "JBE", "JNA", "JE", "JZ", "JNE", "JNZ", "JG", "JNLE", "JGE", "JNL", "JL", "JNGE", "JLE", "JNG", "JC", "JNC", "JNO", "JNP", "JPO", "JNS", "JO", "JP", "JPE", "JS", "LOOP", ]


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
            res += str(disassembledInstruction) + " : "+ bytesToHex(disassembledInstruction.getOpCode()) +"\n"
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

    def __init__(self, function_, loopInstructions):
        self.function = function_
        self.loopInstructions = loopInstructions

    # def addLoopInstruction(self, loopInstruction):
    #     self.loopInstructions.append(loopInstruction)

# -------------------------------------- CODE --------------------------------------


def getListOfFunctions():
    res = []
    for segea in Segments():
        for funcea in Functions(segea, SegEnd(segea)):
            functionName = GetFunctionName(funcea)
            for (startea, endea) in Chunks(funcea):
                res.append(Function(functionName, startea, endea))
    return res


def getListOfPossibleLoops(functions):
    loopFunctions = []
    for function in functions:
        loopInstructions = []
        for instruction in function.disassembled:
            mnemonicName = instruction.Instruction()
            if mnemonicName.startWith("j") and instruction.OperandValue(0) < instruction.possition:
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
    return loopInstructions


# -------------------------------------- UTILS --------------------------------------


def transformPossition(possition):
    return "0x%08x"%(possition)


def bytesToHex(bytes):
    return binascii.hexlify(bytearray(bytes))


def printFunction(functionName, functions):
    for function in functions:
        if functionName == function.name:
            print function.name, transformPossition(function.start), transformPossition(function.end)
            for asm in function.disassembled:
                print transformPossition(asm.possition), ": ", asm.instruction, "#", asm.Instruction(), asm.Operand(
                    0), asm.OperandType(0), asm.OperandValue(0), bytesToHex(asm.OpCode())


def search(list, filter):
    for x in list:
        if filter(x):
            return x
    return None
# -------------------------------------- MAIN --------------------------------------


def main():
    functions = getListOfFunctions()
    possibleLoops = getListOfPossibleLoops(functions)



if __name__ == "__main__":
    main()
