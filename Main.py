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

    
    def getOpCode(self):
        return GetManyBytes(self.possition, ItemSize(self.possition))


# -------------------------------------- CODE --------------------------------------


def getListOfFunctions():
    res = []
    for segea in Segments():
        for funcea in Functions(segea, SegEnd(segea)):
            functionName = GetFunctionName(funcea)
            for (startea, endea) in Chunks(funcea):
                res.append(Function(functionName, startea, endea))
    return res


# -------------------------------------- UTILS --------------------------------------


def transformPossition(possition):
    return "0x%08x"%(possition)

    
def bytesToHex(bytes):
    return binascii.hexlify(bytearray(bytes))


# -------------------------------------- MAIN --------------------------------------


def main():
    functions = getListOfFunctions()
    for function in functions:
        for instruction in function.disassembled:
            if "j" in GetMnem(instruction.possition):
                if GetOperandValue(instruction.possition,0) < instruction.possition :
                    print "Salto hacia arriba", function.name, str(instruction)
            if "loop" in GetMnem(instruction.possition):
                    print "Bucle", function.name, str(instruction)

        
if __name__ == "__main__":
    main()
