#Automatically make a vtable struct for a class
#@author Fenteale
#@category vtable
#@keybinding 
#@menupath Tools.Misc.Make Vtable Struct
#@toolbar 

#from binascii import hexlify
from ghidra.program.model.data import DataTypeConflictHandler
from ghidra.program.model.data import StructureDataType
from ghidra.program.model.data import DataType
from ghidra.program.model.data import PointerDataType
from ghidra.program.model.data import FunctionDefinitionDataType
from ghidra.program.model.data import GenericCallingConvention
from ghidra.program.model.data import ParameterDefinitionImpl

dataManager = currentProgram.getDataTypeManager()

def getAddress(offset):
	return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

def getDataTypeFromString(dtName):
	listOfDataTypes = dataManager.getAllDataTypes()
	for dtI in listOfDataTypes:
		if l.getName() == dtName:
			return l

functionManager = currentProgram.getFunctionManager()
listing = currentProgram.getListing()


addr = askAddress("Location of vtable", "Input offset where class vtable begins")
structName = askString("Name of struct", "Input name of structure to be added")
structData = StructureDataType(structName, 0)
dt = PointerDataType()

preexist = False
lofd = dataManager.getAllStructures()
for l in lofd:
	if l.getName() == structName:
		preexiststruct = l
		preexist = True
		break



print(addr)
codeUnits = listing.getCodeUnits(addr, True)

keepgoing = True
while keepgoing:
	fs = next(codeUnits)
	#print("0x{} : {:16} {}".format(fs.getAddress(), hexlify(fs.getBytes()), fs.toString()))
	valparts = fs.toString().split()
	if valparts[0] == "addr":
		print("YES, this is an pointer")
		fntoadd = functionManager.getFunctionContaining(getAddress(valparts[1]))
		print(fntoadd)
		if fntoadd != None:
			dt = FunctionDefinitionDataType(fntoadd, False) #Second parameter is "Formality", dont know exactly what it does
			#dt.setGenericCallingConvention(GenericCallingConvention.get(3))
			#fnparams = dt.getArguments()
			#className = functionManager.getFunctionContaining(getAddress(valparts[1])).toString().split(":")[0]
			#paramtoadd = ParameterDefinitionImpl("this", getDataTypeFromString(className), "") 
			#fnparams.insert(0, paramtoadd)
			#dt.setArguments(fnparams)
			#ptr = PointerDataType(dt)
			structData.add(dt, 4, functionManager.getFunctionContaining(getAddress(valparts[1])).toString(), "")
	else:
		keepgoing = False

if preexist == True:
	dataManager.replaceDataType(preexiststruct, structData, False)
	print("Replaced " + structName)
else:
	dataManager.addDataType(structData, DataTypeConflictHandler.DEFAULT_HANDLER)
	print("Created " + structName)