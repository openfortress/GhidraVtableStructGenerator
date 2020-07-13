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
from ghidra.program.model.data import CategoryPath

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

print(addr)
codeUnits = listing.getCodeUnits(addr, True)

keepgoing = True
while keepgoing:
	fs = next(codeUnits)
	valparts = fs.toString().split()
	if valparts[0] == "addr":
		print("YES, this is an pointer")
		fntoadd = functionManager.getFunctionContaining(getAddress(valparts[1]))
		print(fntoadd)
		if fntoadd != None:
			dt = FunctionDefinitionDataType(fntoadd, False) #Second parameter is "Formality", I think this strips the "this" parameter, so lets not set this True
			dt.setCategoryPath(CategoryPath("/" + structName))
			dtAdded = dataManager.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER)
			ptr = PointerDataType(dtAdded)
			ptr.setCategoryPath(CategoryPath("/" + structName))
			ptrAdded = dataManager.addDataType(ptr, DataTypeConflictHandler.REPLACE_HANDLER)
			structData.add(ptrAdded, 4, functionManager.getFunctionContaining(getAddress(valparts[1])).toString(), "")
	else:
		keepgoing = False


dataManager.addDataType(structData, DataTypeConflictHandler.REPLACE_HANDLER)
print("Created " + structName)