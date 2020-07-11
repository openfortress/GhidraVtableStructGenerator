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

def getAddress(offset):
	return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

functionManager = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
dataManager = currentProgram.getDataTypeManager()

addr = askAddress("Location of vtable", "Input offset where class vtable begins")
structName = askString("Name of struct", "Input name of structure to be added")
structData = StructureDataType(structName, 0)
dt = PointerDataType()

print(addr)
codeUnits = listing.getCodeUnits(addr, True)

keepgoing = True
while keepgoing:
	fs = next(codeUnits)
	#print("0x{} : {:16} {}".format(fs.getAddress(), hexlify(fs.getBytes()), fs.toString()))
	valparts = fs.toString().split()
	if valparts[0] == "addr":
		print("YES, this is an pointer")
		print(functionManager.getFunctionContaining(getAddress(valparts[1])))
		structData.add(dt, 4, functionManager.getFunctionContaining(getAddress(valparts[1])).toString(), "")
	else:
		keepgoing = False


dataManager.addDataType(structData, DataTypeConflictHandler.DEFAULT_HANDLER)