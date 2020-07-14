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
from ghidra.program.model.data import Undefined4DataType
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
		if dtI.getName() == dtName:
			return dtI

def getClassName(unparsedFnName):
	tmpLst = unparsedFnName.split("::")
	return tmpLst[0]

functionManager = currentProgram.getFunctionManager()
listing = currentProgram.getListing()


#addr = askAddress("Location of vtable", "Input offset where class vtable begins")
#structName = askString("Name of struct", "Input name of structure to be added")


#print(addr)

def generateVtableStruct(vtableAddr):
	codeUnits = listing.getCodeUnits(vtableAddr.add(8), True)
	vtableClassName = ""
	vtableName = ""
	structData = None
	keepgoing = True
	#tmp = next(codeUnits)
	#tmp = next(codeUnits)
	for fs in codeUnits:
		valparts = fs.toString().split()
		if valparts[0] == "addr":
			#print("YES, this is an pointer")
			fntoadd = functionManager.getFunctionContaining(getAddress(valparts[1]))
			if vtableName == "":
				vtableClassName = getClassName(fntoadd.toString())
				vtableName = "vtable" + vtableClassName
				structData = StructureDataType(vtableName, 0)
				print("Making vtable for " + vtableClassName)
				monitor.setMessage("Observe: Making vtable for " + vtableClassName)
			print(fntoadd)
			if fntoadd != None:
				dt = FunctionDefinitionDataType(fntoadd, False) #Second parameter is "Formality", I think this strips the "this" parameter, so lets not set this True
				dt.setCategoryPath(CategoryPath("/" + vtableName))
				dtAdded = dataManager.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER)
				ptr = PointerDataType(dtAdded)
				ptr.setCategoryPath(CategoryPath("/" + vtableName))
				ptrAdded = dataManager.addDataType(ptr, DataTypeConflictHandler.REPLACE_HANDLER)
				structData.add(ptrAdded, ptrAdded.getLength(), functionManager.getFunctionContaining(getAddress(valparts[1])).toString(), "")
		else:
			break
		
			
			

			


	vtableCDataType = dataManager.addDataType(structData, DataTypeConflictHandler.REPLACE_HANDLER)
	vtableCDataTypePtr = PointerDataType(vtableCDataType)
	vtableDTtoAdd = dataManager.addDataType(vtableCDataTypePtr, DataTypeConflictHandler.REPLACE_HANDLER)
	print("Created " + vtableName)

	classDT = getDataTypeFromString(vtableClassName)
	print("Adding vtable to " + classDT.getName() + " structure")
	if classDT.getDataTypeAt(0) != None:
		classDT.delete(0)
	classDT.insert(0, vtableDTtoAdd, vtableDTtoAdd.getLength(), "vtable", "")
	#classDT.realign()


##CODE FROM NOPEY
#Finds all VTables, prints them out in the console
#@author Magnus "Nopey" Larsen
#@category 
#@keybinding 
#@menupath Tools.Misc.Find all VTables
#@toolbar 

symbol_table = currentProgram.getSymbolTable()

symbols = symbol_table.getSymbolIterator()

monitor.initialize(symbol_table.getNumSymbols())

for symbol in symbols:
    monitor.checkCanceled()
    if symbol.getName().startswith("__ZTV"):
        print(symbol)
		vtA = symbol.getAddress()
		generateVtableStruct(vtA)
    monitor.incrementProgress(1)

###END CODE FROM NOPEY

#generateVtableStruct(addr)