#Automatically make a vtable struct for a class
#@author Fenteale
#@category vtable
#@keybinding 
#@menupath Tools.Misc.Make Single Vtable Struct 
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
from ghidra.util.NumericUtilities import convertBytesToString

dataManager = currentProgram.getDataTypeManager()




def getAddress(offset):
	if offset == "" or offset == 0:
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0)
	else:
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

def getDataTypeFromString(dtName):
	listOfDataTypes = dataManager.getAllDataTypes()
	for dtI in listOfDataTypes:
		if dtI.getName() == dtName:
			if type(dtI) == StructureDataType:
				return dtI

def getClassName(unparsedFnName):
	tmpLst = unparsedFnName.split("::")
	return tmpLst[0]

functionManager = currentProgram.getFunctionManager()


addr = askAddress("Location of vtable", "Input offset where class vtable begins")
structName = askString("Name of struct", "Input name of class to be added")
#doGoogle = askYesNo("Performance Option", "Would you like to try and make vtables for google based API classes?")
#doFOSS = askYesNo("Performance Option", "Would you like to try and make vtables for common open source libraries? (eg: Crypto++)")

#print(addr)

def generateVtableStruct(vtableAddr):
	mem = currentProgram.getMemory()
	vtableClassName = structName
	vtableName = "vtable" + vtableClassName
	keepgoing = True
	cAddr = vtableAddr #.add(8)
	structData = StructureDataType(vtableName, 0)
	antiFreeze = 0
	while True:
		#print("Checking " + cAddr.toString())
		fnToCheck = functionManager.getFunctionContaining(getAddress(getAddress(mem.getInt(cAddr)).toString()))
		if fnToCheck != None:
			#print("Found start of vtable")
			break
		if antiFreeze >= 100:
			print("Something has to have gone wrong...")
			return
		cAddr = cAddr.add(1)
		antiFreeze += 1
		
	while True:
		fs = getAddress(mem.getInt(cAddr))
		valpart = fs.toString()
		fntoadd = functionManager.getFunctionContaining(getAddress(valpart))
		if fntoadd != None:
			#print("YES, this is an pointer")
			
			#print(fntoadd)
			if fntoadd != None:
				dt = FunctionDefinitionDataType(fntoadd, False) #Second parameter is "Formality", I think this strips the "this" parameter, so lets not set this True
				#dt.setCategoryPath(CategoryPath("/" + vtableName))
				fnClass = getClassName(fntoadd.toString())
				dt.setCategoryPath(CategoryPath("/vtable" + fnClass))
				dtAdded = dataManager.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER)
				ptr = PointerDataType(dtAdded)
				#ptr.setCategoryPath(CategoryPath("/" + vtableName))
				ptr.setCategoryPath(CategoryPath("/vtable" + fnClass))
				ptrAdded = dataManager.addDataType(ptr, DataTypeConflictHandler.REPLACE_HANDLER)
				structData.add(ptrAdded, ptrAdded.getLength(), fntoadd.toString(), "")
		else:
			print("Vtable reached the end.")
			break
		cAddr = cAddr.add(4)
		
			
			

			

	if structData != None:
		vtableCDataType = dataManager.addDataType(structData, DataTypeConflictHandler.REPLACE_HANDLER)
		vtableCDataTypePtr = PointerDataType(vtableCDataType)
		vtableDTtoAdd = dataManager.addDataType(vtableCDataTypePtr, DataTypeConflictHandler.REPLACE_HANDLER)
		print("Created " + vtableName)

	else:
		print("Skipped " + vtableName)

generateVtableStruct(addr)