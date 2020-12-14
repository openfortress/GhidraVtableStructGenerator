#Print the methods in a class to a file
#@author Fenteale
#@category vtable
#@keybinding 
#@menupath Tools.Misc.Print class methods into file.
#@toolbar 
from ghidra.program.model.data import StructureDataType
from ghidra.program.model.data import PointerDataType

dataManager = currentProgram.getDataTypeManager()

fileToWriteStr = askFile("Where to put output file?", "Save")
classToPrint = askString("Which class?", "What class do you want to print functions for?")
fileToWrite = open(str(fileToWriteStr), "w")

classDT = dataManager.getDataType("/vtable" + classToPrint)

monitor.initialize(classDT.getNumComponents())

for c in classDT.getComponents():
	monitor.checkCanceled()
	#fileToWrite.write(c.getFieldName())
	nameParts = c.getFieldName().split("::")
	if nameParts[0] == classToPrint:
		fileToWrite.write(c.getDataType().getDataType().getPrototypeString(False))
		fileToWrite.write("\n")
	monitor.incrementProgress(1)


fileToWrite.close()