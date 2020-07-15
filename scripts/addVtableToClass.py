#Automatically attach a vtable struct to a class
#@author Fenteale
#@category vtable
#@keybinding 
#@menupath Tools.Misc.Attach Vtable Struct to class struct
#@toolbar 
from ghidra.program.model.data import StructureDataType
from ghidra.program.model.data import PointerDataType

dataManager = currentProgram.getDataTypeManager()

def getVtableDTs():
	listOfVtableDT = []
	listOfDataTypes = dataManager.getAllDataTypes()
	#monitor.initialize(len(listOfDataTypes))
	for dtI in listOfDataTypes:
		if dtI.getName().startswith('vtable'):
			if dtI.getName().endswith('*'):
				listOfVtableDT.append(dtI)
		#monitor.incrementProgress(1)
	return listOfVtableDT

allVT = getVtableDTs()

monitor.initialize(len(allVT))

for dt in allVT:
	monitor.checkCanceled()
	monitor.setMessage("Running for " + dt.getName())
	nameOfClass = dt.getName()[6:-2]
	monitor.setMessage("Adding vtable for " + nameOfClass)
	classDT = dataManager.getDataType("/" + nameOfClass)
	if classDT == None:
		classDT = dataManager.getDataType("/Demangler/" + nameOfClass)
	if classDT != None:
		if classDT.getNumComponents() > 0:
			classDT.delete(0)
			classDT.insert(0, dt, dt.getLength(), "vtable", "")
		else:
			classDT.insert(0, dt, dt.getLength(), "vtable", "")
	monitor.incrementProgress(1)


