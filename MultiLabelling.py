from MultiLabel import MultiLabel

class MultiLabelling:
    # mapping from variables names to multiLabels
    def __init__(self):
        self.multiLabels = {}

    def getMultiLabelsByName(self, name):
        if(isinstance(name, str)):
            if name in self.multiLabels:
                return self.multiLabels[name]
            else:
                return None
        else:
            raise ValueError("Invalid name: must be a string")
    
    def setMultiLabel(self, name, multiLabel):
        if(isinstance(name, str)):
            if(isinstance(multiLabel, MultiLabel)):
                self.multiLabels[name] = multiLabel
            else:
                raise ValueError("Invalid multiLabel")
        else:
            raise ValueError("Invalid name: must be a string")
        
    def __add__(self, other):
        if(isinstance(other, MultiLabelling)):
            newMultiLabelling = MultiLabelling()
            for name in self.multiLabels:
                newMultiLabelling.setMultiLabel(name, self.getMultiLabelsByName(name).deepcopy())
            for name in other.multiLabels:
                if name in newMultiLabelling.multiLabels:
                    newMultiLabelling.setMultiLabel(name, newMultiLabelling.getMultiLabelsByName(name) + other.getMultiLabelsByName(name))
                else:
                    newMultiLabelling.setMultiLabel(name, other.getMultiLabelsByName(name).deepcopy())
            return newMultiLabelling
        else:
            raise ValueError("Invalid multiLabel")

    def deepcopy(self):
        newMultiLabelling = MultiLabelling()
        for name in self.multiLabels:
            newMultiLabelling.setMultiLabel(name, self.multiLabels[name].deepcopy())
        return newMultiLabelling
    
    def __str__(self):
        string = ""
        for var in self.multiLabels:
            string += var + ": " + str(self.multiLabels[var]) + "\n"
        return string
