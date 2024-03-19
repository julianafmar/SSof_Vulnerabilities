from Label import Label
from Pattern import Pattern

class MultiLabel:
    
    def __init__(self):
        self.labels = {}
            
    def addLabel(self, vulnName, label):
        if(isinstance(label, Label)):
            if(isinstance(vulnName, str)):
                if(vulnName in self.labels):
                    self.labels[vulnName] = self.labels[vulnName] + label
                else:
                    self.labels[vulnName] = label
            else:
                raise ValueError("Invalid pattern: must be a string")
        else:
            raise ValueError("Invalid label")
        
    def getLabel(self, vulnName):
        if(isinstance(vulnName, str)):
            if(vulnName in self.labels):
                return self.labels[vulnName]
            else:
                return None
        else:
            raise ValueError("Invalid pattern: must be a string")

    def getLabels(self):
        return self.labels
    
    def __str__(self):
        return str(self.labels)
    
    def __add__(self, other):
        if(isinstance(other, MultiLabel)):
            newMultiLabel = MultiLabel()
            for vulnName in self.labels:
                newMultiLabel.addLabel(vulnName, self.getLabel(vulnName).deepcopy())
            for vulnName in other.labels:
                newMultiLabel.addLabel(vulnName, other.getLabel(vulnName).deepcopy())
            return newMultiLabel
        else:
            raise ValueError("Invalid multiLabel")
        
    def deepcopy(self):
        newMultiLabel = MultiLabel()
        for vulnName in self.labels:
            newMultiLabel.addLabel(vulnName, self.labels[vulnName].deepcopy())
        return newMultiLabel