class Source:
    def __init__(self, name, line):
        self.name = name
        self.line = line

    def getName(self):
        return self.name
    
    def getLine(self):
        return self.line
    
    def __str__(self):
        return ("<" + self.name + "-" + str(self.line) + ">")
    
    def __repr__(self):
        return str(self)
    
    def __eq__(self, other):
        if isinstance(other, Source):
            return self.name == other.name and self.line == other.line
        return False
    
class Sanitizer:
    def __init__(self, name, line):
        self.name = name
        self.line = line

    def getName(self):
        return self.name
    
    def getLine(self):
        return self.line
    
    def __str__(self):
        return ("<" + self.name + "-" + str(self.line) + ">")
    
    def __repr__(self):
        return str(self)
    
    def __eq__(self, other):
        if isinstance(other, Sanitizer):
            return self.name == other.name and self.line == other.line
        return False
    
class Sink:
    def __init__(self, name, line):
        self.name = name
        self.line = line

    def getName(self):
        return self.name
    
    def getLine(self):
        return self.line
    
    def __str__(self):
        return ("<" + self.name + "-" + str(self.line) + ">")
    
    def __repr__(self):
        return str(self)
    
    def __eq__(self, other):
        if isinstance(other, Sink):
            return self.name == other.name and self.line == other.line
        return False