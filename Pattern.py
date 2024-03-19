from Source import Source

class Pattern:
    vuln_name = ""
    sources = []
    sanitizers = []
    sinks = []
    implicit = ""

    def __init__(self, vuln_name, sources, sanitizers, sinks, implicit):
        if (isinstance(vuln_name, str) and isinstance(sources, list) and isinstance(sanitizers, list) and isinstance(sinks, list) and isinstance(implicit, str)):
            for source in sources:
                if (isinstance(source, str)==False):
                    raise ValueError("Invalid source: must be a string")
            for sanitizer in sanitizers:
                if (isinstance(sanitizer, str)==False):
                    raise ValueError("Invalid sanitizer: must be a string")
            for sink in sinks:
                if (isinstance(sink, str)==False):
                    raise ValueError("Invalid sink: must be a string")
            self.vuln_name = vuln_name
            self.sources = sources
            self.sanitizers = sanitizers
            self.sinks = sinks
            self.implicit = implicit
        else:
            raise ValueError("Invalid name of the vulnerability: must be a string")

    def getVulnName(self):
        return self.vuln_name

    def getSources(self):
        return self.sources
    
    def getSanitizers(self):
        return self.sanitizers
    
    def getSinks(self):
        return self.sinks
    
    def isSource(self, name):
        if (isinstance(name, str)):
            return name in self.sources
        else:
            raise ValueError("Invalid source: must be a string")
    
    def isSanitizer(self, name):
        if (isinstance(name, str)):
            return name in self.sanitizers
        else:
            raise ValueError("Invalid sanitizer: must be a string")
    
    def isSink(self, name):
        if (isinstance(name, str)):
            return name in self.sinks
        else:
            raise ValueError("Invalid sink: must be a string")
        
    def isImplicit(self):
        return 1 if self.implicit == "yes" else 0
    
    def __str__(self):
        return "Pattern: " + self.vuln_name + "\nSources: " + str(self.sources) + "\nSanitizers: " + str(self.sanitizers) + "\nSinks: " + str(self.sinks) + "\nImplicit: " + self.implicit + "\n"