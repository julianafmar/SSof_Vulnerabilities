from MultiLabel import MultiLabel
from Pattern import Pattern
from Source import Source, Sanitizer, Sink

class Policy:

    def __init__(self, patterns):
        if(isinstance(patterns, list)):
            for pattern in patterns:
                if (not isinstance(pattern, Pattern)):
                    raise ValueError("Invalid pattern")
                
            self.patterns = patterns
        else:
            raise ValueError("Invalid list of patterns")
                
    def getPatterns(self):
        return self.patterns
    
    def getPatternByName(self, name):
        if (isinstance(name, str)):
            for pattern in self.patterns:
                if (pattern.getVulnName() == name):
                    return pattern
            return None
        else:
            raise ValueError("Invalid vulnerability name: must be a string")

    def getVulnerabilities(self):
        vulnerabilities = []
        for pattern in self.getPatterns():
            vulnerabilities += [pattern.getVulnName()]
        return vulnerabilities
    
    def getVulnerabilitiesBySource(self, source):
        if (isinstance(source, Source)):
            vulnerabilities = []
            for pattern in self.patterns:
                if (pattern.isSource(source.getName())):
                    vulnerabilities += [pattern.getVulnName()]
            return vulnerabilities
        else:
            raise ValueError("Invalid Source")
    
    def getVulnerabilitiesBySanitizer(self, sanitizer):
        if (isinstance(sanitizer, Sanitizer)):
            vulnerabilities = []
            for pattern in self.patterns:
                if (pattern.isSanitizer(sanitizer.getName())):
                    vulnerabilities += [pattern.getVulnName()]
            return vulnerabilities
        else:
            raise ValueError("Invalid Sanitizer")
    
    def getVulnerabilitiesBySink(self, sink):
        if (isinstance(sink, Sink)):
            vulnerabilities = []
            for pattern in self.patterns:
                if (pattern.isSink(sink.getName())):
                    vulnerabilities += [pattern.getVulnName()]
            return vulnerabilities
        else:
            raise ValueError("Invalid Sink")
        
    def illegalFlow(self, name, multiLabel):
        if (isinstance(name, str)):
            if(isinstance(multiLabel, MultiLabel)):
                newMultiLabel = MultiLabel()
                for pattern in self.patterns:
                    if (pattern.isSink(name)):
                        m = multiLabel.getLabel(pattern.getVulnName())
                        if (m is not None):
                            newMultiLabel.addLabel(pattern.getVulnName(), m)
                return newMultiLabel
            else:
                raise ValueError("Invalid multiLabel")
        else:
            raise ValueError("Invalid name of sink: must be a string")