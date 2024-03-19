from MultiLabel import MultiLabel
from Source import Sink
import json

class Vulnerabilities:

    def __init__(self):
        self.vulnerability = {} # vuln -> ([sink, label], (...))

    def getVulnerabilities(self):
        return self.vulnerability

    def getIllegalFlowsByName(self, name):
        return self.vulnerability[name]
        
    def addIllegalFlow(self, sink, vulnName, multiLabel):
        if(isinstance(sink, Sink)):
            if(isinstance(multiLabel, MultiLabel)):
                if vulnName not in self.vulnerability:
                    self.vulnerability[vulnName] = ([sink, multiLabel.getLabel(vulnName)], )
                else:
                    existingFlows = self.vulnerability[vulnName]
                    label = multiLabel.getLabel(vulnName)
                    newFlow = [sink, label]

                    if newFlow not in existingFlows:
                        existSink = False
                        for flow in existingFlows:
                            if flow[0]==sink:
                                flow[1] = flow[1] + label
                                existSink = True
                                break
                        if not existSink:
                            self.vulnerability[vulnName] = existingFlows + (newFlow, )

            else:
                    raise ValueError("Invalid multiLabel")
        else:
            raise ValueError("Invalid sink")

    def __str__(self):
        string = ""
        for vuln in self.vulnerability:
            string += vuln + ": " + str(self.vulnerability[vuln]) + "\n"
        return string
    
    def toJSON(self):
        data = self.getVulnerabilities()
        result = []

        for key, value in data.items():
            count = 1
            for sink, label in value:
                for source, sanitizers in label.getSourcesSanitizers():
                    done = False
                    for vuln in result:
                        if vuln["vulnerability"][0]==key and vuln["source"] == [source.getName() , source.getLine()] and vuln["sink"] == [sink.getName() , sink.getLine()]:
                            if sanitizers==[]:
                                vuln["unsanitized_flows"] = "yes"
                            else:
                                vuln["sanitized_flows"].append([[x.getName(), x.getLine()] for x in sanitizers])
                            done = True
                            break
                    if not done:
                        vuln = {
                            "vulnerability": key + "_" + str(count),
                            "source": [source.getName() , source.getLine()],
                            "sink": [sink.getName() , sink.getLine()]
                        }
                        if sanitizers==[]:
                            vuln["unsanitized_flows"] = "yes"
                            vuln["sanitized_flows"] = []
                        else:
                            vuln["unsanitized_flows"] = "no"
                            vuln["sanitized_flows"] = [[[x.getName(), x.getLine()] for x in sanitizers]]
                        result.append(vuln)
                        count += 1

        return result