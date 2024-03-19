from Pattern import Pattern
from Policy import Policy
from MultiLabelling import MultiLabelling
from Vulnerabilities import Vulnerabilities
import sys
import ast
import astexport.export
import json
from traverse_ast import MyVisitor


#main with args
if __name__ == "__main__":
    # check if there are enough arguments
    if len(sys.argv) < 3:
        print("Usage: python3 py_analyzer.py <slice> <patterns_file>")
        exit(1)

    slice = sys.argv[1]
    patterns_file = sys.argv[2]

    # read slice with open()
    with open(slice, 'r') as f:
        slice = f.read()

    # read patterns from json file
    vulnerabilities = json.load(open(patterns_file))
    
    patterns = []
    for vulnerability in vulnerabilities:
        pattern = Pattern(vulnerability["vulnerability"], \
                                  vulnerability["sources"], \
                                  vulnerability["sanitizers"], \
                                  vulnerability["sinks"],\
                                  vulnerability["implicit"])

        patterns.append(pattern)
    
    policy = Policy(patterns)
    multiLabelling = MultiLabelling()
    vulnerabilities = Vulnerabilities()

    # parse the slice to an AST
    tree = ast.parse(slice)
    
    # use astexport and json to print
    # ast_dict = astexport.export.export_dict(tree)
    # print(json.dumps(ast_dict, indent=2))
    # print("")
    
    visitor = MyVisitor(policy, multiLabelling, vulnerabilities)
    visitor.visit(tree)
    name = sys.argv[1].split(".py")[0] + ".output.json"
    print("Writing output to " + name)
    with open(name, "w") as f:
        vuln = json.dumps(vulnerabilities.toJSON(), indent=4)
        f.write(vuln)