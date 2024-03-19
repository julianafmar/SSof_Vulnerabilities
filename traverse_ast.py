import ast
from Source import Source, Sanitizer, Sink
from MultiLabel import MultiLabel
from Label import Label

class MyVisitor(ast.NodeVisitor):

    def __init__(self, policy, multiLabelling, vulnerabilities):
        self.policy = policy
        self.multiLabelling = multiLabelling
        self.vulnerabilities = vulnerabilities
        self.definedFunctions = []


    def visit_Module(self, node: ast.Module):

        multiLabellings = [self.multiLabelling]
        
        for op in node.body:
            
            if isinstance(op, ast.Expr):
                for multiLabelling in multiLabellings:
                    if isinstance(op.value, ast.Call):
                        self.visit_Call(op.value, multiLabelling)
            
            elif isinstance(op, ast.Assign):
                for multiLabelling in multiLabellings:
                    self.visit_Assign(op, multiLabelling)
            
            elif isinstance(op, ast.If):
                newMultiLabellings = []
                for multiLabelling in multiLabellings:
                    multiLabelling_if, has_else = self.visit_If(op, multiLabelling)
                    newMultiLabellings += multiLabelling_if
                if has_else:
                    multiLabellings = newMultiLabellings
                else:
                    multiLabellings += newMultiLabellings
            
            elif isinstance(op, ast.While):
                newMultiLabellings = []
                for multiLabelling in multiLabellings:
                    multiLabelling_while = self.visit_While(op, multiLabelling)
                    newMultiLabellings += multiLabelling_while
                multiLabellings += newMultiLabellings
            
            elif isinstance(op, ast.FunctionDef):
                for multiLabelling in multiLabellings:
                    self.visit_FunctionDef(op, multiLabelling)
            
            else:
                print("error")


    def visit_Name(self, node: ast.Name, multiLabelling=None, call: bool=False):

        if multiLabelling is None:
            multiLabelling = self.multiLabelling
 
        source = Source(node.id, node.lineno)

        multiLabel = multiLabelling.getMultiLabelsByName(node.id)

        if multiLabel is None:
            multiLabel = MultiLabel()
            if not call:
                for vuln in self.policy.getVulnerabilities():
                    label = Label()
                    label.addSource(source)
                    multiLabel.addLabel(vuln, label)
                return multiLabel
        elif call:
            multiLabel = MultiLabel()
        
        for vuln in self.policy.getVulnerabilitiesBySource(source):
            pattern = self.policy.getPatternByName(vuln)
            label = Label()
            label.addSource(source)
            multiLabel.addLabel(pattern.getVulnName(), label)
        multiLabelling.setMultiLabel(node.id, multiLabel)
        
        return multiLabel
    
    
    def visit_Attribute(self, node: ast.Attribute, multiLabelling=None, isAssignTarget=False):
        
        varMultiLabel = MultiLabel() if isAssignTarget else self.visit_basicNodes(node.value, multiLabelling)
        
        attrName = node.attr
        source = Source(attrName, node.lineno)
        attrMultiLabel = multiLabelling.getMultiLabelsByName(attrName)

        if attrMultiLabel is None:
            attrMultiLabel = MultiLabel()
        
        for vuln in self.policy.getVulnerabilitiesBySource(source):
            pattern = self.policy.getPatternByName(vuln)
            label = Label()
            label.addSource(source)
            attrMultiLabel.addLabel(pattern.getVulnName(), label)
        
        multiLabelling.setMultiLabel(attrName, attrMultiLabel)
        
        return varMultiLabel + attrMultiLabel


    def visit_BinOp(self, node: ast.BinOp, multiLabelling=None):
        
        multiLabel1 = self.visit_basicNodes(node.left, multiLabelling=multiLabelling)
        multiLabel2 = self.visit_basicNodes(node.right, multiLabelling=multiLabelling)

        return multiLabel1 + multiLabel2


    def visit_Compare(self, node: ast.Compare, multiLabelling=None):
        
        multiLabel1 = self.visit_basicNodes(node.left, multiLabelling=multiLabelling)

        for comparator in node.comparators:
            multiLabel2 = self.visit_basicNodes(comparator, multiLabelling=multiLabelling)

        return multiLabel1 + multiLabel2
    

    def visit_Call(self, node: ast.Call, multiLabelling=None, multiLabel_cond=None):        

        if isinstance(node.func, ast.Attribute):
            funcName = node.func.attr
            multiLabel = self.visit_Attribute(node.func, multiLabelling)
        elif node.func.id in self.definedFunctions:
            funcName = node.func.id
            multiLabel = multiLabelling.getMultiLabelsByName(funcName)
        else:
            funcName = node.func.id
            multiLabel = self.visit_Name(node.func, multiLabelling, call=True)

        for arg in node.args:
            multiLabel += self.visit_basicNodes(arg, multiLabelling=multiLabelling)
        
        if multiLabel_cond is not None:
            for vulnName in multiLabel_cond.getLabels():
                if self.policy.getPatternByName(vulnName).isImplicit():
                    label = multiLabel_cond.getLabel(vulnName).deepcopy()
                    multiLabel.addLabel(vulnName, label)
           
        for vuln in multiLabel.getLabels():
            if self.policy.getPatternByName(vuln).isSanitizer(funcName):
                sanitizer = Sanitizer(funcName, node.func.lineno)
                multiLabel.getLabel(vuln).addSanitizer(sanitizer)
        
        sink = Sink(funcName, node.func.lineno)
        self.detectIllegalFlows(sink, multiLabel)
        
        return multiLabel


    def visit_Assign(self, node: ast.Assign, multiLabelling=None, multiLabel_cond=None):

        if multiLabelling is None:
            multiLabelling = self.multiLabelling
        
        multiLabel = self.visit_basicNodes(node.value, multiLabelling=multiLabelling, multiLabel_cond=multiLabel_cond)
        
        if multiLabel_cond is not None:
            for vulnName in multiLabel_cond.getLabels():
                if self.policy.getPatternByName(vulnName).isImplicit():
                    label = multiLabel_cond.getLabel(vulnName).deepcopy()
                    multiLabel.addLabel(vulnName, label)

        if multiLabel is not None:
            for target in node.targets:
                if isinstance(target, ast.Attribute):
                    attrName = target.attr
                    
                    multiLabelAttr = self.visit_Attribute(target, multiLabelling, True)
                    
                    multiLabelling.setMultiLabel(attrName, multiLabel)
                    
                    sink = Sink(target.value.id, target.value.lineno)
                    self.detectIllegalFlows(sink, multiLabelAttr + multiLabel)
                    
                    sink = Sink(attrName, target.lineno)
                    self.detectIllegalFlows(sink, multiLabel)
                
                else:
                    multiLabelling.setMultiLabel(target.id, multiLabel)
                    sink = Sink(target.id, target.lineno)
                    self.detectIllegalFlows(sink, multiLabel)
        

    def visit_If(self, node: ast.If, multiLabelling=None, multiLabel_cond=None):

        if multiLabelling is None:
            multiLabelling = self.multiLabelling

        multiLabelling_cond = multiLabelling.deepcopy()
            
        multiLabel = self.visit_basicNodes(node.test, multiLabelling=multiLabelling_cond)

        if multiLabel_cond is not None:
            multiLabel += multiLabel_cond

        multiLabellings_if = [multiLabelling_cond.deepcopy()]

        for op in node.body:
            if isinstance(op, ast.Expr):
                if isinstance(op.value, ast.Call):
                    for multiLabelling_aux in multiLabellings_if:
                        self.visit_Call(op.value, multiLabelling_aux, multiLabel)
            elif isinstance(op, ast.Assign):
                for multiLabelling_aux in multiLabellings_if:
                    self.visit_Assign(op, multiLabelling_aux, multiLabel)
            elif isinstance(op, ast.If):
                newMultiLabellings = []
                for multiLabelling_aux in multiLabellings_if:
                    multiLabelling_if, has_else = self.visit_If(op, multiLabelling_aux, multiLabel)
                    newMultiLabellings += multiLabelling_if
                if has_else:
                    multiLabellings_if = newMultiLabellings
                else:
                    multiLabellings_if += newMultiLabellings
            elif isinstance(op, ast.While):
                newMultiLabellings = []
                for multiLabelling_aux in multiLabellings_if:
                    multiLabelling_while = self.visit_While(op, multiLabelling_aux, multiLabel)
                    newMultiLabellings += multiLabelling_while
                multiLabellings_if += newMultiLabellings
        
        multiLabellings_else = [multiLabelling_cond.deepcopy()]
        has_else = False
        if node.orelse:
            has_else = True
            for op in node.orelse:
                if isinstance(op, ast.Expr):
                    if isinstance(op.value, ast.Call):
                        for multiLabelling_aux in multiLabellings_else:
                            self.visit_Call(op.value, multiLabelling_aux, multiLabel)
                elif isinstance(op, ast.Assign):
                    for multiLabelling_aux in multiLabellings_else:
                        self.visit_Assign(op, multiLabelling_aux, multiLabel)
                elif isinstance(op, ast.If):
                    newMultiLabellings = []
                    for multiLabelling_aux in multiLabellings_else:
                        multiLabelling_if, has_else = self.visit_If(op, multiLabelling_aux)
                        newMultiLabellings += multiLabelling_if
                    if has_else:
                        multiLabellings_else = newMultiLabellings
                    else:
                        multiLabellings_else += newMultiLabellings
                elif isinstance(op, ast.While):
                    newMultiLabellings = []
                    for multiLabelling_aux in multiLabellings_else:
                        multiLabelling_while = self.visit_While(op, multiLabelling_aux)
                        newMultiLabellings += multiLabelling_while
                    multiLabellings_else += newMultiLabellings
                        
        return multiLabellings_if + multiLabellings_else, has_else


    def visit_While(self, node: ast.While, multiLabelling=None, multiLabel_cond=None, max_loop_iterations=5):

        if multiLabelling is None:
            multiLabelling = self.multiLabelling

        multiLabellings_while = [multiLabelling.deepcopy()]

        for _ in range(max_loop_iterations):
            for multiLabelling_aux in multiLabellings_while:
                multiLabel = self.visit_basicNodes(node.test, multiLabelling=multiLabelling_aux)

            if multiLabel_cond is not None: ## fazer um while dentro do if para testar isto ???
                multiLabel += multiLabel_cond

            for op in node.body:
                if isinstance(op, ast.Expr):
                    if isinstance(op.value, ast.Call):
                        for multiLabelling_aux in multiLabellings_while:
                            self.visit_Call(op.value, multiLabelling_aux, multiLabel)
                elif isinstance(op, ast.Assign):
                    for multiLabelling_aux in multiLabellings_while:
                        self.visit_Assign(op, multiLabelling_aux, multiLabel)
                elif isinstance(op, ast.If):
                    newMultiLabellings = []
                    for multiLabelling_aux in multiLabellings_while:
                        multiLabelling_if, has_else = self.visit_If(op, multiLabelling_aux, multiLabel)
                        newMultiLabellings += multiLabelling_if
                    if has_else:
                        multiLabellings_while = newMultiLabellings
                    else:
                        multiLabellings_while += newMultiLabellings
                elif isinstance(op, ast.While):
                    newMultiLabellings = []
                    for multiLabelling_aux in multiLabellings_while:
                        multiLabelling_while = self.visit_While(op, multiLabelling_aux, multiLabel)
                        newMultiLabellings += multiLabelling_while
                    multiLabellings_while += newMultiLabellings
                    
        return multiLabellings_while


    def visit_List(self, node: ast.List, multiLabelling=None):

        if multiLabelling is None:
            multiLabelling = self.multiLabelling
        
        listMultiLabel = MultiLabel()
        
        for element in node.elts:
            listMultiLabel += self.visit_basicNodes(element, multiLabelling=multiLabelling)

        return listMultiLabel


    def visit_Tuple(self, node: ast.Tuple, multiLabelling=None):
        
        if multiLabelling is None:
            multiLabelling = self.multiLabelling
        
        tupleMultiLabel = MultiLabel()
        
        for element in node.elts:
            tupleMultiLabel += self.visit_basicNodes(element, multiLabelling=multiLabelling)
        
        return tupleMultiLabel
    
    
    def visit_arg(self, node: ast.arg, multiLabelling=None):
        
        if multiLabelling is None:
            multiLabelling = self.multiLabelling
        
        multiLabelling.setMultiLabel(node.arg, MultiLabel())
    
    
    def visit_Return(self, node: ast.Return, multiLabelling=None):
        
        if multiLabelling is None:
            multiLabelling = self.multiLabelling
        
        return self.visit_basicNodes(node.value, multiLabelling=multiLabelling)
    
    
    def visit_FunctionDef(self, node: ast.FunctionDef, multiLabelling=None):
        
        if multiLabelling is None:
            multiLabelling = self.multiLabelling
            
        multiLabel = MultiLabel()
            
        for arg in node.args.args:
            self.visit_arg(arg, multiLabelling=multiLabelling)
            
        for line in node.body:
            if isinstance(line, ast.Return):
                multiLabel = self.visit_Return(line, multiLabelling=multiLabelling)
            else:
                self.visit_basicNodes(line, multiLabelling=multiLabelling)
        
        multiLabelling.setMultiLabel(node.name, multiLabel)
        self.definedFunctions += [node.name]


    def visit_basicNodes(self, node, multiLabelling=None, multiLabel_cond=None):
        
        if (isinstance(node, ast.Name)):
            multiLabel = self.visit_Name(node, multiLabelling)
        elif (isinstance(node, ast.BinOp)):
            multiLabel = self.visit_BinOp(node, multiLabelling)
        elif (isinstance(node, ast.Compare)):
            multiLabel = self.visit_Compare(node, multiLabelling)
        elif (isinstance(node, ast.Call)):
            multiLabel = self.visit_Call(node, multiLabelling, multiLabel_cond)
        elif (isinstance(node, ast.Attribute)):
            multiLabel = self.visit_Attribute(node, multiLabelling)
        elif (isinstance(node, ast.List)):
            multiLabel = self.visit_List(node, multiLabelling)
        elif (isinstance(node, ast.Tuple)):
            multiLabel = self.visit_Tuple(node, multiLabelling)
        else:
            multiLabel = MultiLabel()
            
        return multiLabel


    def detectIllegalFlows(self, sink, multiLabel):

        illegal_multiLabel = self.policy.illegalFlow(sink.getName(), multiLabel)
        
        if illegal_multiLabel:
            for vulnName in illegal_multiLabel.getLabels():
                self.vulnerabilities.addIllegalFlow(sink, vulnName, illegal_multiLabel)