"""Index repository-local Python definitions as AST data. Never import scanned code."""

import ast
from pathlib import PurePosixPath


class PythonProject:
    def __init__(self, files):
        self.functions, self.classes, self.names, self.locations = {}, set(), {}, {}
        self.modules = {}
        for path in files:
            if path.endswith('.py'):
                module = self.module_name(path)
                if module in self.modules:
                    self.modules[module] = None  # ambiguous module roots are not resolved
                else:
                    self.modules[module] = path
        for module, path in self.modules.items():
            if not path:
                continue
            try:
                tree = ast.parse(files[path], filename=path)
            except (SyntaxError, RecursionError):
                continue
            bindings = {}
            for statement in tree.body:
                if isinstance(statement, ast.Import):
                    for alias in statement.names:
                        bindings[alias.asname or alias.name.split('.')[0]] = alias.name if alias.asname else alias.name.split('.')[0]
                elif isinstance(statement, ast.ImportFrom):
                    imported = self.import_module(path, statement.module, statement.level)
                    for alias in statement.names:
                        bindings[alias.asname or alias.name] = f'{imported}.{alias.name}'.strip('.')
                elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    bindings[statement.name] = f'{module}.{statement.name}'
            def index(nodes, prefix):
                for node in nodes:
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        name = prefix + node.name
                        if isinstance(node, ast.ClassDef):
                            self.classes.add(name)
                        else:
                            self.functions[name] = node
                            self.names[id(node)] = name
                            self.locations[name] = (path, files[path], bindings)
                        index(node.body, name + '.')
            index(tree.body, module + '.')

    @staticmethod
    def module_name(path):
        parts = list(PurePosixPath(path.replace('\\', '/')).with_suffix('').parts)
        if parts and parts[0] == 'src':
            parts.pop(0)
        if parts and parts[-1] == '__init__':
            parts.pop()
        return '.'.join(parts)

    def import_module(self, path, module, level):
        if not level:
            return module or ''
        current = self.module_name(path).split('.')
        package = current if path.replace('\\', '/').endswith('/__init__.py') else current[:-1]
        return '.'.join(package[:len(package) - level + 1] + ([module] if module else []))
