"""Conservative Python flow checks with bounded same-file calls; code is never executed."""

import ast
import re
from scanner.models import Category, Finding, Severity


class PythonAIAnalyzer(ast.NodeVisitor):
    def __init__(self, file_path, content, module="ai", include_experimental=False, project=None):
        self.file_path, self.content = file_path, content
        self.module, self.include_experimental = module, include_experimental
        self.findings, self.bindings, self.taint = [], {}, {}
        self.functions, self.classes, self.active_calls = {}, set(), []
        self.class_name = ""
        self.class_bases = {}
        self.literal_sets = {}
        self.function_names = {}
        self.return_sources = []
        self.receiver = None
        self.parameter_bindings = {}
        self.return_bindings = []
        self.call_bindings = {}
        self.call_count = 0
        self.call_cache = {}
        self.model_fields = {}
        self.project = project
        if project:
            self.functions.update(project.functions)
            self.classes.update(project.classes)
            self.function_names.update(project.names)

    def run(self):
        try:
            tree = ast.parse(self.content, filename=self.file_path)
            def index(nodes, prefix=""):
                for node in nodes:
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        name = prefix + node.name
                        if isinstance(node, ast.ClassDef):
                            self.classes.add(name)
                        else:
                            self.functions[name] = node
                            self.function_names[id(node)] = name
                        if not prefix:
                            self.bindings[node.name] = name
                        index(node.body, name + ".")
            index(tree.body)
            self.visit(tree)
            if self.call_count >= 1500:
                self.findings.append(Finding(
                    title="Python call-analysis budget reached", severity=Severity.INFO,
                    category=Category.SAST, module="coverage",
                    description="Bounded call analysis stopped after 1500 invocations for this entry file. Coverage is incomplete.",
                    file_path=self.file_path, rule_id="PY-BUDGET-001", evidence_kind="coverage-notice"))
        except (SyntaxError, RecursionError):
            self.findings.append(Finding(
                title="Python analysis skipped: syntax could not be parsed", severity=Severity.INFO,
                category=Category.SAST, module=self.module, description="Syntax-aware checks could not analyse this file.",
                file_path=self.file_path, recommendation="Check syntax and supported Python version, then scan again.",
                confidence="high", rule_id="PY-PARSE-001"))
        seen = set()
        return [finding for finding in self.findings
                if (finding.rule_id, finding.line_number, finding.description) not in seen
                and not seen.add((finding.rule_id, finding.line_number, finding.description))]

    def visit_Import(self, node):
        for alias in node.names:
            self.bindings[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]

    def visit_ImportFrom(self, node):
        module = self.project.import_module(self.file_path, node.module, node.level) if self.project else node.module
        for alias in node.names:
            self.bindings[alias.asname or alias.name] = f"{module}.{alias.name}" if module else alias.name

    def _name(self, node):
        if isinstance(node, ast.Call):
            constructor = self._name(node.func)
            if constructor in {"pathlib.Path", "socket.socket", "requests.Session", "httpx.Client", "httpx.AsyncClient"}:
                return constructor
            return self.call_bindings.get(id(node), "")
        if isinstance(node, ast.Name):
            return self.bindings.get(node.id, "")
        if isinstance(node, ast.Attribute):
            root = self._name(node.value)
            key = f"{root}.{node.attr}" if root else ""
            if key in self.bindings:
                return self.bindings[key]
            cls = root.split("@", 1)[0]
            fallback = f"{cls}.{node.attr}" if root else ""
            if fallback in self.bindings:
                return self.bindings[fallback]
            return fallback if fallback in self.functions else key
        return ""

    def _key(self, node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            root = self._name(node.value)
            return f"{root}.{node.attr}" if root else None
        return None

    @staticmethod
    def _combine(sources):
        sources = [source for source in sources if source]
        if not sources:
            return None
        selected = min(sources, key=lambda source: (source[0] == "model-response", len(source[2]) if len(source) > 2 else 0))
        safe = set(sources[0][2] if len(sources[0]) > 2 else ())
        for source in sources[1:]:
            safe.intersection_update(source[2] if len(source) > 2 else ())
        return (selected[0], selected[1], frozenset(safe)) + (selected[3:4] if len(selected) > 3 else ())

    @staticmethod
    def _safe_for(source, context):
        return bool(source and len(source) > 2 and context in source[2])

    def _mark_safe(self, source, context):
        if source:
            return (source[0], source[1], frozenset(source[2] if len(source) > 2 else ()) | {context}) + (source[3:4] if len(source) > 3 else ())
        return None

    def visit_FunctionDef(self, node):
        old_parameters, self.parameter_bindings = self.parameter_bindings, {}
        try:
            self._visit_function(node)
        finally:
            self.parameter_bindings = old_parameters

    def _visit_function(self, node, sources=None):
        self.bindings[node.name] = self.function_names.get(id(node), "")
        old_bindings, old_taint, old_literals = self.bindings.copy(), self.taint, self.literal_sets
        self.literal_sets = old_literals.copy()
        self.taint = {key: value for key, value in old_taint.items() if "." in key}
        self.taint.update(sources or {})
        decorators = [decorator.func if isinstance(decorator, ast.Call) else decorator for decorator in node.decorator_list]
        resolved_decorators = {self._name(decorator) for decorator in decorators}
        web_route = any(name.startswith(("fastapi.FastAPI.", "fastapi.APIRouter.", "flask.Flask.", "flask.Blueprint.", "bottle.route", "quart.Quart.", "sanic.Sanic.", "aiohttp.web.RouteTableDef.")) for name in resolved_decorators)
        pyramid_route = "pyramid.view.view_config" in resolved_decorators
        cherry_route = "cherrypy.expose" in resolved_decorators
        route_parameters = set()
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call) and decorator.args and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str):
                route_parameters.update(re.findall(r"(?:<(?:(?:path|string):)?|\{)([A-Za-z_]\w*)(?:>|\})", decorator.args[0].value))
        for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            self.literal_sets.pop(arg.arg, None)
            annotation = self._name(arg.annotation)
            known_types = {"fastapi.Request", "starlette.requests.Request", "django.http.HttpRequest", "sanic.request.Request", "aiohttp.web.Request", "falcon.Request", "sqlite3.Connection", "sqlite3.Cursor"}
            self.bindings[arg.arg] = self.parameter_bindings.get(arg.arg, annotation if annotation in known_types else "")
            if arg.arg == "self" and self.class_name:
                self.bindings[arg.arg] = self.receiver or self.class_name
            if arg.arg in {"request", "req"}:
                if pyramid_route:
                    self.bindings[arg.arg] = "pyramid.request.Request"
                elif web_route and any(name.startswith("sanic.Sanic.") for name in resolved_decorators):
                    self.bindings[arg.arg] = "sanic.request.Request"
                elif any(name.startswith("django.views.decorators.") for name in resolved_decorators) and any(
                        isinstance(item, ast.Attribute) and isinstance(item.value, ast.Name) and item.value.id == arg.arg
                        and item.attr in {"GET", "POST", "COOKIES", "FILES", "body"} for item in ast.walk(node)):
                    self.bindings[arg.arg] = "django.http.HttpRequest"
            if ("django.views.View" in self.class_bases.get(self.class_name, set())
                    and node.name in {"get", "post", "put", "patch", "delete", "head", "options"}
                    and len(node.args.args) > 1 and arg is node.args.args[1]):
                self.bindings[arg.arg] = "django.http.HttpRequest"
            text_annotation = (isinstance(arg.annotation, ast.Name) and arg.annotation.id == "str") or (
                isinstance(arg.annotation, ast.Subscript) and self._name(arg.annotation.value) in {"typing.Optional", "typing.Union"}
                and any(isinstance(item, ast.Name) and item.id == "str" for item in ast.walk(arg.annotation)))
            if isinstance(arg.annotation, ast.BinOp) and isinstance(arg.annotation.op, ast.BitOr):
                text_annotation = any(isinstance(item, ast.Name) and item.id == "str" for item in ast.walk(arg.annotation))
            if (web_route and (text_annotation or arg.arg in route_parameters)) or (cherry_route and arg.arg not in {"self", "cls"}):
                self.taint[arg.arg] = ("input", node.lineno)
            if web_route and "pydantic.BaseModel" in self.class_bases.get(annotation, set()):
                self.bindings[arg.arg] = annotation
                self.taint[arg.arg] = ("input", node.lineno)
        for arg in (node.args.vararg, node.args.kwarg):
            if arg:
                self.bindings[arg.arg] = ""
                if cherry_route:
                    self.taint[arg.arg] = ("input", node.lineno)
        for item in ast.walk(node):
            if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store):
                self.bindings[item.id] = ""
                self.literal_sets.pop(item.id, None)
        # Parameter names alone are not evidence of attacker control.
        old_returns, self.return_sources = self.return_sources, []
        old_return_bindings, self.return_bindings = self.return_bindings, []
        self._visit_block(node.body)
        returned = next((source for source in self.return_sources if source), None)
        returned_binding = next((name for name in self.return_bindings if name), "")
        self.return_sources = old_returns
        self.return_bindings = old_return_bindings
        members = {key: value for key, value in self.bindings.items() if "." in key}
        member_taint = {key: value for key, value in self.taint.items() if "." in key}
        self.bindings, self.taint = old_bindings, old_taint
        for key in set(self.taint) - set(member_taint):
            if "." in key:
                self.taint.pop(key, None)
        self.bindings.update(members)
        self.taint.update(member_taint)
        self.literal_sets = old_literals
        return returned, returned_binding

    def visit_Return(self, node):
        if node.value:
            self.visit(node.value)
            self.return_sources.append(self._source(node.value))
            self.return_bindings.append(self._name(node.value))

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.class_bases[node.name] = {self._name(base) for base in node.bases}
        if "pydantic.BaseModel" in self.class_bases[node.name]:
            for statement in node.body:
                if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                    self.model_fields[node.name, statement.target.id] = ast.unparse(statement.annotation)
        old_bindings, old_taint, old_literals = self.bindings.copy(), self.taint, self.literal_sets
        self.literal_sets = old_literals.copy()
        old_class, self.class_name = self.class_name, node.name
        self.taint = {}
        for statement in node.body:
            self.visit(statement)
        self.bindings, self.taint = old_bindings, old_taint
        self.literal_sets = old_literals
        self.class_name = old_class

    def _source(self, node):
        resolved = self._name(node)
        if isinstance(node, ast.Attribute):
            field = self.model_fields.get((self._name(node.value), node.attr))
            if field in {"int", "float", "bool"}:
                return None
        key = self._key(node)
        if key in self.taint:
            return self.taint[key]
        if isinstance(node, ast.Attribute):
            owner = self._name(node.value)
            if ("http.server.BaseHTTPRequestHandler" in self.class_bases.get(owner, set())
                    and node.attr in {"path", "rfile", "headers"}):
                return ("input", node.lineno)
        if isinstance(node, ast.Call):
            name = self._name(node.func)
            sanitizer = {"html.escape": "html", "markupsafe.escape": "html", "django.utils.html.escape": "html", "django.utils.html.conditional_escape": "html", "bleach.clean": "html", "werkzeug.utils.secure_filename": "path", "shlex.quote": "shell"}.get(name)
            if sanitizer and node.args and (name != "bleach.clean" or len(node.args) == 1 and not node.keywords):
                # Escaping one grammar never removes taint for another sink type.
                return self._mark_safe(self._source(node.args[0]), sanitizer)
            if name in {"os.path.abspath", "os.path.realpath", "pathlib.Path.resolve", "pathlib.Path.absolute"}:
                values = node.args if not isinstance(node.func, ast.Attribute) or not name.startswith("pathlib.") else [node.func.value]
                return self._mark_safe(self._combine(self._source(value) for value in values), "normalized-path")
            if name in {"argparse.ArgumentParser.parse_args", "argparse.ArgumentParser.parse_known_args", "sys.stdin.read", "sys.stdin.readline"}:
                return ("input", node.lineno, frozenset({"local-input"}))
            if name in {"os.path.join", "os.path.abspath", "os.path.realpath", "os.path.normpath", "os.fspath", "pathlib.Path", "pathlib.Path.resolve", "pathlib.Path.absolute", "urllib.parse.unquote", "urllib.parse.unquote_plus", "urllib.parse.parse_qs", "json.loads", "json.load", "base64.b64decode", "zlib.decompress", "builtins.open", "io.open"} or (isinstance(node.func, ast.Name) and node.func.id == "open" and "open" not in self.bindings):
                return self._combine(self._source(value) for value in node.args)
            if name in self.functions:
                return self._invoke(node, name)
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"join", "copy", "rsplit", "splitlines"}:
                return self._combine(self._source(value) for value in [node.func.value] + node.args)
            if name == "socket.socket.recv":
                return ("input", node.lineno)
            if (isinstance(node.func, ast.Attribute)
                    and "tornado.web.RequestHandler" in self.class_bases.get(self._name(node.func.value), set())
                    and node.func.attr in {"get_argument", "get_query_argument", "get_body_argument"}):
                return ("input", node.lineno)
            if isinstance(node.func, ast.Name) and node.func.id == "input" and "input" not in self.bindings:
                return ("input", node.lineno, frozenset({"local-input"}))
            if name in {f"{root}.{method}" for root in ("flask.request", "bottle.request", "quart.request", "fastapi.Request", "starlette.requests.Request", "django.http.HttpRequest", "pyramid.request.Request", "sanic.request.Request", "aiohttp.web.Request", "falcon.Request")
                        for method in ("get_json", "json", "args.get", "args.getlist", "form.get", "forms.get", "query.get", "query_params.get", "headers.get", "cookies.get", "GET.get", "POST.get", "GET.getlist", "POST.getlist", "COOKIES.get")}:
                if any(kw.arg == "type" and isinstance(kw.value, ast.Name) and kw.value.id in {"int", "float"}
                       and kw.value.id not in self.bindings for kw in node.keywords):
                    return None
                return ("input", node.lineno)
            if name == "json.loads" or (isinstance(node.func, ast.Name) and node.func.id == "str" and "str" not in self.bindings):
                return self._source(node.args[0]) if node.args else None
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"get", "read", "strip", "lstrip", "rstrip", "lower", "upper", "decode", "encode", "replace", "split", "format"}:
                source = self._source(node.func.value)
                if source:
                    return source
                if node.func.attr == "format":
                    return next((self._source(value) for value in node.args + [kw.value for kw in node.keywords] if self._source(value)), None)
            if self._is_llm_call(node):
                return ("model-response", node.lineno)
        if resolved == "sys.argv":
            return ("input", node.lineno, frozenset({"local-input"}))
        if resolved in {f"{root}.{attribute}" for root in ("flask.request", "bottle.request", "quart.request", "fastapi.Request", "starlette.requests.Request", "django.http.HttpRequest", "pyramid.request.Request", "sanic.request.Request", "aiohttp.web.Request", "falcon.Request")
                               for attribute in ("args", "form", "forms", "query", "query_params", "json", "data", "headers", "cookies", "files", "GET", "POST", "body", "COOKIES", "FILES", "params", "matchdict", "stream", "media")}:
            return ("input", node.lineno)
        if isinstance(node, ast.Name):
            return self.taint.get(node.id)
        if isinstance(node, ast.Subscript):
            return self._source(node.value)
        if isinstance(node, ast.Attribute):
            source = self._source(node.value)
            if source and source[0] == "model-response" and node.attr in {"content", "output_text", "text"}:
                return ("model", source[1])
            if source and node.attr in {"name"} and self._name(node.value).startswith("pathlib.Path"):
                return self._mark_safe(source, "path")
            return source
        # shortcut: propagate transparent expressions only, expand with framework-specific tests.
        if isinstance(node, (ast.Attribute, ast.Subscript, ast.BinOp, ast.BoolOp, ast.JoinedStr, ast.FormattedValue,
                             ast.List, ast.Tuple, ast.Dict, ast.Await)):
            return self._combine(self._source(child) for child in ast.iter_child_nodes(node))
        return None

    def _assign(self, target, value):
        if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, ast.Call) and self._name(value.func) == "socket.socket.accept":
            if target.elts and isinstance(target.elts[0], ast.Name):
                self.bindings[target.elts[0].id] = "socket.socket"
            for item in target.elts[1:]:
                if isinstance(item, ast.Name):
                    self.bindings[item.id] = ""
                    self.taint.pop(item.id, None)
            return
        key = self._key(target)
        if not key:
            return
        if isinstance(value, (ast.Set, ast.List, ast.Tuple)) and all(isinstance(item, ast.Constant) and isinstance(item.value, str) for item in value.elts):
            self.literal_sets[key] = value
        else:
            self.literal_sets.pop(key, None)
        source = self._source(value) if value is not None else None
        if source:
            self.taint[key] = source
        else:
            self.taint.pop(key, None)
        name = self._name(value)
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Div) and self._name(value.left) == "pathlib.Path":
            name = "pathlib.Path"
        if isinstance(value, ast.Call):
            constructor = self._name(value.func)
            name = self.call_bindings.get(id(value), name)
            if constructor in {"openai.OpenAI", "openai.AsyncOpenAI", "anthropic.Anthropic", "anthropic.AsyncAnthropic"}:
                name = constructor
            if constructor in self.classes or constructor in {"fastapi.FastAPI", "fastapi.APIRouter", "flask.Flask", "flask.Blueprint", "quart.Quart", "sanic.Sanic", "aiohttp.web.RouteTableDef", "socket.socket", "argparse.ArgumentParser", "pathlib.Path", "jinja2.Environment", "zipfile.ZipFile", "tarfile.open"}:
                name = constructor
            name = {"sqlite3.connect": "sqlite3.Connection", "sqlite3.Connection.cursor": "sqlite3.Cursor", "django.db.connection.cursor": "sqlite3.Cursor", "argparse.ArgumentParser.add_subparsers": "argparse.Subparsers", "argparse.Subparsers.add_parser": "argparse.ArgumentParser"}.get(constructor, name)
            if constructor in {"pathlib.Path.resolve", "pathlib.Path.absolute", "pathlib.Path.joinpath"}:
                name = "pathlib.Path"
            factory = self.functions.get(constructor)
            if factory and len(factory.body) == 1 and isinstance(factory.body[0], ast.Return):
                returned = factory.body[0].value
                if isinstance(returned, ast.Call) and self._name(returned.func) == "sqlite3.connect":
                    name = "sqlite3.Connection"
            if constructor in self.classes:
                name = f"{constructor}@{value.lineno}:{value.col_offset}"
                self.bindings[key] = name
                self._invoke(value, f"{constructor}.__init__", receiver=name)
        if isinstance(value, ast.Await) and isinstance(value.value, ast.Call) and self._name(value.value.func) == "asyncpg.connect":
            name = "asyncpg.Connection"
        self.bindings[key] = name

    def _invoke(self, node, name, receiver=None):
        if name not in self.functions or name in self.active_calls or len(self.active_calls) >= 5:
            return None
        function = self.functions[name]
        parameters = function.args.posonlyargs + function.args.args
        if parameters and parameters[0].arg in {"self", "cls"} and "." in name:
            parameters = parameters[1:]
        supplied = [parameter.arg for parameter in parameters[:len(node.args)]] + [kw.arg for kw in node.keywords]
        required = {parameter.arg for parameter in parameters[:max(0, len(parameters) - len(function.args.defaults))]}
        required.update(parameter.arg for parameter, default in zip(function.args.kwonlyargs, function.args.kw_defaults) if default is None)
        valid_names = {parameter.arg for parameter in parameters + function.args.kwonlyargs}
        if (len(node.args) > len(parameters) and not function.args.vararg
                or any(isinstance(value, ast.Starred) for value in node.args)
                or any(kw.arg is None or kw.arg not in valid_names for kw in node.keywords)
                or any(kw.arg in {parameter.arg for parameter in function.args.posonlyargs} for kw in node.keywords)
                or len(set(supplied)) != len(supplied) or not required.issubset(supplied)):
            return None
        # Resolve caller expressions before switching into the callee's scope.
        arguments = [(parameter.arg, value) for parameter, value in zip(parameters, node.args)]
        arguments += [(kw.arg, kw.value) for kw in node.keywords if kw.arg]
        sources = {key: source for key, value in arguments if (source := self._source(value))}
        sources = {key: source if len(source) > 3 else (source[0], source[1], frozenset(source[2] if len(source) > 2 else ()), self.file_path)
                   for key, source in sources.items()}
        bindings = {key: resolved for key, value in arguments if (resolved := self._name(value))}
        cache_key = (id(node), name, receiver, tuple(self.active_calls), tuple(sources.items()),
                     tuple(sorted(self.bindings.items())), tuple(sorted(self.taint.items())),
                     tuple((key, ast.dump(value)) for key, value in sorted(self.literal_sets.items())))
        if cache_key in self.call_cache:
            source, binding, members, member_taint = self.call_cache[cache_key]
            self.call_bindings[id(node)] = binding
            self.bindings.update(members)
            for key in list(self.taint):
                if "." in key:
                    self.taint.pop(key)
            self.taint.update(member_taint)
            return source
        if self.call_count >= 1500:
            return None
        old_class, old_receiver, old_parameters = self.class_name, self.receiver, self.parameter_bindings
        old_file, old_content, old_globals = self.file_path, self.content, None
        if self.project and name in self.project.locations:
            path, content, globals_ = self.project.locations[name]
            if path != self.file_path:
                old_globals = self.bindings
                self.file_path, self.content = path, content
                self.bindings = dict(globals_)
                self.bindings.update({key: value for key, value in old_globals.items() if "." in key})
        parent = name.rsplit(".", 1)[0] if "." in name else ""
        self.class_name = parent if parent in self.classes else old_class
        self.receiver = receiver or (self._name(node.func.value) if isinstance(node.func, ast.Attribute) else old_receiver)
        self.parameter_bindings = bindings
        self.active_calls.append(name)
        self.call_count += 1
        try:
            source, binding = self._visit_function(function, sources)
            if source and len(source) < 4:
                source = source[0], source[1], frozenset(source[2] if len(source) > 2 else ()), self.file_path
            self.call_bindings[id(node)] = binding
            self.call_cache[cache_key] = (source, binding,
                                          {key: value for key, value in self.bindings.items() if "." in key},
                                          {key: value for key, value in self.taint.items() if "." in key})
            return source
        finally:
            self.active_calls.pop()
            self.class_name, self.receiver, self.parameter_bindings = old_class, old_receiver, old_parameters
            if old_globals is not None:
                old_globals.update({key: value for key, value in self.bindings.items() if "." in key})
                self.bindings = old_globals
            self.file_path, self.content = old_file, old_content

    def visit_Assign(self, node):
        self.visit(node.value)
        for target in node.targets:
            self._assign(target, node.value)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.visit(node.value)
        self._assign(node.target, node.value)

    def visit_AugAssign(self, node):
        self.visit(node.value)
        if isinstance(node.target, ast.Name) and node.target.id not in self.taint:
            self._assign(node.target, node.value)

    def visit_With(self, node):
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars:
                self._assign(item.optional_vars, item.context_expr)
        for statement in node.body:
            self.visit(statement)

    visit_AsyncWith = visit_With

    def _state(self):
        return self.bindings.copy(), self.taint.copy(), self.literal_sets.copy()

    def _restore(self, state):
        self.bindings, self.taint, self.literal_sets = (part.copy() for part in state)

    def _merge_states(self, states):
        """Keep possible taint, but only retain resolutions/allowlists shared by every path."""
        if not states:
            return
        self.bindings = {key: value for key, value in states[0][0].items()
                         if all(state[0].get(key) == value for state in states)}
        self.taint = {}
        for _, taint, _ in states:
            for key, value in taint.items():
                self.taint[key] = self._combine([self.taint.get(key), value])
        self.literal_sets = {key: value for key, value in states[0][2].items()
                             if all(key in state[2] and ast.dump(state[2][key]) == ast.dump(value)
                                    for state in states)}

    def _terminates(self, statement):
        if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
            return True
        if isinstance(statement, ast.If):
            return bool(statement.body and statement.orelse
                        and self._terminates(statement.body[-1])
                        and self._terminates(statement.orelse[-1]))
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
            return self._name(statement.value.func) in {"flask.abort", "quart.abort", "sys.exit"}
        return False

    def _visit_block(self, statements):
        for statement in statements:
            self.visit(statement)
            if self._terminates(statement):
                return False
        return True

    def visit_If(self, node):
        self.visit(node.test)
        initial = self._state()
        allowed = self._literal_allowlist(node.test)
        boundary, positive = self._path_boundary(node.test)
        states = []
        if allowed and isinstance(node.test.ops[0], ast.In):
            self.taint.pop(allowed, None)
        if boundary and positive and self.taint.get(boundary):
            self.taint[boundary] = self._mark_safe(self.taint.get(boundary), "path")
        if self._visit_block(node.body):
            states.append(self._state())
        self._restore(initial)
        if allowed and isinstance(node.test.ops[0], ast.NotIn):
            self.taint.pop(allowed, None)
        if boundary and not positive and self.taint.get(boundary):
            self.taint[boundary] = self._mark_safe(self.taint.get(boundary), "path")
        if self._visit_block(node.orelse):
            states.append(self._state())
        self._merge_states(states)

    def _path_boundary(self, test):
        positive = True
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            positive, test = False, test.operand
        if isinstance(test, ast.Call) and self._name(test.func) in self.functions:
            function = self.functions[self._name(test.func)]
            parameters = function.args.posonlyargs + function.args.args
            if parameters and parameters[0].arg in {"self", "cls"}:
                parameters = parameters[1:]
            normalized = {}
            for statement in function.body:
                if isinstance(statement, ast.Assign) and len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name):
                    value = statement.value
                    normalized.pop(statement.targets[0].id, None)
                    if isinstance(value, ast.Call) and self._name(value.func) in {"os.path.abspath", "os.path.realpath"} and value.args and isinstance(value.args[0], ast.Name):
                        normalized[statement.targets[0].id] = normalized.get(value.args[0].id, value.args[0].id)
                elif isinstance(statement, ast.Return) and isinstance(statement.value, ast.Call):
                    returned = statement.value
                    if (isinstance(returned.func, ast.Attribute) and returned.func.attr == "startswith"
                            and isinstance(returned.func.value, ast.Name) and returned.func.value.id in normalized and returned.args):
                        prefix = returned.args[0]
                        if (isinstance(prefix, ast.BinOp) and isinstance(prefix.op, ast.Add)
                                and (self._name(prefix.right) == "os.sep" or isinstance(prefix.right, ast.Constant) and prefix.right.value in {"/", "\\"})):
                            base = normalized.get(prefix.left.id, prefix.left.id) if isinstance(prefix.left, ast.Name) else None
                            base_argument = next((value for param, value in zip(parameters, test.args) if param.arg == base), None)
                            base_argument = next((kw.value for kw in test.keywords if kw.arg == base), base_argument)
                            if base_argument is not None and self._source(base_argument):
                                continue
                            parameter = normalized[returned.func.value.id]
                            argument = next((value for param, value in zip(parameters, test.args) if param.arg == parameter), None)
                            argument = next((kw.value for kw in test.keywords if kw.arg == parameter), argument)
                            if self._key(argument):
                                return self._key(argument), positive
                elif not isinstance(statement, ast.Expr):
                    # No guessed summaries for arbitrary validators or branching code.
                    break
        if isinstance(test, ast.Call) and isinstance(test.func, ast.Attribute) and test.args:
            source = self._source(test.func.value)
            key = self._key(test.func.value)
            if key and self._safe_for(source, "normalized-path"):
                if test.func.attr == "is_relative_to" and self._name(test.func.value) == "pathlib.Path" and not self._source(test.args[0]):
                    return key, positive
                prefix = test.args[0]
                boundary_suffix = isinstance(prefix, ast.BinOp) and isinstance(prefix.op, ast.Add) and (
                    self._name(prefix.right) == "os.sep" or isinstance(prefix.right, ast.Constant) and prefix.right.value in {"/", "\\"})
                if test.func.attr == "startswith" and boundary_suffix and not self._source(prefix.left):
                    return key, positive
        if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], (ast.Eq, ast.NotEq)):
            left, right = test.left, test.comparators[0]
            if isinstance(right, ast.Call) and self._name(right.func) == "os.path.commonpath":
                left, right = right, left
            if isinstance(left, ast.Call) and self._name(left.func) == "os.path.commonpath" and left.args and isinstance(left.args[0], (ast.List, ast.Tuple)):
                values = left.args[0].elts
                if len(values) == 2 and any(ast.dump(value) == ast.dump(right) for value in values):
                    candidate = next((value for value in values if ast.dump(value) != ast.dump(right)), None)
                    key = self._key(candidate)
                    if key and self._safe_for(self._source(candidate), "normalized-path") and not self._source(right):
                        return key, positive == isinstance(test.ops[0], ast.Eq)
        return None, positive

    def _literal_allowlist(self, test):
        if not isinstance(test, ast.Compare) or len(test.comparators) != 1:
            return None
        values = test.comparators[0]
        if isinstance(values, ast.Name):
            values = self.literal_sets.get(values.id)
        if (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name)
                and len(test.ops) == 1 and isinstance(test.ops[0], (ast.In, ast.NotIn))
                and isinstance(values, (ast.Set, ast.List, ast.Tuple))
                and all(isinstance(value, ast.Constant) and isinstance(value.value, str) for value in values.elts)):
            return test.left.id
        return None

    def visit_Try(self, node):
        # A handler may run after any prefix of the try block, not just its entry.
        prefixes, states = [self._state()], []
        falls_through = True
        for statement in node.body:
            self.visit(statement)
            prefixes.append(self._state())
            if self._terminates(statement):
                falls_through = False
                break
        if falls_through and self._visit_block(node.orelse):
            states.append(self._state())
        self._merge_states(prefixes)
        handler_entry = self._state()
        for handler in node.handlers:
            self._restore(handler_entry)
            if handler.name:
                self.bindings[handler.name] = ""
                self.taint.pop(handler.name, None)
                self.literal_sets.pop(handler.name, None)
            if self._visit_block(handler.body):
                states.append(self._state())
        self._merge_states(states)
        self._visit_block(node.finalbody)

    visit_TryStar = visit_Try

    def visit_For(self, node):
        self.visit(node.iter)
        initial = self._state()
        self._assign(node.target, node.iter)
        self._visit_block(node.body)
        self._merge_states([initial, self._state()])
        before_else = self._state()
        self._visit_block(node.orelse)
        if any(isinstance(item, ast.Break) for item in ast.walk(node)):
            self._merge_states([before_else, self._state()])

    visit_AsyncFor = visit_For

    def visit_While(self, node):
        self.visit(node.test)
        initial = self._state()
        self._visit_block(node.body)
        self._merge_states([initial, self._state()])
        before_else = self._state()
        self._visit_block(node.orelse)
        if any(isinstance(item, ast.Break) for item in ast.walk(node)):
            self._merge_states([before_else, self._state()])

    def _is_llm_call(self, node):
        return self._name(node.func) in {
            "openai.chat.completions.create", "openai.ChatCompletion.create", "openai.responses.create",
            "openai.OpenAI.chat.completions.create", "openai.AsyncOpenAI.chat.completions.create",
            "openai.OpenAI.responses.create", "openai.AsyncOpenAI.responses.create",
            "anthropic.Anthropic.messages.create", "anthropic.AsyncAnthropic.messages.create",
        }

    def visit_Call(self, node):
        if self._name(node.func) == "threading.Thread":
            target = next((kw.value for kw in node.keywords if kw.arg == "target"), None)
            arguments = next((kw.value for kw in node.keywords if kw.arg == "args"), None)
            if target is not None and isinstance(arguments, (ast.Tuple, ast.List)):
                callback = ast.copy_location(ast.Call(func=target, args=arguments.elts, keywords=[]), node)
                self._invoke(callback, self._name(target))
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.attr in {"append", "extend", "insert", "add", "update", "clear", "remove", "pop"}:
            self.literal_sets.pop(node.func.value.id, None)
        name = self._name(node.func)
        builtin = node.func.id if isinstance(node.func, ast.Name) and node.func.id not in self.bindings else ""
        values = node.args[:1] + [kw.value for kw in node.keywords if kw.arg in {"source", "object", "command", "args", "s", "data", "file"}]
        source = next((self._source(value) for value in values if self._source(value)), None)
        code_sink = builtin in {"eval", "exec"}
        shell_sink = name in {"os.system", "os.popen"} or (
            name in {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_call", "subprocess.check_output"}
            and any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords))
        if source and source[0] != "model-response" and (code_sink or (shell_sink and not self._safe_for(source, "shell"))):
            model = source[0] == "model"
            self._add(node, "PY-AI-EXEC-001" if model else "PY-SAST-EXEC-001",
                      "LLM output reaches code execution" if model else "External input reaches command/code execution",
                      Severity.CRITICAL, Category.SAST,
                      f"{'Model output' if model else 'External input'} from line {source[1]} reaches this execution sink without a recognised boundary.",
                      "Do not execute untrusted text. Use a fixed operation allowlist and structured arguments.", "CWE-94" if code_sink else "CWE-78", source_line=source[1], source_file=source[3] if len(source) > 3 else None)
        unsafe_loader = name in {"pickle.load", "pickle.loads", "dill.load", "dill.loads", "joblib.load"}
        if name == "yaml.load":
            loader = next((kw.value for kw in node.keywords if kw.arg == "Loader"), node.args[1] if len(node.args) > 1 else None)
            unsafe_loader = self._name(loader) in {"yaml.Loader", "yaml.UnsafeLoader", "yaml.CLoader", "yaml.CUnsafeLoader"}
        if name == "torch.load":
            unsafe_loader = any(kw.arg == "weights_only" and isinstance(kw.value, ast.Constant) and kw.value.value is False for kw in node.keywords)
        if unsafe_loader and source and source[0] == "input":
            self._add(node, "PY-AI-MODEL-001", "External input reaches unsafe deserialization", Severity.HIGH,
                      Category.INSECURE_MODEL_DEPLOYMENT, f"External input from line {source[1]} reaches an unsafe object loader.",
                      "Use a data-only format or safe loader; never deserialize externally controlled objects.", "CWE-502", source_line=source[1], source_file=source[3] if len(source) > 3 else None)
        if name in {"asyncpg.Connection.fetch", "asyncpg.Connection.fetchrow", "asyncpg.Connection.execute", "sqlite3.Cursor.execute", "sqlite3.Cursor.executemany", "sqlite3.Cursor.executescript",
                    "sqlite3.Connection.execute", "sqlite3.Connection.executemany", "sqlite3.Connection.executescript"} and source and source[0] == "input":
            self._add(node, "PY-SAST-SQL-001", "External input is interpolated into a SQL statement", Severity.HIGH,
                      Category.SAST, f"External input from line {source[1]} reaches the statement argument of a resolved database execution call.",
                      "Use SQL placeholders and pass values separately. Allowlist dynamic identifiers rather than interpolating input.",
                      "CWE-89", source_line=source[1], source_file=source[3] if len(source) > 3 else None)
        path_values = node.args[:1] + [kw.value for kw in node.keywords if kw.arg in {"file", "filename", "path", "path_or_file", "name"}]
        path_source = self._combine(self._source(value) for value in path_values)
        path_sink = builtin == "open" or name in {"builtins.open", "io.open", "flask.send_file", "quart.send_file", "PIL.Image.open", "tarfile.open", "zipfile.ZipFile"}
        if name in {"pathlib.Path.open", "pathlib.Path.read_text", "pathlib.Path.read_bytes", "pathlib.Path.write_text", "pathlib.Path.write_bytes"} and isinstance(node.func, ast.Attribute):
            path_sink, path_source = True, self._source(node.func.value)
        if path_sink and path_source and path_source[0] == "input" and not self._safe_for(path_source, "path") and not self._safe_for(path_source, "local-input"):
            self._add(node, "PY-SAST-PATH-001", "External input controls a filesystem path", Severity.HIGH,
                      Category.SAST, f"External input from line {path_source[1]} reaches a file operation without an observed path boundary.",
                      "Resolve the candidate and trusted root, reject paths outside that root using path-component containment, and avoid following untrusted symlinks.", "CWE-22", source_line=path_source[1], source_file=path_source[3] if len(path_source) > 3 else None)
        url_values = node.args[:1] + [kw.value for kw in node.keywords if kw.arg == "url"]
        url_source = self._combine(self._source(value) for value in url_values)
        if name in {f"{library}.{method}" for library in ("requests", "httpx") for method in ("get", "post", "put", "patch", "delete", "head", "options")} | {"urllib.request.urlopen"} and url_source and url_source[0] == "input":
            self._add(node, "PY-SAST-SSRF-001", "External input controls an outbound request URL", Severity.HIGH, Category.SAST,
                      f"External input from line {url_source[1]} controls the destination URL of a resolved HTTP request.",
                      "Use a fixed destination allowlist, validate resolved IPs and redirects, and block internal or link-local addresses.", "CWE-918", source_line=url_source[1], source_file=url_source[3] if len(url_source) > 3 else None)
        if name in {"django.http.HttpResponse", "starlette.responses.HTMLResponse", "fastapi.responses.HTMLResponse", "sanic.response.html", "pyramid.response.Response", "aiohttp.web.Response", "flask.Response"}:
            content = node.args[:1] + [kw.value for kw in node.keywords if kw.arg == "content"]
            html_source = next((self._source(value) for value in content if self._source(value)), None)
            media = next((kw.value for kw in node.keywords if kw.arg in {"content_type", "media_type"}), None)
            # shortcut: custom response headers/types are not resolved; add coverage with framework-specific tests.
            html_response = media is None or (isinstance(media, ast.Constant) and isinstance(media.value, str)
                                             and media.value.split(";", 1)[0].strip().lower() == "text/html")
            if (html_source and html_source[0] == "input" and not self._safe_for(html_source, "html") and html_response and len(node.args) <= 1
                    and not any(kw.arg in {"headers", None} for kw in node.keywords)):
                self._add(node, "PY-SAST-XSS-001", "External input reaches an HTML response", Severity.HIGH,
                          Category.SAST, f"External input from line {html_source[1]} reaches an explicit HTML response without recognised escaping.",
                          "Use an autoescaping template or context-appropriate escaping. Prefer a plain-text or JSON response for non-HTML data.",
                          "CWE-79", source_line=html_source[1], source_file=html_source[3] if len(html_source) > 3 else None)
        if self.include_experimental and self._is_llm_call(node):
            if any(self._source(value) and self._source(value)[0] == "input" for value in node.args + [kw.value for kw in node.keywords]):
                self._add(node, "PY-AI-PROMPT-001", "External input reaches an LLM (review only)", Severity.MEDIUM,
                          Category.PROMPT_INJECTION, "This is a trust-boundary review candidate, not proof of prompt injection.",
                          "Review privileged instructions and downstream tool controls.", "CWE-74", experimental=True)
        if name in self.functions:
            self._invoke(node, name)
        self.generic_visit(node)

    def _add(self, node, rule_id, title, severity, category, description, recommendation, cwe, experimental=False, source_line=None, source_file=None):
        from scanner.utils.helpers import redact_secrets
        lines = self.content.splitlines()
        indices = set(range(node.lineno - 1, min(len(lines), node.end_lineno)))
        if source_line and (source_file is None or source_file == self.file_path) and source_line <= len(lines):
            indices.add(source_line - 1)
        snippet = redact_secrets("\n".join(f"{i + 1}: {lines[i]}" for i in sorted(indices)))
        self.findings.append(Finding(title=title, severity=severity, category=category, module=self.module,
            description=description, file_path=self.file_path, line_number=node.lineno,
            code_snippet=snippet, recommendation=recommendation, cwe=cwe,
            confidence="medium" if experimental else "high", rule_id=rule_id,
            maturity="experimental" if experimental else "stable", evidence_kind="static-flow",
            trace=([{"role": "source", "file_path": source_file or self.file_path, "line_number": source_line}] if source_line else [])
                  + [{"role": "sink", "file_path": self.file_path, "line_number": node.lineno}]))


def analyze_python(file_path, content, module="ai", include_experimental=False, project=None):
    return PythonAIAnalyzer(file_path, content, module, include_experimental, project).run()
