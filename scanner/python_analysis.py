"""Conservative Python flow checks with bounded same-file calls; code is never executed."""

import ast
from scanner.models import Category, Finding, Severity


class PythonAIAnalyzer(ast.NodeVisitor):
    def __init__(self, file_path, content, module="ai", include_experimental=False):
        self.file_path, self.content = file_path, content
        self.module, self.include_experimental = module, include_experimental
        self.findings, self.bindings, self.taint = [], {}, {}
        self.functions, self.classes, self.active_calls = {}, set(), []
        self.class_name = ""
        self.class_bases = {}
        self.literal_sets = {}

    def run(self):
        try:
            tree = ast.parse(self.content, filename=self.file_path)
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.functions[node.name] = node
                    self.bindings[node.name] = node.name
                elif isinstance(node, ast.ClassDef):
                    self.classes.add(node.name)
                    self.bindings[node.name] = node.name
                    for method in node.body:
                        if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            self.functions[f"{node.name}.{method.name}"] = method
            self.visit(tree)
        except SyntaxError:
            self.findings.append(Finding(
                title="Python analysis skipped: syntax could not be parsed", severity=Severity.INFO,
                category=Category.SAST, module=self.module, description="Syntax-aware checks could not analyse this file.",
                file_path=self.file_path, recommendation="Check syntax and supported Python version, then scan again.",
                confidence="high", rule_id="PY-PARSE-001"))
        return self.findings

    def visit_Import(self, node):
        for alias in node.names:
            self.bindings[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self.bindings[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def _name(self, node):
        if isinstance(node, ast.Name):
            return self.bindings.get(node.id, "")
        if isinstance(node, ast.Attribute):
            root = self._name(node.value)
            return f"{root}.{node.attr}" if root else ""
        return ""

    def visit_FunctionDef(self, node):
        self._visit_function(node)

    def _visit_function(self, node, sources=None):
        self.bindings[node.name] = node.name if node.name in self.functions else ""
        old_bindings, old_taint, old_literals = self.bindings.copy(), self.taint, self.literal_sets
        self.literal_sets = old_literals.copy()
        self.taint = dict(sources or {})
        for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            self.literal_sets.pop(arg.arg, None)
            annotation = self._name(arg.annotation)
            self.bindings[arg.arg] = annotation if annotation in {"fastapi.Request", "starlette.requests.Request", "django.http.HttpRequest"} else ""
            if arg.arg == "self" and self.class_name:
                self.bindings[arg.arg] = self.class_name
            if ("django.views.View" in self.class_bases.get(self.class_name, set())
                    and node.name in {"get", "post", "put", "patch", "delete", "head", "options"}
                    and len(node.args.args) > 1 and arg is node.args.args[1]):
                self.bindings[arg.arg] = "django.http.HttpRequest"
            if isinstance(arg.annotation, ast.Name) and arg.annotation.id == "str":
                if any(isinstance(decorator, ast.Call) and self._name(decorator.func) in {
                    f"fastapi.FastAPI.{method}" for method in ("get", "post", "put", "delete", "patch", "api_route")
                } for decorator in node.decorator_list):
                    self.taint[arg.arg] = ("input", node.lineno)
        for arg in (node.args.vararg, node.args.kwarg):
            if arg:
                self.bindings[arg.arg] = ""
        for item in ast.walk(node):
            if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store):
                self.bindings[item.id] = ""
                self.literal_sets.pop(item.id, None)
        # Parameter names alone are not evidence of attacker control.
        self._visit_block(node.body)
        self.bindings, self.taint = old_bindings, old_taint
        self.literal_sets = old_literals

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.class_bases[node.name] = {self._name(base) for base in node.bases}
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
            owner = self._name(node.value)
            if ("http.server.BaseHTTPRequestHandler" in self.class_bases.get(owner, set())
                    and node.attr in {"path", "rfile", "headers"}):
                return ("input", node.lineno)
        if isinstance(node, ast.Call):
            name = self._name(node.func)
            if name == "socket.socket.recv":
                return ("input", node.lineno)
            if (isinstance(node.func, ast.Attribute)
                    and "tornado.web.RequestHandler" in self.class_bases.get(self._name(node.func.value), set())
                    and node.func.attr in {"get_argument", "get_query_argument", "get_body_argument"}):
                return ("input", node.lineno)
            if isinstance(node.func, ast.Name) and node.func.id == "input" and "input" not in self.bindings:
                return ("input", node.lineno)
            if name in {f"{root}.{method}" for root in ("flask.request", "bottle.request", "quart.request", "fastapi.Request", "starlette.requests.Request", "django.http.HttpRequest")
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
        if resolved in {f"{root}.{attribute}" for root in ("flask.request", "bottle.request", "quart.request", "fastapi.Request", "starlette.requests.Request", "django.http.HttpRequest")
                               for attribute in ("args", "form", "forms", "query", "query_params", "json", "data", "headers", "cookies", "files", "GET", "POST", "body", "COOKIES", "FILES")}:
            return ("input", node.lineno)
        if isinstance(node, ast.Name):
            return self.taint.get(node.id)
        if isinstance(node, ast.Subscript):
            return self._source(node.value)
        if isinstance(node, ast.Attribute):
            source = self._source(node.value)
            if source and source[0] == "model-response" and node.attr in {"content", "output_text", "text"}:
                return ("model", source[1])
            return source
        # shortcut: propagate transparent expressions only, expand with framework-specific tests.
        if isinstance(node, (ast.Attribute, ast.Subscript, ast.BinOp, ast.BoolOp, ast.JoinedStr, ast.FormattedValue,
                             ast.List, ast.Tuple, ast.Dict, ast.Await)):
            for child in ast.iter_child_nodes(node):
                source = self._source(child)
                if source:
                    return source
        return None

    def _assign(self, target, value):
        if not isinstance(target, ast.Name):
            return
        if isinstance(value, (ast.Set, ast.List, ast.Tuple)) and all(isinstance(item, ast.Constant) and isinstance(item.value, str) for item in value.elts):
            self.literal_sets[target.id] = value
        else:
            self.literal_sets.pop(target.id, None)
        source = self._source(value) if value is not None else None
        if source:
            self.taint[target.id] = source
        else:
            self.taint.pop(target.id, None)
        name = self._name(value)
        if isinstance(value, ast.Call):
            constructor = self._name(value.func)
            if constructor in {"openai.OpenAI", "openai.AsyncOpenAI", "anthropic.Anthropic", "anthropic.AsyncAnthropic"}:
                name = constructor
            if constructor in self.classes or constructor in {"fastapi.FastAPI", "socket.socket"}:
                name = constructor
            name = {"sqlite3.connect": "sqlite3.Connection", "sqlite3.Connection.cursor": "sqlite3.Cursor"}.get(constructor, name)
            factory = self.functions.get(constructor)
            if factory and len(factory.body) == 1 and isinstance(factory.body[0], ast.Return):
                returned = factory.body[0].value
                if isinstance(returned, ast.Call) and self._name(returned.func) == "sqlite3.connect":
                    name = "sqlite3.Connection"
        self.bindings[target.id] = name

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
                if key not in self.taint or self.taint[key][0] == "model-response":
                    self.taint[key] = value
        self.literal_sets = {key: value for key, value in states[0][2].items()
                             if all(key in state[2] and ast.dump(state[2][key]) == ast.dump(value)
                                    for state in states)}

    @staticmethod
    def _terminates(statement):
        if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
            return True
        if isinstance(statement, ast.If):
            return bool(statement.body and statement.orelse
                        and PythonAIAnalyzer._terminates(statement.body[-1])
                        and PythonAIAnalyzer._terminates(statement.orelse[-1]))
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
        states = []
        if allowed and isinstance(node.test.ops[0], ast.In):
            self.taint.pop(allowed, None)
        if self._visit_block(node.body):
            states.append(self._state())
        self._restore(initial)
        if allowed and isinstance(node.test.ops[0], ast.NotIn):
            self.taint.pop(allowed, None)
        if self._visit_block(node.orelse):
            states.append(self._state())
        self._merge_states(states)

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
        if source and source[0] != "model-response" and (code_sink or shell_sink):
            model = source[0] == "model"
            self._add(node, "PY-AI-EXEC-001" if model else "PY-SAST-EXEC-001",
                      "LLM output reaches code execution" if model else "External input reaches command/code execution",
                      Severity.CRITICAL, Category.SAST,
                      f"{'Model output' if model else 'External input'} from line {source[1]} reaches this execution sink without a recognised boundary.",
                      "Do not execute untrusted text. Use a fixed operation allowlist and structured arguments.", "CWE-94" if code_sink else "CWE-78", source_line=source[1])
        unsafe_loader = name in {"pickle.load", "pickle.loads", "dill.load", "dill.loads", "joblib.load"}
        if name == "yaml.load":
            loader = next((kw.value for kw in node.keywords if kw.arg == "Loader"), node.args[1] if len(node.args) > 1 else None)
            unsafe_loader = self._name(loader) in {"yaml.Loader", "yaml.UnsafeLoader", "yaml.CLoader", "yaml.CUnsafeLoader"}
        if name == "torch.load":
            unsafe_loader = any(kw.arg == "weights_only" and isinstance(kw.value, ast.Constant) and kw.value.value is False for kw in node.keywords)
        if unsafe_loader and source and source[0] == "input":
            self._add(node, "PY-AI-MODEL-001", "External input reaches unsafe deserialization", Severity.HIGH,
                      Category.INSECURE_MODEL_DEPLOYMENT, f"External input from line {source[1]} reaches an unsafe object loader.",
                      "Use a data-only format or safe loader; never deserialize externally controlled objects.", "CWE-502", source_line=source[1])
        if name in {"sqlite3.Cursor.execute", "sqlite3.Cursor.executemany", "sqlite3.Cursor.executescript",
                    "sqlite3.Connection.execute", "sqlite3.Connection.executemany", "sqlite3.Connection.executescript"} and source and source[0] == "input":
            self._add(node, "PY-SAST-SQL-001", "External input is interpolated into a SQL statement", Severity.HIGH,
                      Category.SAST, f"External input from line {source[1]} reaches the SQL statement of a resolved SQLite execution call.",
                      "Use SQL placeholders and pass values separately. Allowlist dynamic identifiers rather than interpolating input.",
                      "CWE-89", source_line=source[1])
        if name in {"django.http.HttpResponse", "starlette.responses.HTMLResponse", "fastapi.responses.HTMLResponse"}:
            content = node.args[:1] + [kw.value for kw in node.keywords if kw.arg == "content"]
            html_source = next((self._source(value) for value in content if self._source(value)), None)
            media = next((kw.value for kw in node.keywords if kw.arg in {"content_type", "media_type"}), None)
            # shortcut: custom response headers/types are not resolved; add coverage with framework-specific tests.
            html_response = media is None or (isinstance(media, ast.Constant) and isinstance(media.value, str)
                                             and media.value.split(";", 1)[0].strip().lower() == "text/html")
            if (html_source and html_source[0] == "input" and html_response and len(node.args) <= 1
                    and not any(kw.arg in {"headers", None} for kw in node.keywords)):
                self._add(node, "PY-SAST-XSS-001", "External input reaches an HTML response", Severity.HIGH,
                          Category.SAST, f"External input from line {html_source[1]} reaches an explicit HTML response without recognised escaping.",
                          "Use an autoescaping template or context-appropriate escaping. Prefer a plain-text or JSON response for non-HTML data.",
                          "CWE-79", source_line=html_source[1])
        if self.include_experimental and self._is_llm_call(node):
            if any(self._source(value) and self._source(value)[0] == "input" for value in node.args + [kw.value for kw in node.keywords]):
                self._add(node, "PY-AI-PROMPT-001", "External input reaches an LLM (review only)", Severity.MEDIUM,
                          Category.PROMPT_INJECTION, "This is a trust-boundary review candidate, not proof of prompt injection.",
                          "Review privileged instructions and downstream tool controls.", "CWE-74", experimental=True)
        # shortcut: direct same-file calls only, depth three; dynamic dispatch and tainted helper returns remain unsupported.
        if name in self.functions and name not in self.active_calls and len(self.active_calls) < 3:
            function = self.functions[name]
            parameters = function.args.posonlyargs + function.args.args
            if "." in name and parameters and parameters[0].arg in {"self", "cls"}:
                parameters = parameters[1:]
            supplied = [parameter.arg for parameter in parameters[:len(node.args)]] + [kw.arg for kw in node.keywords]
            required = {parameter.arg for parameter in parameters[:len(parameters) - len(function.args.defaults)]}
            required.update(parameter.arg for parameter, default in zip(function.args.kwonlyargs, function.args.kw_defaults) if default is None)
            valid_names = {parameter.arg for parameter in parameters + function.args.kwonlyargs}
            if (function.args.vararg or function.args.kwarg or len(node.args) > len(parameters)
                    or any(isinstance(value, ast.Starred) for value in node.args)
                    or any(kw.arg is None or kw.arg not in valid_names for kw in node.keywords)
                    or any(kw.arg in {parameter.arg for parameter in function.args.posonlyargs} for kw in node.keywords)
                    or len(set(supplied)) != len(supplied) or not required.issubset(supplied)):
                self.generic_visit(node)
                return
            sources = {parameter.arg: self._source(value) for parameter, value in zip(parameters, node.args)
                       if not isinstance(value, ast.Starred) and self._source(value)}
            sources.update({kw.arg: self._source(kw.value) for kw in node.keywords if kw.arg and self._source(kw.value)})
            if sources:
                old_class = self.class_name
                self.class_name = name.rsplit(".", 1)[0] if "." in name else ""
                self.active_calls.append(name)
                self._visit_function(function, sources)
                self.active_calls.pop()
                self.class_name = old_class
        self.generic_visit(node)

    def _add(self, node, rule_id, title, severity, category, description, recommendation, cwe, experimental=False, source_line=None):
        from scanner.utils.helpers import redact_secrets
        lines = self.content.splitlines()
        indices = set(range(node.lineno - 1, min(len(lines), node.end_lineno)))
        if source_line:
            indices.add(source_line - 1)
        snippet = redact_secrets("\n".join(f"{i + 1}: {lines[i]}" for i in sorted(indices)))
        self.findings.append(Finding(title=title, severity=severity, category=category, module=self.module,
            description=description, file_path=self.file_path, line_number=node.lineno,
            code_snippet=snippet, recommendation=recommendation, cwe=cwe,
            confidence="medium" if experimental else "high", rule_id=rule_id,
            maturity="experimental" if experimental else "stable"))


def analyze_python(file_path, content, module="ai", include_experimental=False):
    return PythonAIAnalyzer(file_path, content, module, include_experimental).run()
