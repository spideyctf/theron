import pytest
from tests.test_security_obligations import findings
from tests.test_html_ordering import BASE as HTML
from tests.test_tls_state import CODE as TLS
from tests.test_mcp_validation import BASE as MCP
from tests.test_ast_capability import CODE as AI


@pytest.mark.parametrize('flag,code,prefix',[
 ('html_obligations',HTML.format(body=' return unicodedata.normalize("NFKC",text)'),'PY-OBL-HTML-ORDER'),
 ('tls_obligations',TLS,'PY-OBL-TLS-POOL'),
 ('message_obligations',MCP.format(body='   value=self.model.model_validate(message.data)'),'PY-OBL-MCP-VALIDATION'),
 ('sandbox_obligations',AI,'PY-OBL-AI-CAPABILITY'),
])
def test_each_new_condition_has_an_isolated_ablation(flag,code,prefix):
    assert any(f.rule_id.startswith(prefix) for f in findings(code))
    assert not any(f.rule_id.startswith(prefix) for f in findings(code,disabled_features={flag}))
