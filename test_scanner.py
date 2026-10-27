from app.scanner import static_scan


def test_eval_detected():
    findings = static_scan('x = eval(user_input)', 'python')
    assert any(f['title'] == 'Python dynamic execution' and f['line'] == 1 for f in findings)


def test_safe_code():
    assert static_scan('print("Hello world")', 'python') == []


def test_language_specific_rule():
    assert static_scan('eval(x)', 'sql') == []


def test_inner_html():
    assert any(f['title'] == 'JavaScript innerHTML' for f in static_scan('node.innerHTML = untrusted;', 'javascript'))
