"""Coverage gate work: safety_report.py sat at 42% coverage because only
the all-pass path of generate_safety_report() was exercised, and
report_to_markdown() was never called at all. These tests cover the
FAIL branches (each level can independently fail) and the markdown
renderer, which is real behavior the deploy-safety gate depends on.
"""
from stage2_sdk_ai.safety_report import generate_safety_report, report_to_markdown


def test_generate_safety_report_all_fail_is_needs_fix():
    inj = {"pass_rate": 0.0}
    pii = {"pass_rate": 0.0}
    cost = {"pass": False}
    appr = {"pass_rate": 0.0}
    report = generate_safety_report(inj, pii, cost, appr, tests_passed=0)
    assert report["overall"] == "NEEDS_FIX"
    assert report["recommendation"].startswith("Do not deploy")
    assert report["levels"]["L2_input_output"] == "FAIL"
    assert report["levels"]["L3_auth_ratelimit_cost"] == "FAIL"
    assert report["levels"]["L4_human_approval"] == "FAIL"
    assert report["levels"]["L5_redteam"] == "FAIL"
    # L1 is always PASS -- there is no readonly check to fail.
    assert report["levels"]["L1_readonly"] == "PASS"
    assert report["recommendation"].startswith("Do not deploy")


def test_generate_safety_report_mixed_pass_fail():
    """One level failing is enough to flip overall to NEEDS_FIX."""
    inj = {"pass_rate": 1.0}
    pii = {"pass_rate": 1.0}
    cost = {"pass": True}
    appr = {"pass_rate": 0.5}  # below the 0.8 threshold -> FAIL
    report = generate_safety_report(inj, pii, cost, appr, tests_passed=10)
    assert report["levels"]["L4_human_approval"] == "FAIL"
    assert report["levels"]["L2_input_output"] == "PASS"
    assert report["overall"] == "NEEDS_FIX"


def test_generate_safety_report_missing_keys_default_to_fail():
    """Empty eval dicts should fail closed (missing pass_rate -> 0)."""
    report = generate_safety_report({}, {}, {}, {}, tests_passed=0)
    assert report["overall"] == "NEEDS_FIX"
    assert report["levels"]["L5_redteam"] == "FAIL"


def test_generate_safety_report_custom_coverage_label():
    inj = {"pass_rate": 1.0}
    pii = {"pass_rate": 1.0}
    cost = {"pass": True}
    appr = {"pass_rate": 1.0}
    report = generate_safety_report(
        inj, pii, cost, appr, tests_passed=91, coverage="80%+ (verified)"
    )
    assert report["coverage_gate"] == "80%+ (verified)"
    assert report["overall"] == "SAFE_TO_DEPLOY"
    assert report["recommendation"] == "Deploy with L1-L5 active."


def test_report_to_markdown_renders_all_sections():
    inj = {"pass_rate": 1.0, "blocked": 10, "total": 10}
    pii = {"pass_rate": 1.0, "filtered": 5, "total": 5}
    cost = {"pass": True, "spike_blocked": True}
    appr = {"pass_rate": 1.0, "blocked": 3, "total": 3}
    report = generate_safety_report(inj, pii, cost, appr, tests_passed=91)
    md = report_to_markdown(report)
    assert "# Safety Report" in md
    assert "Overall: SAFE_TO_DEPLOY" in md
    assert "Tests: 91" in md
    assert "## Levels" in md
    assert "L1_readonly: PASS" in md
    assert "## Evals" in md
    assert "prompt_injection" in md


def test_report_to_markdown_handles_missing_fields_gracefully():
    """report_to_markdown must not crash on a partially-populated dict."""
    md = report_to_markdown({})
    assert "# Safety Report" in md
    assert "Overall: None" in md
