"""Drift detection, including the POSITIVE CONTROLS.

House experimental law #2: a gate must be demonstrably able to FAIL. Several
tests here feed the evaluator a synthetic mismatch and require a finding; the
paired tests feed it matching state and require silence. Without both halves,
a check that returns [] for everything would pass a "no findings on a healthy
machine" test forever.
"""

from __future__ import annotations

from spiral_guardian.evaluate import (
    compare_binary,
    evaluate_drift,
    evaluate_port_exposure,
    extract_declared_endpoints,
)


# === positive control: the gate CAN fire ==================================


def test_bind_mismatch_is_detected(plist_item, port_entry):
    """POSITIVE CONTROL: declared localhost + actual wildcard MUST be caught.

    This is the shape of the live com.ollama.server case on the Mac Studio.
    """
    item = plist_item(
        label="com.ollama.server",
        environment_variables={"OLLAMA_HOST": "127.0.0.1:11434"},
    )
    ports = [port_entry(11434, "wildcard", ["*:11434"], "ollama")]

    findings = evaluate_drift([item], ports, {})

    mismatches = [f for f in findings if f["class"] == "bind_mismatch"]
    assert len(mismatches) == 1, "the bind-mismatch gate failed to fire"
    assert mismatches[0]["severity"] == "high"
    assert mismatches[0]["declared_scope"] == "localhost"
    assert mismatches[0]["actual_scope"] == "wildcard"
    assert "11434" in mismatches[0]["detail"]


def test_bind_match_produces_no_finding(plist_item, port_entry):
    """NEGATIVE CONTROL: declared and actual agreeing must stay silent."""
    item = plist_item(environment_variables={"SERVICE_HOST": "127.0.0.1:8100"})
    ports = [port_entry(8100, "localhost", ["127.0.0.1:8100"])]

    findings = evaluate_drift([item], ports, {})

    assert [f for f in findings if f["class"] == "bind_mismatch"] == []


def test_declared_not_loaded_is_detected(plist_item, port_entry):
    """POSITIVE CONTROL: a plist configuring an unloaded service is drift."""
    item = plist_item(
        loaded=False,
        launchd_state=None,
        environment_variables={"OLLAMA_HOST": "127.0.0.1:11434"},
    )
    findings = evaluate_drift([item], [port_entry(11434, "localhost")], {})

    unloaded = [f for f in findings if f["class"] == "declared_not_loaded"]
    assert len(unloaded) == 1, "config-with-no-reader gate failed to fire"
    assert "not loaded" in unloaded[0]["detail"]


def test_loaded_service_is_not_reported_as_unloaded(plist_item, port_entry):
    item = plist_item(loaded=True, environment_variables={"SERVICE_HOST": "127.0.0.1:8100"})
    findings = evaluate_drift([item], [port_entry(8100, "localhost")], {})
    assert [f for f in findings if f["class"] == "declared_not_loaded"] == []


def test_missing_declared_binary_is_detected(plist_item):
    item = plist_item(declared_binary_exists=False, declared_binary="/nope/missing")
    findings = evaluate_drift([item], [], {})
    assert any(f["class"] == "declared_binary_missing" for f in findings)


def test_declared_port_with_no_listener_is_reported(plist_item):
    item = plist_item(environment_variables={"SERVICE_PORT": "9999"})
    findings = evaluate_drift([item], [], {})
    absent = [f for f in findings if f["class"] == "declared_port_absent"]
    assert len(absent) == 1
    assert absent[0]["declared_port"] == 9999


# === binary comparison: the false-positive traps ==========================


def test_symlinked_binary_is_not_a_mismatch():
    """/usr/local/bin/ollama -> /Applications/Ollama.app/... is NOT drift."""
    verdict, _ = compare_binary(
        "/usr/local/bin/ollama",
        "/Applications/Ollama.app/Contents/Resources/ollama",
        "/Applications/Ollama.app/Contents/Resources/ollama",
        "/Applications/Ollama.app/Contents/Resources/ollama serve",
    )
    assert verdict == "match"


def test_interpreter_running_declared_script_is_a_match():
    """A venv console script run by Python must not read as binary drift.

    Live case: com.templetwo.sovereign-sse declares venv/bin/sovereign-sse and
    runs as .../Python with the script as argv[1]. An earlier draft of this
    check reported it as HIGH-severity drift. It was fine.
    """
    verdict, _ = compare_binary(
        "/Users/x/sovereign-stack/venv/bin/sovereign-sse",
        "/Users/x/sovereign-stack/venv/bin/sovereign-sse",
        "/opt/homebrew/.../Python.app/Contents/MacOS/Python",
        "/opt/homebrew/.../Python.app/Contents/MacOS/Python /Users/x/sovereign-stack/venv/bin/sovereign-sse",
    )
    assert verdict == "match_via_argv"


def test_interpreter_without_declared_script_is_inconclusive_not_mismatch():
    verdict, explanation = compare_binary(
        "/Users/x/venv/bin/thing", "/Users/x/venv/bin/thing",
        "/opt/homebrew/bin/python3.12", "/opt/homebrew/bin/python3.12 -m something.else",
    )
    assert verdict == "inconclusive_interpreter"
    assert "cannot be resolved" in explanation


def test_genuine_binary_swap_is_a_mismatch():
    """POSITIVE CONTROL: a real binary substitution must still be caught."""
    verdict, _ = compare_binary(
        "/usr/local/bin/legit", "/usr/local/bin/legit", "/tmp/evil", "/tmp/evil --serve",
    )
    assert verdict == "mismatch"


def test_binary_mismatch_finding_is_emitted_for_a_real_swap(plist_item):
    item = plist_item(
        declared_binary="/usr/local/bin/legit", declared_binary_real="/usr/local/bin/legit",
    )
    processes = {999: {"pid": 999, "executable_real": "/tmp/evil", "args": "/tmp/evil --serve"}}
    findings = evaluate_drift([item], [], processes)
    assert any(f["class"] == "binary_mismatch" and f["severity"] == "high" for f in findings)


# === endpoint parsing ======================================================


def test_extract_endpoints_parses_host_and_port():
    endpoints = extract_declared_endpoints({"OLLAMA_HOST": "127.0.0.1:11434"})
    assert len(endpoints) == 1
    assert endpoints[0]["declared_host"] == "127.0.0.1"
    assert endpoints[0]["declared_port"] == 11434
    assert endpoints[0]["declared_scope"] == "localhost"


def test_extract_endpoints_parses_bare_port_and_wildcard_host():
    assert extract_declared_endpoints({"APP_PORT": "8080"})[0]["declared_port"] == 8080
    wildcard = extract_declared_endpoints({"BIND_ADDR": "0.0.0.0"})[0]
    assert wildcard["declared_scope"] == "wildcard"


def test_origins_are_not_treated_as_bind_addresses():
    """A CORS allowlist is not a bind address; treating it as one invents drift."""
    assert extract_declared_endpoints({"OLLAMA_ORIGINS": "http://127.0.0.1:*"}) == []


def test_unrelated_env_vars_are_ignored():
    assert extract_declared_endpoints({"PATH": "/usr/bin", "SOVEREIGN_ROOT": "/x"}) == []


# === port exposure =========================================================


def test_wildcard_bind_is_flagged_without_claiming_reachability(port_entry):
    findings = evaluate_port_exposure([port_entry(11434, "wildcard", ["*:11434"])])
    assert len(findings) == 1
    assert findings[0]["reachability_from_other_hosts"] == "not_tested"
    assert "not proof of network exposure" in findings[0]["caveat"]


def test_localhost_bind_is_not_flagged(port_entry):
    assert evaluate_port_exposure([port_entry(8100, "localhost")]) == []


def test_unowned_port_is_flagged_and_says_owner_unknown(port_entry):
    entry = port_entry(631, "wildcard", ["*:631"])
    entry["processes"] = []
    entry["owner_known"] = False
    findings = evaluate_port_exposure([entry])
    assert findings[0]["owner_known"] is False
    assert "not visible" in findings[0]["detail"]
