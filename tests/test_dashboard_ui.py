from pathlib import Path


DASHBOARD_PUBLIC_PATH = Path(__file__).resolve().parents[1] / "dashboard/public"


def test_all_dashboard_html_pages_use_shared_branding_and_tablet_viewport():
    pages = sorted(DASHBOARD_PUBLIC_PATH.glob("*.html"))

    assert pages
    for page in pages:
        html = page.read_text(encoding="utf-8")
        assert 'name="viewport" content="width=device-width, initial-scale=1"' in html
        assert 'href="/assets/qyleron_logo.png"' in html
        assert "Echidra" in html


def test_dashboard_uses_shared_stylesheet_and_banner_header():
    html = (DASHBOARD_PUBLIC_PATH / "index.html").read_text(encoding="utf-8")
    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")

    assert 'href="/dashboard.css"' in html
    assert 'src="/assets/Qyleron_Banner.png"' in html
    assert '<div class="product-name">Echidra OSS</div>' in html
    assert "@media (max-width: 768px)" in css


def test_dashboard_exposes_security_overview_without_filters():
    html = (DASHBOARD_PUBLIC_PATH / "index.html").read_text(encoding="utf-8")

    assert "Active Threats" in html
    assert "Low Risk Sessions" in html
    assert "Warnings" in html
    assert "Total Events" in html
    assert "Recent Security Events" in html
    assert "Apply Filters" not in html
    assert "Clear" not in html


def test_dashboard_map_and_events_are_backed_by_live_api_calls():
    html = (DASHBOARD_PUBLIC_PATH / "index.html").read_text(encoding="utf-8")

    assert 'id="attackOriginMap"' in html
    assert "L.map(\"attackOriginMap\"" in html
    assert "L.circle([run.latitude, run.longitude]" in html
    assert "L.circleMarker([run.latitude, run.longitude]" in html
    assert 'fetchJSON("/reports/summary")' in html
    assert 'fetchJSON("/classifier/runs?limit=10")' in html
    # The old static mock dataset must be gone.
    assert "attackOrigins" not in html
    assert "Moscow" not in html


def test_personas_page_uses_shared_styles_and_form_sections():
    html = (DASHBOARD_PUBLIC_PATH / "personas.html").read_text(encoding="utf-8")

    assert "<style>" not in html
    assert 'href="/dashboard.css"' in html
    assert 'href="/assets/qyleron_logo.png"' in html
    for section in ["Identity", "Services", "Deception", "Alerting"]:
        assert section in html
    for view in ["Configuration", "Analytics"]:
        assert view in html
    assert "buildPersonaRow" in html
    assert "persona-config-form" in html
    assert "toggle-switch" in html
    assert "analyticsPlaceholder" in html
    assert "initCustomSelects" in html
    assert "custom-select" in html


def test_sessions_page_uses_shared_styles_and_session_table_columns():
    html = (DASHBOARD_PUBLIC_PATH / "sessions.html").read_text(encoding="utf-8")

    assert "<style>" not in html
    assert 'href="/dashboard.css"' in html
    for heading in [
        "Time",
        "Source IP",
        "Country",
        "Persona",
        "Protocol",
        "Actor",
        "Risk",
        "Intent",
    ]:
        assert f">{heading}<" in html
    assert ">Report<" not in html
    assert "Export CSV" in html
    assert "data-session-row" in html
    assert "Analyst Recommendation" in html


def test_sessions_page_is_backed_by_live_api_calls():
    html = (DASHBOARD_PUBLIC_PATH / "sessions.html").read_text(encoding="utf-8")

    assert "/classifier/runs?from_ts=" in html
    assert "to_ts=" in html
    assert "fetchJSON(`/sessions/${sessionId}/events`)" in html
    # The old static mock dataset must be gone.
    assert "sess-1048" not in html
    assert "185.234.219.x" not in html


def test_sessions_page_server_side_filters_by_date_range_not_client_side():
    """A flat limit=500 fetch filtered client-side would silently drop
    older in-range sessions once the honeypot has more than 500 total --
    the range must be sent to the server, and truncation must be visible
    rather than presenting a capped result as if it were complete."""
    html = (DASHBOARD_PUBLIC_PATH / "sessions.html").read_text(encoding="utf-8")

    assert "async function loadSessions(from, to)" in html
    assert 'id="rangeTruncatedNotice"' in html
    assert "runs.length >= SESSIONS_FETCH_LIMIT" in html


def test_sessions_page_flags_partial_classifications():
    """A session classified mid-flight (real-time partial classification)
    must be visibly distinguishable from a fully closed one, both on screen
    and in the CSV export -- previously classification_status wasn't even
    persisted, so there was nothing to show here at all."""
    html = (DASHBOARD_PUBLIC_PATH / "sessions.html").read_text(encoding="utf-8")

    assert "run.classification_status" in html
    assert 'session.classificationStatus !== "complete"' in html
    assert ">Partial<" in html
    assert '"Status"' in html


def test_sessions_and_analytics_range_pickers_cannot_produce_an_inverted_range():
    for page in ("sessions.html", "analytics.html"):
        html = (DASHBOARD_PUBLIC_PATH / page).read_text(encoding="utf-8")

        assert "function syncRangeConstraints" in html, page
        # The calendar itself must be constrained (native min/max), not just
        # validated after the fact.
        assert "toDateInput.min = fromDateInput.value" in html, page
        assert "fromDateInput.max = toDateInput.value" in html, page
        # Hour dropdowns must be mutually constrained when the range is a
        # single day, not left free to produce an inverted same-day range.
        assert "HOUR_OPTIONS.filter(({ hour }) => hour <= upperBound)" in html, page
        assert "HOUR_OPTIONS.filter(({ hour }) => hour >= lowerBound)" in html, page
        assert 'addEventListener("change", syncRangeConstraints)' in html, page


def test_sessions_and_analytics_csv_export_neutralizes_formula_injection():
    """top_commands/session fields can contain raw attacker-typed honeypot
    input (e.g. a 'command' starting with =/+/-/@) -- exporting it verbatim
    would let it execute as a live formula when opened in a spreadsheet."""
    for page in ("sessions.html", "analytics.html"):
        html = (DASHBOARD_PUBLIC_PATH / page).read_text(encoding="utf-8")

        assert "function sanitizeCsvCell" in html, page
        assert "/^[=+\\-@\\t\\r]/.test(stringValue)" in html, page
        # downloadCsv must actually route every cell through the sanitizer,
        # not just define it unused.
        assert "sanitizeCsvCell(value).replaceAll" in html, page


def test_analytics_page_is_backed_by_live_api_calls():
    html = (DASHBOARD_PUBLIC_PATH / "analytics.html").read_text(encoding="utf-8")

    assert "fetchJSON(" in html
    assert "/analytics/summary?from_ts=" in html
    # Intent tiles must reflect the classifier's real Intent values, not
    # invented labels that can never actually be produced.
    assert 'id="intentDataAccess"' in html
    assert 'id="intentInteractiveOperation"' in html
    # The old synthetic data generator must be gone.
    assert "generateSyntheticEvents" not in html
    assert "mulberry32" not in html
    assert "Persistence Setup" not in html
    assert "Scanner Validation" not in html


def test_alerts_page_history_table_distinguishes_channel():
    """A persona routed to Slack (or both) must be visibly distinguishable
    from an email alert in the dispatch history, not just silently absent."""
    html = (DASHBOARD_PUBLIC_PATH / "alerts.html").read_text(encoding="utf-8")

    assert ">Channel<" in html
    assert '{slack: "Slack", both: "Slack + Email"}[ev.channel] || "Email"' in html
