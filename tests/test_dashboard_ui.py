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
    assert 'fetchJSON("/classifier/runs?limit=8")' in html
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


def test_sessions_page_exports_classification_status_without_a_redundant_risk_badge():
    """classification_status is still captured and exported in the CSV
    Status column, but the Risk column no longer crams a second "Partial"
    badge next to the risk-level badge -- that read as an unexplained
    second label stacked under Risk, not a status column of its own."""
    html = (DASHBOARD_PUBLIC_PATH / "sessions.html").read_text(encoding="utf-8")

    assert "run.classification_status" in html
    assert 'session.classificationStatus === "complete" ? "Complete" : "Partial"' in html
    assert '"Status"' in html
    assert 'session.classificationStatus !== "complete"' not in html
    assert ">Partial<" not in html


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


def test_every_dashboard_page_confirms_logout_with_an_in_page_modal():
    """window.confirm() is a native dialog that some browser contexts (eg. a
    sandboxed iframe without allow-modals) suppress outright, so clicking
    Logout would silently do nothing -- an in-page modal always renders
    regardless of that, and every dashboard page must wire it the same way."""
    pages = [
        "index.html",
        "sessions.html",
        "analytics.html",
        "intelligence.html",
        "personas.html",
        "alerts.html",
    ]
    for page in pages:
        html = (DASHBOARD_PUBLIC_PATH / page).read_text(encoding="utf-8")

        assert "window.confirm" not in html, page
        assert 'id="logoutConfirmModal"' in html, page
        assert 'class="modal-backdrop"' in html, page
        assert 'id="logoutConfirmBtn"' in html, page
        assert 'id="logoutCancelBtn"' in html, page
        assert '"click", openLogoutConfirm' in html, page
        assert '"click", performLogout' in html, page
        # Clicking the backdrop itself, and pressing Escape, must also close
        # the modal -- not just the explicit Cancel/close button.
        assert "event.target === logoutConfirmModal" in html, page
        assert 'event.key === "Escape"' in html, page


def test_every_password_field_has_a_show_hide_toggle():
    """Every password input across the dashboard (login, signup, confirm,
    SMTP) must let the user reveal what they typed before submitting --
    a password field with no way to check for typos is a common source of
    lockouts and misconfigured SMTP credentials."""
    fields_by_page = {
        "auth.html": ["loginPassword", "signupPassword", "confirmPassword"],
        "alerts.html": ["smtpPassword"],
    }
    for page, field_ids in fields_by_page.items():
        html = (DASHBOARD_PUBLIC_PATH / page).read_text(encoding="utf-8")

        assert "password-field-wrapper" in html, page
        assert "initPasswordToggle" in html, page
        for field_id in field_ids:
            assert f'id="{field_id}"' in html, (page, field_id)
            assert f'id="{field_id}Toggle"' in html, (page, field_id)
            assert f'initPasswordToggle("{field_id}", "{field_id}Toggle")' in html, (
                page,
                field_id,
            )


def test_no_dashboard_page_shows_a_full_page_loader():
    """A full-viewport loading overlay hides the header/nav along with the
    content -- every page's loading state must live inside its own table or
    list container instead, never block the whole page."""
    pages = [
        "index.html",
        "sessions.html",
        "analytics.html",
        "intelligence.html",
        "personas.html",
        "alerts.html",
    ]
    for page in pages:
        html = (DASHBOARD_PUBLIC_PATH / page).read_text(encoding="utf-8")
        assert 'id="pageLoader"' not in html, page
        assert "hidePageLoader" not in html, page

    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")
    assert "position: fixed;\n  inset: 0;\n  z-index: 4000;" not in css


def test_high_volume_tables_show_a_loader_inside_their_own_container():
    """Only pages whose table can hold a lot of rows -- sessions (up to 500)
    and the alert history (up to 200) -- show a loading row; a colspan-wide
    spinner row so it disappears the instant real rows replace it, not on a
    separate timer. Small, fast lookups (a handful of personas, aggregated
    issues, the 8 most recent events) don't need one."""
    table_pages = {
        "sessions.html": 'tableBody.innerHTML = \'<tr><td colspan="8" class="table-loader-cell"><div class="spinner"></div></td></tr>\';',
        "alerts.html": 'tbody.innerHTML = \'<tr><td colspan="7" class="table-loader-cell"><div class="spinner" role="status" aria-label="Loading alert history"></div></td></tr>\';',
    }
    for page, loader_line in table_pages.items():
        html = (DASHBOARD_PUBLIC_PATH / page).read_text(encoding="utf-8")
        assert loader_line in html, page

    for page in ["personas.html", "intelligence.html", "index.html"]:
        html = (DASHBOARD_PUBLIC_PATH / page).read_text(encoding="utf-8")
        assert "table-loader-cell" not in html, page

    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")
    assert ".table-loader-cell {" in css


def test_modal_backdrop_blurs_content_behind_it():
    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")

    assert "backdrop-filter: blur(6px);" in css


def test_every_dashboard_page_styles_the_logout_modal_close_button_as_danger():
    pages = [
        "index.html",
        "sessions.html",
        "analytics.html",
        "intelligence.html",
        "personas.html",
        "alerts.html",
    ]
    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")
    assert ".modal-close-danger {" in css

    for page in pages:
        html = (DASHBOARD_PUBLIC_PATH / page).read_text(encoding="utf-8")
        assert 'class="modal-close modal-close-danger" id="logoutConfirmCloseBtn"' in html, page


def test_failed_logout_restores_focus_to_the_logout_button():
    """logoutButton.disabled = true (set before the fetch) drops keyboard
    focus even though closeLogoutConfirm() had just set it there -- on a
    failed logout the button is re-enabled but focus was never restored,
    stranding a keyboard user's focus nowhere after the alert() closes."""
    pages = [
        "index.html",
        "sessions.html",
        "analytics.html",
        "intelligence.html",
        "personas.html",
        "alerts.html",
    ]
    for page in pages:
        html = (DASHBOARD_PUBLIC_PATH / page).read_text(encoding="utf-8")
        assert "logoutButton.disabled = false;\n        logoutButton.focus();" in html, page


def test_cross_buttons_have_no_fill_behind_the_x():
    """Every close (x) button -- the default modal-close and the danger
    logout variant -- shows only a border and the x mark, no solid fill
    behind it."""
    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")

    assert "background: transparent;\n  color: var(--muted);" in css
    assert "border-color: #e5484d;\n  background: transparent;\n  color: #e5484d;" in css


def test_standard_buttons_use_the_dark_scheme_with_a_raised_shadow():
    """text-button/iconless-button/logout-button use the original dark
    surface color scheme (not the white-bg/black-text variant), lifted off
    the page with a shadow so they read as raised/tactile."""
    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")

    assert "color: var(--text);\n  background: var(--surface-hover);\n  cursor: pointer;" in css
    assert "box-shadow: 0 2px 4px rgba(0, 0, 0, 0.45)" in css
    assert ".text-button:active {" in css


def test_sessions_table_has_pagination_controls():
    html = (DASHBOARD_PUBLIC_PATH / "sessions.html").read_text(encoding="utf-8")

    assert 'id="sessionsPagination" class="table-pagination"' in html
    assert "function renderPagination(totalPages)" in html
    assert "SESSIONS_PAGE_SIZE = 25" in html

    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")
    assert ".table-pagination {" in css
    assert "justify-content: flex-end;" in css


def test_pagination_render_restores_focus_after_destroying_the_clicked_button():
    """renderPagination() replaces its own innerHTML on every Prev/Next
    click, destroying the button that had focus -- without restoring it
    somewhere, a keyboard user's focus is lost to <body>. Only do this when
    focus was actually inside the pagination area (a Prev/Next click), not
    on an unrelated re-render like the initial load or a new date range."""
    html = (DASHBOARD_PUBLIC_PATH / "sessions.html").read_text(encoding="utf-8")

    assert "const hadFocusInside = paginationContainer.contains(document.activeElement);" in html
    assert 'id="sessionsPaginationStatus" tabindex="-1"' in html
    assert (
        "if (hadFocusInside) {\n"
        '        document.getElementById("sessionsPaginationStatus").focus();\n'
        "      }"
    ) in html


def test_disabled_pagination_button_does_not_pick_up_hover_styling():
    """:disabled doesn't stop :hover from matching in CSS -- without an
    explicit reset, mousing over a disabled Prev/Next button still shows
    the enabled-button hover border/background, a false affordance for a
    button that does nothing when clicked."""
    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")

    assert (
        ".table-pagination .text-button:disabled:hover,\n"
        ".table-pagination .text-button:disabled:focus-visible {\n"
        "  border-color: var(--line);\n"
        "  background: var(--surface-hover);\n"
        "}"
    ) in css

    # The persona-config modal's own close button must be unaffected --
    # only the logout modal gets the danger treatment.
    personas_html = (DASHBOARD_PUBLIC_PATH / "personas.html").read_text(encoding="utf-8")
    assert 'class="modal-close" id="modalCloseBtn"' in personas_html


def test_sessions_table_persona_column_shows_only_the_friendly_name():
    """The Persona column previously also showed the raw session_id
    underneath the friendly name -- just the name now, keeping the cell
    focused on what it's labeled as. session.sessionId itself is still used
    elsewhere (expanding a row's detail view fetches /sessions/{id}/events),
    so only the removed table-cell markup is asserted gone, not the field."""
    html = (DASHBOARD_PUBLIC_PATH / "sessions.html").read_text(encoding="utf-8")

    assert "<strong>${escHtml(session.persona)}</strong>" in html
    assert "<span>Session ${escHtml(session.sessionId)}</span>" not in html
    assert "loadSessionEvents(session.sessionId)" in html
