import fnmatch
import re
import tomllib
from pathlib import Path


DASHBOARD_PUBLIC_PATH = Path(__file__).resolve().parents[1] / "dashboard/public"


def test_every_dashboard_file_is_included_in_the_package():
    # pyproject.toml's package-data decides which files a pip install gets;
    # a file it misses works from a clone but is absent once installed.
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    patterns = tomllib.loads(pyproject.read_text(encoding="utf-8"))["tool"]["setuptools"][
        "package-data"
    ]["dashboard"]

    missing = [
        path.name
        for path in sorted(DASHBOARD_PUBLIC_PATH.iterdir())
        if path.is_file()
        and not any(fnmatch.fnmatch(f"public/{path.name}", pattern) for pattern in patterns)
    ]

    assert missing == []


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
    assert "L.map(container" in html
    assert "L.circle([lat, lon]" in html
    assert "L.circleMarker([lat, lon]" in html
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
    for section in ["Identity", "Deception", "Alerting"]:
        assert section in html
    for view in ["Configuration", "Analytics"]:
        assert view in html
    assert "buildPersonaRow" in html
    assert "persona-config-form" in html
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
    assert "Analyst Recommendation" not in html


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
    rather than presenting a capped result as if it were complete -- with a
    way to load the older sessions beyond the cap."""
    html = (DASHBOARD_PUBLIC_PATH / "sessions.html").read_text(encoding="utf-8")

    assert "async function loadSessions(from, to, { background = false } = {})" in html
    assert 'id="loadOlderBar"' in html
    assert "runs.length >= SESSIONS_FETCH_LIMIT" in html
    assert "&offset=${loadedRunCount}" in html


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


def test_analytics_blocklist_export_uses_the_applied_range():
    html = (DASHBOARD_PUBLIC_PATH / "analytics.html").read_text(encoding="utf-8")

    assert 'id="exportBlocklistButton"' in html
    assert "/analytics/blocklist?from_ts=" in html
    # The range the page is showing, not unapplied picker edits.
    assert "const { from, to } = currentRange;" in html
    assert "currentRange = { from, to };" in html
    assert "echidra-blocklist_${dateRangeSuffix()}.txt" in html
    assert "No public attacker IPs in this range" in html


def test_dashboard_pages_use_in_page_notices_not_browser_popups():
    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")
    assert ".dashboard-notice {" in css
    assert ".dashboard-notice.notice-error {" in css

    for page in (
        "index.html",
        "sessions.html",
        "analytics.html",
        "intelligence.html",
        "personas.html",
        "alerts.html",
    ):
        html = (DASHBOARD_PUBLIC_PATH / page).read_text(encoding="utf-8")
        assert "function showNotice(message, options)" in html, page
        assert 'notice.setAttribute("aria-live", "polite");' in html, page
        assert "alert(" not in html.replace("browser's alert()", ""), page


def test_forms_use_dashboard_validation_not_browser_bubbles():
    auth_html = (DASHBOARD_PUBLIC_PATH / "auth.html").read_text(encoding="utf-8")
    assert '<form id="loginForm" class="auth-form" novalidate>' in auth_html
    assert '<form id="signupForm" class="auth-form hidden" novalidate>' in auth_html

    personas_html = (DASHBOARD_PUBLIC_PATH / "personas.html").read_text(encoding="utf-8")
    assert personas_html.count('autocomplete="off" novalidate>') == 2
    assert 'statusEl.textContent = "Enter a display name.";' in personas_html


def test_auth_page_wording_and_server_messages_are_shown_cleanly():
    html = (DASHBOARD_PUBLIC_PATH / "auth.html").read_text(encoding="utf-8")

    # "Log In"/"Sign Up" are verbs; "Login"/"Signup" are nouns, not button labels.
    assert '<button type="submit" class="btn" id="loginButton">Log In</button>' in html
    assert '<button type="submit" class="btn" id="signupButton">Sign Up</button>' in html
    assert ">Login<" not in html and ">Signup<" not in html
    assert "Please " not in html
    # Pydantic's "Value error, " prefix never reaches the user.
    assert 'detail.replace(/^Value error, /, "")' in html


def test_login_returns_only_to_same_site_dashboard_pages():
    html = (DASHBOARD_PUBLIC_PATH / "auth.html").read_text(encoding="utf-8")

    assert "window.location.assign(safeNextPath())" in html
    assert 'window.location.assign("/dashboard")' not in html
    # Open-redirect guards: only /dashboard paths, no protocol-relative or
    # backslash tricks that browsers treat as another host.
    assert 'next.startsWith("/dashboard/")' in html
    assert 'next.includes("//")' in html
    assert 'next.includes("\\\\")' in html


def test_empty_states_tell_a_new_user_what_happens_next():
    index_html = (DASHBOARD_PUBLIC_PATH / "index.html").read_text(encoding="utf-8")
    assert "No attacker activity yet." in index_html
    assert "<code>echidra status</code>" in index_html

    sessions_html = (DASHBOARD_PUBLIC_PATH / "sessions.html").read_text(encoding="utf-8")
    assert "New sessions appear here as soon as someone connects to a decoy." in sessions_html

    intelligence_html = (DASHBOARD_PUBLIC_PATH / "intelligence.html").read_text(encoding="utf-8")
    assert "No findings yet. Attacker sessions are grouped into findings" in intelligence_html


def test_dashboard_css_replaces_native_scrollbars_spinners_and_autofill():
    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")
    assert "scrollbar-width: thin;" in css
    assert "*::-webkit-scrollbar-thumb {" in css
    assert 'input[type="number"]::-webkit-inner-spin-button' in css
    assert "input:-webkit-autofill" in css


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
    """Pages whose table can hold a lot of rows -- sessions (up to 500) and
    the alert history (up to 200) -- show a loading row unconditionally and
    immediately; a colspan-wide spinner row so it disappears the instant
    real rows replace it, not on a separate timer. personas.html and
    index.html don't fetch into a table at all, so they never show one."""
    table_pages = {
        "sessions.html": 'tableBody.innerHTML = \'<tr><td colspan="8" class="table-loader-cell"><div class="spinner" role="status" aria-label="Loading sessions"></div></td></tr>\';',
        "alerts.html": 'tbody.innerHTML = \'<tr><td colspan="7" class="table-loader-cell"><div class="spinner" role="status" aria-label="Loading alert history"></div></td></tr>\';',
    }
    for page, loader_line in table_pages.items():
        html = (DASHBOARD_PUBLIC_PATH / page).read_text(encoding="utf-8")
        assert loader_line in html, page

    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")
    assert ".table-loader-cell {" in css


def test_every_data_container_shows_a_spinner_on_first_paint():
    """After login or a page change, each table/panel shows a spinner in its
    own box until its first fetch replaces it, instead of sitting blank."""
    initial_loaders = {
        "sessions.html": '<tbody id="sessionsTableBody"><tr><td colspan="8" class="table-loader-cell">',
        "intelligence.html": '<tbody id="issueTableBody"><tr><td colspan="6" class="table-loader-cell">',
        "personas.html": '<tbody id="personaTableBody"><tr><td colspan="5" class="table-loader-cell">',
        "alerts.html": '<tbody id="alertEventsBody"><tr><td colspan="7" class="table-loader-cell">',
        "analytics.html": '<div id="analyticsLoading" class="panel-loader">',
    }
    for page, marker in initial_loaders.items():
        html = (DASHBOARD_PUBLIC_PATH / page).read_text(encoding="utf-8")
        assert marker in html, page

    index_html = (DASHBOARD_PUBLIC_PATH / "index.html").read_text(encoding="utf-8")
    assert '<div id="mapLoader" class="panel-loader map-loader">' in index_html
    assert 'aria-label="Loading recent events"' in index_html
    assert 'document.getElementById("mapLoader").hidden = true;' in index_html


def _setTimeout_delays(html: str, marker: str) -> list[int]:
    """Return the millisecond delay argument of every setTimeout(...) call
    whose preceding text contains marker -- so a test can assert the actual
    configured delay instead of just that a setTimeout(...) call exists
    somewhere (which would still pass if the delay were changed to 0, 30000,
    or anything else)."""
    delays = []
    for match in re.finditer(r"setTimeout\([^,]*,\s*(\d+)\s*\)", html):
        window_start = max(0, match.start() - 400)
        if marker in html[window_start:match.start()]:
            delays.append(int(match.group(1)))
    return delays


def test_slow_loads_get_a_delayed_loader_not_an_immediate_one():
    """Issue lookups (Intelligence), persona analytics, and the Analytics
    charts are all normally fast -- unlike Sessions/Alerts' immediate
    loader, these only show a spinner if that particular fetch is actually
    still running after 300ms, so a fast response never flashes one."""
    intelligence_html = (DASHBOARD_PUBLIC_PATH / "intelligence.html").read_text(encoding="utf-8")
    assert '<tr><td colspan="6" class="table-loader-cell"><div class="spinner" role="status" aria-label="Loading issues"></div></td></tr>' in intelligence_html
    # Background refresh ticks must never trigger the delayed loader --
    # rebuilding the table under an analyst mid-read is exactly what the
    # background guard right after this exists to prevent.
    assert "const loadingTimer = background ? null : setTimeout(" in intelligence_html
    assert _setTimeout_delays(intelligence_html, "loadingTimer") == [300]

    personas_html = (DASHBOARD_PUBLIC_PATH / "personas.html").read_text(encoding="utf-8")
    # Visible on first paint until the persona list and first analytics
    # arrive; later persona or range changes use the delay.
    assert '<div id="analyticsLoading" class="panel-loader">' in personas_html
    assert '<div id="analyticsPlaceholder" class="analytics-placeholder" hidden>' in personas_html
    assert _setTimeout_delays(personas_html, "loadingTimer") == [300]
    # Request-scoped, not just "does the dropdown still say this persona" --
    # re-selecting the same persona (or a quick back-and-forth landing on it
    # again) would otherwise let an older, slower fetch for that identical
    # persona overwrite a newer one's result.
    assert "var personaAnalyticsRequestId = 0;" in personas_html
    assert "if (requestId === personaAnalyticsRequestId) loading.hidden = false;" in personas_html
    assert "if (requestId !== personaAnalyticsRequestId) return;" in personas_html

    analytics_html = (DASHBOARD_PUBLIC_PATH / "analytics.html").read_text(encoding="utf-8")
    # Visible on first paint (first load); later range changes use the delay.
    assert 'id="analyticsLoading" class="panel-loader">' in analytics_html
    assert "const loadingTimer = background ? null : setTimeout(" in analytics_html
    assert _setTimeout_delays(analytics_html, "loadingTimer") == [300]
    assert "setInterval(() => applyRange({ background: true }), 30000);" in analytics_html
    # Same request-scoping as personas.html, so a superseded request (eg.
    # the background tick racing a user's Apply click) can't hide the
    # loader or render stale data over a newer, still-in-flight request.
    assert "let analyticsRequestId = 0;" in analytics_html
    assert "if (requestId === analyticsRequestId) loadingEl.hidden = false;" in analytics_html
    assert "if (requestId !== analyticsRequestId) return;" in analytics_html

    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")
    assert ".panel-loader {" in css
    assert ".panel-loader[hidden] {" in css


def test_modal_backdrop_dims_without_blur_so_modal_scrolling_stays_smooth():
    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")
    backdrop = css.split(".modal-backdrop {", 1)[1].split("}", 1)[0]

    assert "background: rgba(0, 0, 0, 0.82);" in backdrop
    assert "backdrop-filter:" not in backdrop.replace("No backdrop-filter", "")


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
    """text-button/logout-button use the original dark surface color scheme
    (not the white-bg/black-text variant), lifted off the page with a
    shadow so they read as raised/tactile."""
    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")

    assert "color: var(--text);\n  background: var(--surface-hover);\n  cursor: pointer;" in css
    assert "box-shadow: 0 2px 4px rgba(0, 0, 0, 0.45)" in css
    assert ".text-button:active {" in css

    # .logout-button is a separate, non-combined rule (not comma-joined with
    # .text-button) that happens to currently match it -- assert on it by
    # name too, or a future regression/divergence there would pass silently.
    assert ".logout-button {" in css
    assert "color: var(--text);\n  background: var(--surface-hover);\n  cursor: pointer;\n  font-size: 14px;\n  font-weight: 500;\n  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.45)" in css
    assert ".logout-button:active {" in css


def test_sessions_table_has_pagination_controls():
    html = (DASHBOARD_PUBLIC_PATH / "sessions.html").read_text(encoding="utf-8")

    assert 'id="sessionsPagination" class="table-pagination"' in html
    assert "function renderPagination(totalPages)" in html
    assert "SESSIONS_PAGE_SIZE = 10" in html

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

    # The date range button shares the reset: Persona analytics disables it
    # when there are no personas.
    assert (
        ".table-pagination .text-button:disabled:hover,\n"
        ".table-pagination .text-button:disabled:focus-visible,\n"
        ".time-range-control .text-button:disabled:hover,\n"
        ".time-range-control .text-button:disabled:focus-visible {\n"
        "  border-color: var(--line);\n"
        "  background: var(--surface-hover);\n"
        "}"
    ) in css

    # Every modal close button (logout, persona config) uses the same red
    # danger styling for visual consistency.
    personas_html = (DASHBOARD_PUBLIC_PATH / "personas.html").read_text(encoding="utf-8")
    assert 'class="modal-close modal-close-danger" id="modalCloseBtn"' in personas_html


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


def test_personas_page_reopens_the_last_persona_and_tab():
    """The sidebar link is plain /personas, so coming back from another page
    used to open Configuration on the first persona. The last persona and tab
    are kept in localStorage and used only when the URL names neither, and
    every storage call is guarded so a blocked store can't break the page."""
    html = (DASHBOARD_PUBLIC_PATH / "personas.html").read_text(encoding="utf-8")

    assert (
        'var restoreLastView = !new URLSearchParams(window.location.search).has("persona")'
        " && !window.location.hash;"
    ) in html
    assert "try { return window.localStorage.getItem(key); } catch (e) { return null; }" in html
    assert "saveLastView(LAST_TAB_KEY, tab);" in html
    assert "saveLastView(LAST_PERSONA_KEY, personaId);" in html

    # A persona the URL or last visit names loads alongside the persona list,
    # not after it, and isn't fetched a second time once the list arrives.
    assert "if (prefetchedPersona) loadPersonaAnalytics(prefetchedPersona);" in html
    assert "if (initial && initial === prefetchedPersona) {" in html
    assert html.index("prefetchedPersona = knownPersona;") < html.index(
        "var results = await Promise.all([fetchPresets(), fetchConfigs()]);"
    )
    assert '(restoreLastView && readLastView(LAST_TAB_KEY) === "analytics")' in html
    assert "|| (restoreLastView ? readLastView(LAST_PERSONA_KEY) : null);" in html

    # The tab is chosen in its own script ahead of the main one, so the page
    # never draws Configuration first and then switches. The dropdown code
    # loads in the head, so the persona dropdown is styled and shows the
    # known persona (not the raw "Select a persona…" select) from the start.
    assert html.index('<script src="/custom-select.js"></script>') < html.index("</head>")
    assert html.index("function showTab(tab)") < html.index("var noticeTimer = null;")
    assert (
        'document.getElementById("personaSelector").options[0].textContent = knownPersona || "Loading personas…";'
    ) in html
    assert html.index("initCustomSelects(analyticsView);") < html.index("var noticeTimer = null;")
    assert "sel.options[0].textContent = PERSONA_PLACEHOLDER_TEXT;" in html
    assert "prefetchedPersona = knownPersona;" in html
    # If the persona list fails, the first-load spinner gives way to a note.
    assert '"Couldn\'t load personas. Reload the page to try again."' in html


def test_persona_peak_hours_fits_its_card_without_a_scrollbar():
    """Peak Attack Hours used to sit in an always-scrolling box, which showed
    an empty scrollbar when nothing overflowed. With all 24 hours sent by the
    server it fits the card, labelled every 3rd hour."""
    html = (DASHBOARD_PUBLIC_PATH / "personas.html").read_text(encoding="utf-8")
    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")

    assert "scrollable" not in html
    assert "line-chart-scroll" not in css
    assert '<div class="bar-chart" id="hoursChart"' in html


def test_persona_peak_hours_is_a_full_width_bar_chart_like_analytics():
    """Peak Attack Hours matches Analytics' Attacks by Hour: bars on a scale,
    a stub for empty hours, the whole column as the hover target, every 3rd
    hour labelled. The two time charts span the row so 24 columns fit with
    their counts on top. Chart tooltips are 13px."""
    html = (DASHBOARD_PUBLIC_PATH / "personas.html").read_text(encoding="utf-8")
    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")

    assert 'renderBarChart("hoursChart", (data.peak_hours || []).map(function(d) {' in html
    assert 'tip: formatHourRange(d.hour) + ": " + formatSessionCount(d.count)' in html
    assert "}), 8);" in html
    assert "'<div class=\"stacked-bar is-empty\" style=\"height: 2px;\"></div>'" in html
    assert "return '<div class=\"bar-column\" data-tip=\"' + tip + '\" aria-label=\"' + tip + '\">'" in html
    assert html.count('<div class="chart-card chart-card-wide">') == 2
    assert ".persona-analytics-body .chart-card-wide {\n  grid-column: 1 / -1;\n}" in css

    assert "padding: 8px 11px;" in css
    assert "color: var(--text);\n  font-size: 13px;\n  line-height: 1.4;\n  pointer-events: none;" in css


def test_persona_sessions_trend_labels_the_first_and_last_day():
    """The trend axis labelled every Nth day from the first, so the range's
    last day (eg. today) often had no label. The bar chart always labels the
    last column and drops a regular label too close before it."""
    html = (DASHBOARD_PUBLIC_PATH / "personas.html").read_text(encoding="utf-8")

    assert "return i === lastIndex || (i % labelStep === 0 && (i === 0 || lastIndex - i >= labelStep / 2));" in html


def test_chart_hover_cursor_column_highlight_and_risk_tooltip():
    """Line-chart dots aren't clickable, so they keep the arrow cursor. A
    Risk Trend column is hovered as a whole, with a faint fill, and its
    tooltip lists each risk level with its colour, then the total."""
    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")
    html = (DASHBOARD_PUBLIC_PATH / "analytics.html").read_text(encoding="utf-8")

    # The line charts (and their dots) are gone: every time chart is bars.
    assert ".line-chart" not in css
    assert ".bar-column:hover {\n  background: rgba(255, 255, 255, 0.04);\n}" in css
    assert ".chart-tip-swatch {" in css
    assert ".chart-tip-total {" in css

    assert 'data-risk-high="${point.high}" data-risk-medium="${point.medium}" data-risk-low="${point.low}"' in html
    assert 'row("chart-tip-row chart-tip-total", "Total", total)' in html
    # Built with textContent, never innerHTML, so a label can't inject markup.
    assert "title.textContent = target.dataset.tipTitle;" in html


def test_analytics_charts_use_the_12_hour_clock_and_dates_with_the_year():
    """Attacks by Hour used 24-hour labels (00-23, "08:00 – 09:00") while the
    rest of the dashboard is 12-hour. It now uses the hour picker's labels,
    every 3rd hour on the axis, and says "1 session". Risk Trend tooltips
    give the year; the axis stays short."""
    html = (DASHBOARD_PUBLIC_PATH / "analytics.html").read_text(encoding="utf-8")

    assert "return `${HOUR_OPTIONS[hour].label} – ${HOUR_OPTIONS[(hour + 1) % 24].label}`;" in html
    assert ":00 – " not in html
    assert "label: HOUR_OPTIONS[Number(hour)].label," in html
    assert "tip: `${formatHourRange(hour)}: ${formatSessionCount(count)}`" in html
    assert 'return `${count} ${count === 1 ? "session" : "sessions"}`;' in html
    assert "${values[i]} sessions" not in html

    assert "tipLabel: formatTrendLabel(point.date, bucket, true)" in html
    assert '...(withYear ? { year: "numeric" } : {})' in html
    assert 'data-tip-title="${escHtml(point.tipLabel)}"' in html


def test_risk_trend_thins_column_labels_and_reads_clearly():
    """With up to 31 daily columns there isn't room for every date, so
    every Nth column is labelled, always the last, and unlabelled columns
    keep the space so bars stay level. Counts are white 13px and dates 12px
    in the lighter grey, on one line."""
    html = (DASHBOARD_PUBLIC_PATH / "analytics.html").read_text(encoding="utf-8")
    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")

    assert "const labelStep = Math.max(1, Math.ceil(points.length / maxLabels));" in html
    assert "}), 12);" in html  # Risk Trend: about 12 date labels
    assert '<span class="bar-label${showLabel(i) ? "" : " is-unlabelled"}">' in html

    assert ".bar-value {\n  display: block;\n  min-height: 18px;\n  color: var(--text);\n  text-align: center;\n  font-size: 13px;" in css
    assert ".bar-label {\n  justify-self: center;\n  white-space: nowrap;\n  color: var(--hint);\n  text-align: center;\n  font-size: 13px;" in css
    assert ".bar-label.is-unlabelled {\n  visibility: hidden;\n}" in css
    # The legend sits clear of the date labels (Risk Trend only).
    assert ".bar-chart + .map-legend {\n  margin-top: 30px;\n}" in css
    # Empty columns show no "0"; the count line keeps its height.
    assert '<span class="bar-value">${total ? total.toLocaleString("en-US") : ""}</span>' in html
    assert ".bar-value {\n  display: block;\n  min-height: 18px;" in css
    assert 'id="riskTrendChart" class="bar-chart"' in html


def test_risk_trend_draws_bars_on_a_round_number_scale():
    """Risk Trend is drawn like Datadog's or Elastic's alert histogram:
    round numbers down the left, faint grid lines, a solid baseline that
    empty days sit on, and slim square bars, instead of wide rounded bars
    with no scale and an 8px minimum that made 1 and 5 look the same."""
    html = (DASHBOARD_PUBLIC_PATH / "analytics.html").read_text(encoding="utf-8")
    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")

    assert "return Math.max(1, step);" in html
    assert "const top = Math.ceil(max / step) * step;" in html
    assert '<span class="risk-grid-line${tick === 0 ? " is-baseline" : ""}"' in html
    assert "${tick.toLocaleString(\"en-US\")}" in html
    assert 'style="height: ${total ? Math.max(2, heightOf(total)) : 2}px;"' in html
    # An empty day gets a grey stub on the baseline, so it reads as zero
    # rather than missing.
    assert '<div class="stacked-bar${total ? "" : " is-empty"}"' in html
    assert ".stacked-bar.is-empty {\n  background: var(--subtle);\n}" in css
    # Axis values (Risk Trend numbers and dates, line chart ticks) in the
    # lighter grey.
    assert "transform: translateY(50%);\n  color: var(--hint);" in css
    assert "color: var(--hint);\n  text-align: right;\n  font-size: 13px;" in css
    assert "Math.max(8, (total / max) * 170)" not in html

    assert "--risk-baseline: 24px;" in css
    assert ".risk-grid-line.is-baseline {\n  background: var(--border-strong);\n}" in css
    assert "width: min(48px, 50%);\n  border-radius: 2px 2px 0 0;" in css
    # The baseline offset counts on a fixed date-row height.
    assert "line-height: 16px;\n  height: 16px;" in css


def test_persona_charts_use_the_12_hour_clock_and_dates_with_the_month_name():
    """Personas matches Analytics: Peak Attack Hours in 12-hour form
    ("6 PM – 7 PM"), dates as "20 Oct" on the axis and "20 Oct 2026" in
    tooltips (dd/mm read as mm/dd for US users), and "1 session"."""
    html = (DASHBOARD_PUBLIC_PATH / "personas.html").read_text(encoding="utf-8")

    assert 'return (hour % 12 === 0 ? 12 : hour % 12) + " " + (hour < 12 ? "AM" : "PM");' in html
    assert 'return formatHour12(hour) + " – " + formatHour12((hour + 1) % 24);' in html
    assert "label: formatHour12(d.hour)," in html
    assert ':00 – ' not in html
    assert 'var options = { day: "2-digit", month: "short" };\n      if (withYear) options.year = "numeric";\n      return date.toLocaleDateString("en-GB", options);' in html
    assert "return formatDate(parseDateKey(dateStr), true);" in html
    assert 'return count + " " + (count === 1 ? "session" : "sessions");' in html
    assert 'values[i] + " sessions"' not in html


def test_each_page_remembers_its_own_range_for_the_tab():
    """The navbar links carry no range, so each page reset to its default
    whenever you came back to it. Sessions, Analytics and Personas each keep
    their own last applied range (one key per page, so changing one doesn't
    change the others) for the browser tab -- sessionStorage, not
    localStorage, so it can't come back stale in a new tab days later -- and
    use it when the URL names none. An Intelligence link with no range still
    means all time on Sessions."""
    pages = {
        page: (DASHBOARD_PUBLIC_PATH / f"{page}.html").read_text(encoding="utf-8")
        for page in ("sessions", "analytics", "personas")
    }

    for page, html in pages.items():
        assert f'SAVED_RANGE_KEY = "echidra.range.{page}";' in html, page
        assert "window.sessionStorage.getItem(SAVED_RANGE_KEY)" in html, page
        assert "window.sessionStorage.setItem(SAVED_RANGE_KEY, range.toString());" in html, page
        assert "localStorage.setItem(SAVED_RANGE_KEY" not in html, page
        assert '"echidra.range"' not in html, page

    for page in ("sessions", "analytics"):
        html = pages[page]
        assert "function readRangeFromUrl(params = new URLSearchParams(window.location.search)) {" in html, page
        assert "return stored ? readRangeFromUrl(new URLSearchParams(stored)) : null;" in html, page
        assert "    rememberRange(params);\n    }" in html, page

    assert "const urlRange = readRangeFromUrl() || (issueScope ? null : readSavedRange());" in pages["sessions"]
    assert "let issueAllTime = Boolean(issueScope) && !readRangeFromUrl();" in pages["sessions"]
    assert "const savedRange = readRangeFromUrl() || readSavedRange();" in pages["analytics"]
    assert "rememberRange(fromDateInput.value, toDateInput.value);" in pages["personas"]
    assert "var savedRange = readSavedRange();" in pages["personas"]


def test_attacks_by_hour_is_a_bar_chart_like_risk_trend():
    """Attacks by Hour was a line whose tooltip needed the pointer exactly on
    an 8px dot. It now uses Risk Trend's bar chart: values down the left,
    grid lines, a stub for empty hours, and the whole column as the hover
    target, in one orange band."""
    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")
    html = (DASHBOARD_PUBLIC_PATH / "analytics.html").read_text(encoding="utf-8")

    assert 'id="attacksByHourChart" class="bar-chart"' in html
    assert 'renderHourBars("attacksByHourChart", attacksByHour);' in html
    assert 'segments: [["count-fill", count]],' in html
    assert "})), 8);" in html  # every 3rd hour labelled
    assert "function renderLineChart" not in html
    assert "line-chart-dot" not in html
    assert ".bar-segment.count-fill {\n  background: #f6691d;\n}" in css


def test_persona_sessions_is_a_bar_chart_by_day_week_or_month():
    """Personas → Sessions was a line whose tooltip needed the pointer on an
    8px dot, with 77 crowded dots on a long range. It's now Risk Trend's bar
    chart, a column per day up to 31 days, per week (Monday to Sunday) up to
    180, per month beyond, with the subtitle following; partial weeks are
    named by the days inside the range. No line chart is left."""
    html = (DASHBOARD_PUBLIC_PATH / "personas.html").read_text(encoding="utf-8")

    assert '<div class="bar-chart" id="trendChart"' in html
    assert 'var unit = spanDays <= 31 ? "day" : spanDays <= 180 ? "week" : "month";' in html
    assert "monday.setDate(date.getDate() - ((date.getDay() + 6) % 7));" in html
    assert 'tipLabel = formatDate(b.start, b.start.getFullYear() !== b.end.getFullYear()) + " – " + formatDate(b.end, true);' in html
    assert 'week: "Sessions per week (Monday to Sunday).",' in html
    assert 'renderBarChart("trendChart", trend.points, 12);' in html
    assert "renderAnalytics(data, range);" in html
    assert "renderLineChart" not in html
    assert "line-chart" not in html


def test_chart_subtitles_say_what_one_column_or_point_is():
    """Each time chart's subtitle states its rollup (per day, per week,
    per month, by hour of day), as Datadog and Grafana do. Risk Trend's
    changes with the bucket the server picked, so its title stays plain."""
    analytics = (DASHBOARD_PUBLIC_PATH / "analytics.html").read_text(encoding="utf-8")
    personas = (DASHBOARD_PUBLIC_PATH / "personas.html").read_text(encoding="utf-8")
    css = (DASHBOARD_PUBLIC_PATH / "dashboard.css").read_text(encoding="utf-8")

    assert '<p id="riskTrendSubtitle">Sessions per day, by risk level.</p>' in analytics
    assert 'week: "Sessions per week (Monday to Sunday), by risk level.",' in analytics
    assert 'month: "Sessions per month, by risk level."' in analytics
    assert "Risk Trend (by ${bucket})" not in analytics
    assert "<p>Sessions by hour of day, added up across the range.</p>" in analytics

    assert '<p class="chart-card-subtitle" id="trendChartSubtitle">Sessions per day.</p>' in personas
    assert '<p class="chart-card-subtitle">Sessions by hour of day, added up across the range.</p>' in personas
    assert ".chart-card-subtitle {" in css


def test_risk_trend_week_columns_name_only_days_inside_the_range():
    """A week column covers Monday to Sunday, so a range from Saturday 1 Aug
    showed "27 Jul". Week columns are now labelled and described by the
    days inside the applied range ("01 Aug", "01 Aug – 02 Aug 2026")."""
    html = (DASHBOARD_PUBLIC_PATH / "analytics.html").read_text(encoding="utf-8")

    assert "const { start, end } = weekSpanInRange(point.date, currentRange);" in html
    assert "const start = range && dayOf(range.from) > weekStart ? dayOf(range.from) : weekStart;" in html
    assert "const end = range && dayOf(range.to) < weekEnd ? dayOf(range.to) : weekEnd;" in html
    # Across New Year both ends carry their year ("28 Dec 2026 – 03 Jan 2027").
    assert "const startYear = start.getFullYear() !== end.getFullYear();" in html
    assert "tipLabel: `${formatShortDate(start, startYear)} – ${formatShortDate(end, true)}`" in html
    assert "Week of" not in html
