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
    assert "Trusted Sessions" in html
    assert "Warnings" in html
    assert "Total Events" in html
    assert "Recent Security Events" in html
    assert "Apply Filters" not in html
    assert "Clear" not in html


def test_dashboard_map_uses_leaflet_mock_attack_origins():
    html = (DASHBOARD_PUBLIC_PATH / "index.html").read_text(encoding="utf-8")

    assert 'id="attackOriginMap"' in html
    assert "L.map(\"attackOriginMap\"" in html
    assert "L.circle([origin.lat, origin.lng]" in html
    assert "L.circleMarker([origin.lat, origin.lng]" in html
    assert "Moscow" in html
    assert "Beijing" in html
    assert "Sao Paulo" in html


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
        "Risk",
        "Intent",
    ]:
        assert f">{heading}<" in html
    assert ">Report<" not in html
    assert "Download CSV Report" in html
    assert "data-session-row" in html
