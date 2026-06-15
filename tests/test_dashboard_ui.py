from pathlib import Path


DASHBOARD_PUBLIC_PATH = Path(__file__).resolve().parents[1] / "dashboard/public"


def test_all_dashboard_html_pages_use_shared_branding_and_tablet_viewport():
    pages = sorted(DASHBOARD_PUBLIC_PATH.glob("*.html"))

    assert pages
    for page in pages:
        html = page.read_text(encoding="utf-8")
        assert 'name="viewport" content="width=device-width, initial-scale=1"' in html
        assert 'href="/assets/qyleron_logo.png"' in html
        assert 'src="/assets/Qyleron_Banner.png"' in html
        assert '<div class="product-name">Echidra</div>' in html
        assert "@media (max-width: 768px)" in html
