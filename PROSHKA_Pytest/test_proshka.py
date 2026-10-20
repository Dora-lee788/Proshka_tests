"""Read-only black-box smoke tests for the public #PROSHKA website.

All checks use GET requests only. The tests do not submit forms or send personal data.
"""

import os
import re
from urllib.parse import urljoin

import pytest
import requests

BASE_URL = os.getenv("PROSHKA_BASE_URL", "https://proshkaekosystem.ru/").rstrip("/") + "/"
TIMEOUT = 10

PAGES = [
    ("partner.html", "Страница партнёрства"),
    ("brands/events/events.html", "Ивенты"),
    ("brands/music/music.html", "Музыка"),
    ("brands/dance/dance.html", "Dance"),
    ("brands/cinema/cinema.html", "Кинорежиссура"),
    ("brands/clothing/clothing.html", "Мерч"),
    ("showcase/vampilov-son.html", "Проект Старший сын"),
]

ASSETS = [
    "css/style.css",
    "css/hero.css",
    "js/script.js",
    "js/forms.js",
    "js/hero.js",
    "js/scene.js",
]


def get(path=""):
    """Perform one read-only GET request to the configured public site."""
    return requests.get(urljoin(BASE_URL, path), timeout=TIMEOUT, allow_redirects=True)


def html_text(response):
    """Decode HTML using its declared meta charset, not requests' Latin-1 fallback."""
    raw = response.content
    declared = re.search(
        br"<meta[^>]+charset\s*=\s*['\"]?\s*([a-zA-Z0-9._-]+)",
        raw[:8192],
        re.IGNORECASE,
    )
    if declared:
        encoding = declared.group(1).decode("ascii", errors="ignore")
    else:
        content_type = response.headers.get("Content-Type", "")
        match = re.search(r"charset\s*=\s*['\"]?\s*([a-zA-Z0-9._-]+)", content_type, re.I)
        encoding = match.group(1) if match else "utf-8"
    try:
        return raw.decode(encoding, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def test_homepage_is_accessible_and_html():
    response = get()
    assert response.status_code == 200, f"Главная страница вернула HTTP {response.status_code}"
    assert "text/html" in response.headers.get("Content-Type", "").lower()
    assert "#PROSHKA" in html_text(response)


def test_tracking_query_does_not_break_homepage():
    response = get("?utm_source=chatgpt.com")
    assert response.status_code == 200, f"URL с UTM вернул HTTP {response.status_code}"
    page = html_text(response)
    assert "#PROSHKA" in page
    assert "<html" in page.lower()


@pytest.mark.parametrize("path,label", PAGES, ids=[p[1] for p in PAGES])
def test_public_pages_are_accessible(path, label):
    response = get(path)
    assert response.status_code == 200, f"{label}: HTTP {response.status_code} ({response.url})"
    assert "text/html" in response.headers.get("Content-Type", "").lower(), f"{label}: ответ не HTML"


def test_partner_form_contains_expected_fields():
    response = get("partner.html")
    assert response.status_code == 200
    page = html_text(response).lower()

    # Use form control names/IDs as the primary check; display labels may be phrased differently.
    expected_fields = {
        "ФИО / имя": r"(?:name|id)\s*=\s*['\"](?:fullname|fio|full.?name)['\"]",
        "телефон": r"(?:name|id)\s*=\s*['\"](?:phone|tel|telephone)['\"]|type\s*=\s*['\"]tel['\"]",
        "почта": r"(?:name|id)\s*=\s*['\"](?:email|mail)['\"]|type\s*=\s*['\"]email['\"]",
        "город": r"(?:name|id)\s*=\s*['\"]city['\"]",
    }
    for field_label, pattern in expected_fields.items():
        assert re.search(pattern, page, re.I), (
            f"В HTML страницы партнёрства не найден элемент формы для поля «{field_label}». "
            "Проверьте актуальную разметку страницы вручную."
        )


def test_partner_page_discloses_personal_data_policy():
    """Check visible mention or a likely policy link; absence is a review finding, not proof of illegality."""
    response = get("partner.html")
    assert response.status_code == 200
    page = html_text(response).lower()
    disclosure_terms = (
        "политика конфиденциальности",
        "политика обработки персональных данных",
        "обработка персональных данных",
        "согласие на обработку",
    )
    policy_href = re.search(
        r"href\s*=\s*['\"][^'\"]*(?:privacy|policy|personal.?data|personaldata|confidential)[^'\"]*['\"]",
        page,
        re.I,
    )
    assert any(term in page for term in disclosure_terms) or policy_href, (
        "В HTML страницы партнёрства не найдено явного упоминания политики/согласия "
        "или ссылки с характерным названием. Проверьте страницу вручную."
    )


def test_main_css_and_js_assets_are_accessible():
    for asset in ASSETS:
        response = get(asset)
        assert response.status_code == 200, f"Ресурс {asset}: HTTP {response.status_code}"
        assert len(response.content) > 20, f"Ресурс {asset} пустой или слишком короткий"


def test_https_is_used_after_redirects():
    response = get()
    assert response.url.lower().startswith("https://"), (
        f"После перенаправлений используется не HTTPS: {response.url}"
    )


def test_security_headers_baseline():
    """Missing headers are reported for review; their absence alone does not prove an exploit."""
    response = get()
    headers = {key.lower(): value for key, value in response.headers.items()}
    missing = []
    if "strict-transport-security" not in headers:
        missing.append("Strict-Transport-Security")
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        missing.append("X-Content-Type-Options: nosniff")
    if "referrer-policy" not in headers:
        missing.append("Referrer-Policy")
    csp = headers.get("content-security-policy", "") or headers.get("content-security-policy-report-only", "")
    if not csp:
        missing.append("Content-Security-Policy (или Report-Only)")
    xfo = headers.get("x-frame-options", "")
    if not xfo and "frame-ancestors" not in csp.lower():
        missing.append("X-Frame-Options или CSP frame-ancestors")
    assert not missing, "Для ручной проверки не обнаружены защитные HTTP-заголовки: " + ", ".join(missing)


@pytest.mark.parametrize("path", [".env", ".git/HEAD"], ids=["env-file", "git-metadata"])
def test_common_private_files_are_not_exposed(path):
    """GET-only check. Does not print or otherwise reveal any response body."""
    response = get(path)

    # Any non-200 final response means the requested resource was not returned successfully.
    # 405 (Method Not Allowed), as seen in the first run, is not evidence of file exposure.
    if response.status_code != 200:
        return

    content_type = response.headers.get("Content-Type", "").lower()
    body = response.content[:2000]
    body_start = body.lstrip().lower()
    if "text/html" in content_type and (b"<html" in body_start or b"<!doctype html" in body_start):
        pytest.skip("HTTP 200 с HTML похож на fallback-страницу хостинга; нужен ручной просмотр")

    # Detect only recognizable file formats and never include file contents in assertion output.
    if path == ".env":
        looks_like_env = re.search(rb"(?m)^\s*[A-Z_][A-Z0-9_]{1,50}\s*=\s*\S+", body)
        assert not looks_like_env, "Ответ похож на опубликованный .env-файл; содержимое не выводится"
    else:
        looks_like_git_head = re.search(rb"(?m)^\s*(?:ref:\s*refs/heads/[^\s]+|[0-9a-f]{40})\s*$", body)
        assert not looks_like_git_head, "Ответ похож на содержимое .git/HEAD; содержимое не выводится"

    pytest.skip("HTTP 200 без узнаваемого формата файла: результат требует ручной проверки")
