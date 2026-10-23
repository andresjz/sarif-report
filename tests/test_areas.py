"""Path classification tests."""

from sarif_report.areas import classify

UI_AREAS = [
    {"label": "src/pages", "match": ["src/pages/"]},
    {"label": "src/components", "match": ["src/components/"]},
    {"label": ".github (CI)", "match": [".github/"]},
    {"label": "Build", "match": ["Dockerfile", "vite.config", "package.json", "tsconfig"]},
    {"label": "Otros", "match": ["*"]},
]


def test_prefix_match_wins():
    assert classify("src/pages/Home.tsx", UI_AREAS) == 0
    assert classify("src/components/Button.tsx", UI_AREAS) == 1


def test_first_match_order_is_respected():
    # A path that could match two areas lands in the first declared one.
    areas = [
        {"label": "src", "match": ["src/"]},
        {"label": "pages", "match": ["src/pages/"]},
        {"label": "Otros", "match": ["*"]},
    ]
    assert classify("src/pages/Home.tsx", areas) == 0


def test_substring_match_for_build_files():
    assert classify("frontend/vite.config.ts", UI_AREAS) == 3
    assert classify("package.json", UI_AREAS) == 3
    assert classify("tsconfig.json", UI_AREAS) == 3


def test_github_prefix():
    assert classify(".github/workflows/ci.yml", UI_AREAS) == 2


def test_catch_all():
    assert classify("random/other/file.md", UI_AREAS) == 4


def test_leading_dot_slash_normalized():
    assert classify("./src/pages/Home.tsx", UI_AREAS) == 0


def test_backslashes_normalized():
    assert classify("src\\pages\\Home.tsx", UI_AREAS) == 0


def test_no_catch_all_falls_back_to_last():
    areas = [
        {"label": "src/pages", "match": ["src/pages/"]},
        {"label": "src/components", "match": ["src/components/"]},
    ]
    # Nothing matches -> stable fallback to last area index.
    assert classify("README.md", areas) == 1
