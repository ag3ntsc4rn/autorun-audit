import pytest

from autorun_audit import jsonc


def test_comments_and_trailing_commas() -> None:
    text = """{
  // line comment
  "a": "http://x // not a comment", /* block
  comment */ "b": [1, 2,],
}"""
    assert jsonc.loads(text) == {"a": "http://x // not a comment", "b": [1, 2]}


def test_escaped_quotes_in_strings() -> None:
    assert jsonc.loads(r'{"a": "say \"hi\" // ok",}') == {"a": 'say "hi" // ok'}


def test_bom() -> None:
    assert jsonc.loads('\ufeff{"a": 1}') == {"a": 1}


def test_comments_keep_line_numbers() -> None:
    assert jsonc.strip_comments("/* a\nb */1").count("\n") == 1


def test_invalid() -> None:
    with pytest.raises(jsonc.JsoncError):
        jsonc.loads("{nope")
