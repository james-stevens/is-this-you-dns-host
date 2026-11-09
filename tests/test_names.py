import pytest

from dns_host.errors import ApiError
from dns_host.names import normalise_apex, normalise_name


def test_apex_is_lowercased_and_made_absolute():
    assert normalise_apex("Example.COM").to_text() == "example.com."
    assert normalise_apex("example.com.").to_text() == "example.com."


def test_unicode_apex_is_idna():
    assert normalise_apex("Bücher.Example").to_text() == "xn--bcher-kva.example."


def test_wildcard_and_bad_labels_are_rejected():
    with pytest.raises(ApiError) as caught:
        normalise_name("*.example.com.")
    assert caught.value.error == "bad_label"
    with pytest.raises(ApiError):
        normalise_name("-bad.example.com.")
    assert normalise_name("_auth.7e9a.example.com.").to_text() == "_auth.7e9a.example.com."
