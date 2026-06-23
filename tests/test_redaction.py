"""Tests for credential redaction and the privacy-sensitive helpers.

The single most important property here: a plaintext secret from a leak record
must NEVER survive into anything we store. Several tests assert that directly
against realistic secret strings, not just the masked-format shape.
"""

import pytest

from pcrm.collectors.leaklookup import (
    mask_identifier, parse_record, summarize_source, severity_for as ll_severity,
)
from pcrm.collectors.hibp import (
    invert_breached_domain, severity_for as hibp_severity,
)

SECRET = "S3cr3t-P@ssw0rd!"  # used to prove it never appears in output


# ------------------------------------------------------- mask_identifier
def test_mask_email_keeps_two_chars_and_domain():
    assert mask_identifier("john.doe@example.com") == "jo******@example.com"


def test_mask_short_local_part():
    assert mask_identifier("a@x.com") == "a*@x.com"


def test_mask_username_only():
    assert mask_identifier("administrator") == "ad" + "*" * 11


def test_mask_hides_bulk_of_local_part():
    masked = mask_identifier("sensitiveuser@corp.com")
    assert masked.startswith("se") and "nsitiveuser" not in masked
    assert masked.endswith("@corp.com")


# ------------------------------------------------------- parse_record
def test_parse_record_drops_secret():
    ident, has_secret = parse_record(f"john@x.com:{SECRET}")
    assert ident == "jo**@x.com"
    assert has_secret is True
    assert SECRET not in ident


def test_parse_record_no_secret():
    assert parse_record("bob@x.com") == ("bo*@x.com", False)


def test_parse_record_empty_secret_is_not_a_secret():
    assert parse_record("bob@x.com:") == ("bo*@x.com", False)


def test_parse_record_hash_style_secret_dropped():
    ident, has_secret = parse_record("user@x.com:5f4dcc3b5aa765d61d8327deb882cf99")
    assert has_secret is True
    assert "5f4dcc3b" not in ident


# ------------------------------------------------------- summarize_source
def test_summarize_counts_dedupes_and_flags_secret():
    records = [f"a@x.com:{SECRET}", f"a@x.com:{SECRET}",
               "bob@x.com", "carol@x.com:deadbeef"]
    count, sample, has_secret = summarize_source(records)
    assert count == 4                      # count is raw record count
    assert has_secret is True
    assert len(sample) <= 3
    assert sample == sorted(set(sample))   # deduped + sorted


def test_summarize_never_leaks_secrets_into_sample():
    records = [f"alice@x.com:{SECRET}", "carol@x.com:deadbeefhash",
               f"dave@x.com:{SECRET}"]
    _, sample, _ = summarize_source(records)
    blob = " ".join(sample)
    assert SECRET not in blob
    assert "deadbeefhash" not in blob


def test_summarize_caps_sample_size():
    # distinct first-two chars so masking doesn't collapse them
    records = [f"{p}user@x.com:{SECRET}"
               for p in ("ab", "cd", "ef", "gh", "ij")]
    _, sample, _ = summarize_source(records, sample_n=3)
    assert len(sample) == 3


def test_summarize_collapses_similar_identifiers():
    # masking is intentionally lossy: near-identical locals dedupe to one entry
    records = [f"user{i}@x.com" for i in range(10)]   # all -> us***@x.com
    count, sample, _ = summarize_source(records)
    assert count == 10
    assert sample == ["us***@x.com"]


def test_summarize_no_secret_when_only_identifiers():
    count, _, has_secret = summarize_source(["a@x.com", "b@x.com"])
    assert count == 2 and has_secret is False


# ------------------------------------------------------- leaklookup severity
def test_ll_severity_credentials_and_count():
    assert ll_severity(8, True) == 68.0       # 45 + 15 + 8


def test_ll_severity_no_credentials():
    assert ll_severity(0, False) == 45.0


def test_ll_severity_count_capped_at_20():
    assert ll_severity(100, True) == 80.0      # 45 + 15 + 20
    assert ll_severity(30, False) == 65.0      # 45 + 20


def test_ll_severity_never_exceeds_90():
    assert ll_severity(10_000, True) <= 90.0


# ------------------------------------------------------- hibp invert
def test_invert_breached_domain():
    out = invert_breached_domain({"j.doe": ["Adobe", "LinkedIn"],
                                  "billing": ["Adobe"]})
    assert out == {"Adobe": ["j.doe", "billing"], "LinkedIn": ["j.doe"]}


def test_invert_empty():
    assert invert_breached_domain({}) == {}


def test_invert_none_is_safe():
    assert invert_breached_domain(None) == {}


# ------------------------------------------------------- hibp severity
def test_hibp_severity_credentials_recent():
    score, has_creds = hibp_severity(
        {"DataClasses": ["Email addresses", "Passwords"], "BreachDate": "2024-05-01"}, 14)
    assert score == 84.0   # 45 + 15 + 14 + 10
    assert has_creds is True


def test_hibp_severity_email_only_old():
    score, has_creds = hibp_severity(
        {"DataClasses": ["Email addresses"], "BreachDate": "2017-01-01"}, 2)
    assert score == 47.0   # 45 + 0 + 2
    assert has_creds is False


def test_hibp_severity_auth_token_counts_as_credentials():
    _, has_creds = hibp_severity({"DataClasses": ["Auth tokens"], "BreachDate": "2020-01-01"}, 1)
    assert has_creds is True


def test_hibp_severity_capped_at_95():
    score, _ = hibp_severity(
        {"DataClasses": ["Passwords"], "BreachDate": "2025-01-01"}, 10_000)
    assert score <= 95.0
