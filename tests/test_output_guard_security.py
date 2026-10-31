from stage2_sdk_ai.output_guard import check_output, contains_pii, redact_pii


def test_redacts_email_phone_ssn_card_and_street_address():
    original = (
        "Email alice@example.com, phone 555-123-4567, "
        "SSN 123-45-6789, card 4111 1111 1111 1111, address 123 Main St"
    )
    result = check_output(original)

    assert result["filtered"] is True
    assert "[REDACTED:EMAIL]" in result["text"]
    assert "[REDACTED:PHONE]" in result["text"]
    assert "[REDACTED:SSN]" in result["text"]
    assert "[REDACTED:CARD]" in result["text"]
    assert "[REDACTED:ADDRESS]" in result["text"]
    assert not contains_pii(result["text"])


def test_redacts_pii_recursively_from_source_metadata():
    result = check_output(
        "A safe answer",
        sources=[
            {
                "text": "Contact alice@example.com",
                "metadata": {"phone": "555-123-4567"},
            }
        ],
    )

    assert result["filtered"] is True
    assert "alice@example.com" not in str(result["sources"])
    assert "555-123-4567" not in str(result["sources"])


def test_does_not_flag_non_luhn_number_as_payment_card():
    original = "Reference number 1234567890123456"
    redacted, changed = redact_pii(original)
    assert changed is False
    assert redacted == original


def test_non_string_model_output_fails_closed():
    result = check_output(None)
    assert result["filtered"] is True
    assert result["text"] == ""
    assert result["sources"] == []


def test_redacts_international_and_local_phone_formats():
    for number in ("+254 712 345 678", "0712 345 678"):
        result = check_output(f"Call {number}")
        assert result["filtered"] is True
        assert number not in result["text"]
        assert not contains_pii(result["text"])
