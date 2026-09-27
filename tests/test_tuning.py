from socmind.tuning import DispositionRecord, suggest_tuning


def test_tuning_requires_repeated_false_positive_pattern():
    records = [
        DispositionRecord("rule-1", "false-positive", "approved admin script"),
        DispositionRecord("rule-1", "false-positive", "approved admin script"),
        DispositionRecord("rule-1", "benign-positive", "approved admin script"),
        DispositionRecord("rule-1", "true-positive", "confirmed incident"),
        DispositionRecord("rule-1", "false-positive", "maintenance window"),
    ]
    suggestions = suggest_tuning(records)
    assert len(suggestions) == 1
    assert suggestions[0].false_positive_rate == 0.8
    assert suggestions[0].common_reasons[0] == "approved admin script"


def test_tuning_does_not_overreact_to_small_sample():
    records = [
        DispositionRecord("rule-1", "false-positive", "admin"),
        DispositionRecord("rule-1", "false-positive", "admin"),
    ]
    assert suggest_tuning(records) == []
