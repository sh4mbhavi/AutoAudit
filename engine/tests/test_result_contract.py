"""Phase 3 evidence states and scoring behavior."""

from decimal import Decimal

import pytest

from worker import result_contract


@pytest.mark.parametrize(
    "value,status", [(True, "passed"), (False, "failed"), (None, "indeterminate")]
)
def test_strict_opa_outcomes(value, status):
    result = result_contract.OPAResult.model_validate(
        {
            "compliant": value,
            "message": "Synthetic result",
            "affected_resources": [],
            "details": {},
        }
    )
    assert result.status == status


@pytest.mark.parametrize(
    "value",
    [
        {},
        None,
        [],
        {"compliant": "false"},
        {"compliant": 1},
        {"compliant": 0},
        {"compliant": []},
        {"compliant": True, "message": 4},
        {"compliant": True, "details": []},
        {"compliant": True, "affected_resources": {}},
    ],
)
def test_invalid_opa_output_cannot_be_assessed(value):
    with pytest.raises(ValueError):
        result_contract.OPAResult.model_validate(value)


@pytest.mark.parametrize(
    "counts,selected,compliance,coverage",
    [
        (
            {
                "passed": 8,
                "failed": 2,
                "indeterminate": 3,
                "error": 2,
                "not_assessable": 5,
                "skipped": 120,
            },
            20,
            Decimal("80.00"),
            Decimal("50.00"),
        ),
        ({"error": 10}, 10, None, Decimal("0.00")),
        ({"not_assessable": 4}, 4, None, Decimal("0.00")),
        ({"skipped": 140}, 0, None, None),
        ({"passed": 1, "error": 2}, 3, Decimal("100.00"), Decimal("33.33")),
    ],
)
def test_scores_include_every_selected_control(counts, selected, compliance, coverage):
    assert result_contract.calculate_scores(counts, selected) == (compliance, coverage)


def test_legacy_selection_does_not_invent_coverage():
    assert result_contract.calculate_scores({"passed": 1}, None) == (
        Decimal("100.00"),
        None,
    )
