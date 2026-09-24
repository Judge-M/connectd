"""Transactional spend admission for financial Tier 2 calls."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_CEILING, ROUND_FLOOR
import json
from zoneinfo import ZoneInfo


class SpendError(ValueError):
    pass


def usd_to_cents(amount: Decimal) -> int:
    if not amount.is_finite() or amount < 0 or amount * 100 != (amount * 100).to_integral_value():
        raise SpendError("USD amount must be nonnegative with at most two decimal places")
    return int(amount * 100)


def period_start(now: datetime, period: str, reset_timezone: str = "UTC") -> datetime:
    day = now.astimezone(ZoneInfo(reset_timezone)).replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "daily":
        return day.astimezone(timezone.utc)
    if period == "weekly":
        return (day - timedelta(days=day.weekday())).astimezone(timezone.utc)
    if period == "monthly":
        return day.replace(day=1).astimezone(timezone.utc)
    raise SpendError("unsupported budget period")


@dataclass(frozen=True)
class SpendAssessment:
    financial: bool
    cost_cents: int
    approval_required: bool
    rate_per_unit_microusd: int = 0
    max_units: int = 0


@dataclass(frozen=True)
class ModelQuote:
    reserve_cents: int
    max_total_tokens: int
    input_rate_per_1k_usd: Decimal
    output_rate_per_1k_usd: Decimal
    max_cost_cents: int


def model_quote(pricing: str | dict) -> ModelQuote:
    try:
        value = json.loads(pricing) if isinstance(pricing, str) else pricing
        input_rate = Decimal(str(value["input_rate_per_1k_tokens"]))
        output_rate = Decimal(str(value["output_rate_per_1k_tokens"]))
        maximum = int(value["max_total_tokens"])
        cap = usd_to_cents(Decimal(str(value["max_cost_per_request"])))
        if (not input_rate.is_finite() or not output_rate.is_finite() or
                input_rate < 0 or output_rate < 0 or input_rate + output_rate <= 0 or
                maximum <= 0 or cap <= 0):
            raise ValueError("invalid pricing")
        worst_usd = Decimal(maximum) * max(input_rate, output_rate) / Decimal(1000)
        reserve = min(cap, int((worst_usd * 100).to_integral_value(rounding=ROUND_CEILING)))
        return ModelQuote(reserve, maximum, input_rate, output_rate, cap)
    except (TypeError, KeyError, ValueError, ArithmeticError) as exc:
        raise SpendError("model pricing needs nonnegative input/output rates, max_total_tokens, and max_cost_per_request") from exc


def bounded_model_call(quote: ModelQuote, prompt_tokens: int,
                       requested_output_tokens: int) -> tuple[int, int]:
    """Return clamped output tokens and the rounded-up worst-case reservation."""
    if (type(prompt_tokens) is not int or prompt_tokens < 0 or
            type(requested_output_tokens) is not int or requested_output_tokens <= 0):
        raise SpendError("paid inference needs valid prompt and output token counts")
    if prompt_tokens >= quote.max_total_tokens:
        raise SpendError("prompt exceeds registered total token limit")
    input_usd = Decimal(prompt_tokens) * quote.input_rate_per_1k_usd / Decimal(1000)
    cap_usd = Decimal(quote.max_cost_cents) / Decimal(100)
    if input_usd >= cap_usd:
        raise SpendError("prompt alone meets or exceeds the per-request cost cap")
    remaining = cap_usd - input_usd
    cost_limit = (int((remaining * Decimal(1000) / quote.output_rate_per_1k_usd)
                      .to_integral_value(rounding=ROUND_FLOOR))
                  if quote.output_rate_per_1k_usd > 0 else quote.max_total_tokens)
    output_tokens = min(requested_output_tokens, quote.max_total_tokens - prompt_tokens, cost_limit)
    if output_tokens <= 0:
        raise SpendError("no output tokens remain under the per-request cost cap")
    reserved_usd = input_usd + Decimal(output_tokens) * quote.output_rate_per_1k_usd / Decimal(1000)
    reserved_cents = int((reserved_usd * 100).to_integral_value(rounding=ROUND_CEILING))
    if reserved_cents > quote.max_cost_cents:
        raise SpendError("model reservation exceeds the per-request cost cap")
    return output_tokens, reserved_cents


def metered_quote(pricing: str | dict | None) -> tuple[int, int, int]:
    if not pricing:
        return (0, 0, 0)
    try:
        value = json.loads(pricing) if isinstance(pricing, str) else pricing
        rate = int(value["rate_per_unit_microusd"])
        maximum = int(value["max_units"])
        if rate <= 0 or maximum <= 0 or rate != value["rate_per_unit_microusd"] or maximum != value["max_units"]:
            raise ValueError("invalid rate or maximum")
    except (TypeError, KeyError, ValueError) as exc:
        raise SpendError("pricing_model needs positive rate_per_unit_microusd and max_units") from exc
    return ((rate * maximum + 9999) // 10000, rate, maximum)


def budget_requires_approval(db, task_id: str, cost_cents: int, now: datetime,
                             reset_timezone: str = "UTC") -> bool:
    budgets = db.execute("SELECT period,amount_cents FROM quota_budgets WHERE task_id=?", (task_id,)).fetchall()
    if not budgets or cost_cents == 0:
        return True
    for budget in budgets:
        since = period_start(now, budget["period"], reset_timezone).isoformat()
        spent = db.execute("""SELECT COALESCE(SUM(amount_cents),0) FROM quota_records
            WHERE task_id=? AND created_at>=?""", (task_id, since)).fetchone()[0]
        if spent + cost_cents > budget["amount_cents"]:
            return True
    return False


def assess_spend(db, task_id: str, tool: dict, now: datetime,
                 reset_timezone: str = "UTC") -> SpendAssessment:
    financial = bool(tool["is_financial"] or tool["provider_tier"] in {
        "external_paid", "private_rented"} or tool["effect_class"] in {
        "external_mutation", "billing_impact"} or tool["cost_per_invocation_cents"] or
        tool["pricing_model"])
    if not financial:
        return SpendAssessment(False, 0, False)
    metered_cents, rate, maximum = metered_quote(tool["pricing_model"])
    cost = int(tool["cost_per_invocation_cents"]) + metered_cents
    if cost < 0:
        raise SpendError("negative tool cost")
    return SpendAssessment(True, cost,
                           budget_requires_approval(db, task_id, cost, now, reset_timezone),
                           rate, maximum)


def settle_record(db, record_id: str, actual_units: int, *, rate_per_unit_microusd: int,
                  max_units: int, fixed_cents: int = 0) -> None:
    if not 0 <= actual_units <= max_units:
        raise SpendError("trusted usage exceeded the registered maximum")
    settled = fixed_cents + (rate_per_unit_microusd * actual_units + 9999) // 10000
    result = db.execute("""UPDATE quota_records SET amount_cents=?,actual_units=?,status='settled'
        WHERE record_id=? AND status='reserved' AND amount_cents>=?""",
        (settled, actual_units, record_id, settled))
    if result.rowcount != 1:
        raise SpendError("quota reservation cannot be settled")
