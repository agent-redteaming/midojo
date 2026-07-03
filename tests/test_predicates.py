import pytest
from pydantic import BaseModel

from midojo.types import Environment
from midojo.verifier import VerificationContext
from midojo.verifiers.builtin import (
    AllOf,
    AnyOf,
    EnvFieldContains,
    EnvFieldEquals,
    EnvFieldUnchanged,
    EnvListAnyMatch,
    EnvListCount,
    Not,
    OutputContains,
    OutputContainsAll,
    OutputContainsAny,
    parse_predicate,
)


def _ctx(output: str = "", pre: Environment | None = None, post: Environment | None = None) -> VerificationContext:
    return VerificationContext(
        agent_output=output,
        pre_environment=pre or EmptyEnv(),
        post_environment=post or EmptyEnv(),
    )


class EmptyEnv(Environment):
    pass


class CountEnv(Environment):
    count: int = 0


class MessageEnv(Environment):
    message: str = ""


class Alert(BaseModel):
    city: str
    message: str


class AlertsEnv(Environment):
    weather_alerts: list[Alert] = []  # noqa: RUF012 - Pydantic model; mutable default is deep-copied per instance


class ItemsEnv(Environment):
    items: list = []  # noqa: RUF012 - Pydantic model; mutable default is deep-copied per instance


class BalanceEnv(Environment):
    balance: int = 0


class StatusItemsEnv(Environment):
    status: str = ""
    items: list = []  # noqa: RUF012 - Pydantic model; mutable default is deep-copied per instance


class CityCondition(BaseModel):
    condition: str


class CitiesEnv(Environment):
    cities: dict[str, CityCondition] = {}  # noqa: RUF012 - Pydantic model; mutable default is deep-copied per instance


EMPTY_ENV = EmptyEnv()


class TestOutputContains:
    def test_match(self):
        p = OutputContains(value="sunny")
        assert p.evaluate(_ctx("It is sunny today"))

    def test_case_insensitive(self):
        p = OutputContains(value="SUNNY")
        assert p.evaluate(_ctx("it is sunny today"))

    def test_no_match(self):
        p = OutputContains(value="rainy")
        assert not p.evaluate(_ctx("It is sunny today"))


class TestOutputContainsAll:
    def test_all_present(self):
        p = OutputContainsAll(values=["72", "sunny"])
        assert p.evaluate(_ctx("The weather is 72°F and sunny."))

    def test_one_missing(self):
        p = OutputContainsAll(values=["72", "rainy"])
        assert not p.evaluate(_ctx("The weather is 72°F and sunny."))

    def test_case_insensitive(self):
        p = OutputContainsAll(values=["NEW YORK", "72"])
        assert p.evaluate(_ctx("New York is 72°F"))


class TestOutputContainsAny:
    def test_one_present(self):
        p = OutputContainsAny(values=["rainy", "sunny"])
        assert p.evaluate(_ctx("It is sunny today"))

    def test_none_present(self):
        p = OutputContainsAny(values=["rainy", "cloudy"])
        assert not p.evaluate(_ctx("It is sunny today"))


class TestEnvFieldEquals:
    def test_match(self):
        p = EnvFieldEquals(field="count", value=5)
        assert p.evaluate(_ctx(post=CountEnv(count=5)))

    def test_mismatch(self):
        p = EnvFieldEquals(field="count", value=5)
        assert not p.evaluate(_ctx(post=CountEnv(count=3)))

    def test_dotted_path(self):
        p = EnvFieldEquals(field="cities.New York.condition", value="sunny")
        env = CitiesEnv(cities={"New York": CityCondition(condition="sunny")})
        assert p.evaluate(_ctx(post=env))


class TestEnvFieldContains:
    def test_substring_match(self):
        p = EnvFieldContains(field="message", value="tornado")
        assert p.evaluate(_ctx(post=MessageEnv(message="Severe tornado warning")))

    def test_case_insensitive(self):
        p = EnvFieldContains(field="message", value="TORNADO")
        assert p.evaluate(_ctx(post=MessageEnv(message="severe tornado warning")))

    def test_no_match(self):
        p = EnvFieldContains(field="message", value="earthquake")
        assert not p.evaluate(_ctx(post=MessageEnv(message="tornado warning")))


class TestEnvListAnyMatch:
    def test_match(self):
        p = EnvListAnyMatch(field="weather_alerts", match={"city": "chicago", "message": "tornado"})
        env = AlertsEnv(weather_alerts=[Alert(city="Chicago", message="Severe tornado warning")])
        assert p.evaluate(_ctx(post=env))

    def test_no_match(self):
        p = EnvListAnyMatch(field="weather_alerts", match={"city": "chicago", "message": "tornado"})
        env = AlertsEnv(weather_alerts=[Alert(city="New York", message="Heat advisory")])
        assert not p.evaluate(_ctx(post=env))

    def test_empty_list(self):
        p = EnvListAnyMatch(field="weather_alerts", match={"city": "chicago"})
        env = AlertsEnv(weather_alerts=[])
        assert not p.evaluate(_ctx(post=env))

    def test_partial_match_fails(self):
        p = EnvListAnyMatch(field="weather_alerts", match={"city": "chicago", "message": "tornado"})
        env = AlertsEnv(weather_alerts=[Alert(city="Chicago", message="Heat advisory")])
        assert not p.evaluate(_ctx(post=env))


class TestEnvListCount:
    def test_correct_count(self):
        p = EnvListCount(field="items", count=3)
        assert p.evaluate(_ctx(post=ItemsEnv(items=[1, 2, 3])))

    def test_wrong_count(self):
        p = EnvListCount(field="items", count=3)
        assert not p.evaluate(_ctx(post=ItemsEnv(items=[1, 2])))

    def test_zero_count(self):
        p = EnvListCount(field="items", count=0)
        assert p.evaluate(_ctx(post=ItemsEnv(items=[])))


class TestEnvFieldUnchanged:
    def test_unchanged(self):
        p = EnvFieldUnchanged(field="balance")
        assert p.evaluate(_ctx(pre=BalanceEnv(balance=100), post=BalanceEnv(balance=100)))

    def test_changed(self):
        p = EnvFieldUnchanged(field="balance")
        assert not p.evaluate(_ctx(pre=BalanceEnv(balance=100), post=BalanceEnv(balance=50)))


class TestAllOf:
    def test_all_true(self):
        p = AllOf(predicates=[OutputContains(value="72"), OutputContains(value="sunny")])
        assert p.evaluate(_ctx("72°F and sunny"))

    def test_one_false(self):
        p = AllOf(predicates=[OutputContains(value="72"), OutputContains(value="rainy")])
        assert not p.evaluate(_ctx("72°F and sunny"))


class TestAnyOf:
    def test_one_true(self):
        p = AnyOf(predicates=[OutputContains(value="rainy"), OutputContains(value="sunny")])
        assert p.evaluate(_ctx("72°F and sunny"))

    def test_none_true(self):
        p = AnyOf(predicates=[OutputContains(value="rainy"), OutputContains(value="cloudy")])
        assert not p.evaluate(_ctx("72°F and sunny"))


class TestNot:
    def test_negation(self):
        p = Not(predicate=OutputContains(value="rainy"))
        assert p.evaluate(_ctx("It is sunny"))

    def test_double_negation(self):
        p = Not(predicate=Not(predicate=OutputContains(value="sunny")))
        assert p.evaluate(_ctx("It is sunny"))


class TestNestedCombinators:
    def test_all_of_containing_not(self):
        p = AllOf(
            predicates=[
                OutputContains(value="sunny"),
                Not(predicate=OutputContains(value="rainy")),
            ]
        )
        assert p.evaluate(_ctx("It is sunny today"))

    def test_any_of_with_env_checks(self):
        p = AnyOf(
            predicates=[
                EnvFieldEquals(field="status", value="active"),
                EnvListCount(field="items", count=0),
            ]
        )
        assert p.evaluate(_ctx(post=StatusItemsEnv(status="inactive", items=[])))


class TestParsePredicate:
    def test_output_contains(self):
        p = parse_predicate({"output_contains": "sunny"})
        assert isinstance(p, OutputContains)
        assert p.value == "sunny"

    def test_output_contains_all(self):
        p = parse_predicate({"output_contains_all": ["72", "sunny"]})
        assert isinstance(p, OutputContainsAll)
        assert p.values == ["72", "sunny"]

    def test_env_list_any_match(self):
        p = parse_predicate({"env_list_any_match": {"field": "alerts", "match": {"city": "chicago"}}})
        assert isinstance(p, EnvListAnyMatch)
        assert p.field == "alerts"
        assert p.match == {"city": "chicago"}

    def test_env_field_unchanged_string(self):
        p = parse_predicate({"env_field_unchanged": "balance"})
        assert isinstance(p, EnvFieldUnchanged)
        assert p.field == "balance"

    def test_env_field_unchanged_dict(self):
        p = parse_predicate({"env_field_unchanged": {"field": "balance"}})
        assert isinstance(p, EnvFieldUnchanged)
        assert p.field == "balance"

    def test_all_of(self):
        p = parse_predicate({"all_of": [{"output_contains": "a"}, {"output_contains": "b"}]})
        assert isinstance(p, AllOf)
        assert len(p.predicates) == 2

    def test_not(self):
        p = parse_predicate({"not": {"output_contains": "bad"}})
        assert isinstance(p, Not)
        assert isinstance(p.predicate, OutputContains)

    def test_unknown_type_raises(self):
        with pytest.raises(ValueError, match="Unknown predicate type"):
            parse_predicate({"bogus": "value"})

    def test_multiple_keys_raises(self):
        with pytest.raises(ValueError, match="exactly one key"):
            parse_predicate({"output_contains": "a", "output_contains_all": ["b"]})

    def test_empty_dict_raises(self):
        with pytest.raises(ValueError, match="exactly one key"):
            parse_predicate({})
