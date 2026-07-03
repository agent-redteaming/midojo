from midojo.env_inference import infer_environment_type
from midojo.types import Environment


def test_scalar_fields():
    env_data = {"name": "test", "count": 5, "ratio": 3.14, "active": True}
    EnvType = infer_environment_type("demo", env_data)  # noqa: N806 - type factory
    assert issubclass(EnvType, Environment)

    instance = EnvType.model_validate(env_data)
    assert instance.name == "test"
    assert instance.count == 5
    assert instance.ratio == 3.14
    assert instance.active is True
    assert instance.model_dump() == env_data


def test_empty_list_defaults():
    env_data = {"items": []}
    EnvType = infer_environment_type("demo", env_data)  # noqa: N806 - type factory
    instance = EnvType.model_validate(env_data)
    assert instance.items == []

    instance_no_field = EnvType.model_validate({})
    assert instance_no_field.items == []


def test_dict_of_nested_dicts():
    env_data = {
        "cities": {
            "NYC": {"name": "New York", "pop": 8_000_000},
            "SF": {"name": "San Francisco", "pop": 800_000},
        }
    }
    EnvType = infer_environment_type("demo", env_data)  # noqa: N806 - type factory
    instance = EnvType.model_validate(env_data)
    assert instance.cities["NYC"].name == "New York"
    assert instance.cities["SF"].pop == 800_000


def test_nonempty_list_of_dicts():
    env_data = {
        "alerts": [
            {"city": "Chicago", "message": "tornado"},
            {"city": "NYC", "message": "flood"},
        ]
    }
    EnvType = infer_environment_type("demo", env_data)  # noqa: N806 - type factory
    instance = EnvType.model_validate(env_data)
    assert len(instance.alerts) == 2
    assert instance.alerts[0].city == "Chicago"


def test_nonempty_list_of_scalars():
    env_data = {"tags": ["a", "b", "c"]}
    EnvType = infer_environment_type("demo", env_data)  # noqa: N806 - type factory
    instance = EnvType.model_validate(env_data)
    assert instance.tags == ["a", "b", "c"]


def test_roundtrip_weather_structure():
    env_data = {
        "cities": {
            "New York": {
                "city": "New York",
                "temperature_f": 72.0,
                "condition": "sunny",
                "notes": "",
            },
            "San Francisco": {
                "city": "San Francisco",
                "temperature_f": 58.0,
                "condition": "foggy",
                "notes": "",
            },
        },
        "weather_alerts": [],
    }
    EnvType = infer_environment_type("weather", env_data)  # noqa: N806 - type factory
    instance = EnvType.model_validate(env_data)
    assert instance.cities["New York"].temperature_f == 72.0
    assert instance.weather_alerts == []

    dumped = instance.model_dump()
    assert dumped["cities"]["San Francisco"]["condition"] == "foggy"

    instance2 = EnvType.model_validate(dumped)
    assert instance2.cities["New York"].city == "New York"


def test_model_copy_deep():
    env_data = {"items": [], "cities": {"A": {"name": "a", "pop": 1}}}
    EnvType = infer_environment_type("demo", env_data)  # noqa: N806 - type factory
    instance = EnvType.model_validate(env_data)
    copy = instance.model_copy(deep=True)
    copy.items.append({"x": 1})
    assert instance.items == []
