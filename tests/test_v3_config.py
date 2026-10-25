"""Unit tests for ShadowRecon Phase 5: TOML Schema Validation & Env Var Interpolation."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / "src"))
sys.path.insert(0, str(root_dir))

from shadowrecon.config import (
    ConfigValidationError,
    interpolate_env_vars,
    load_toml_config,
    validate_toml_config,
)


class TestEnvVarInterpolation(unittest.TestCase):
    def test_interpolate_curly_braces(self):
        os.environ["TEST_SHADOW_KEY"] = "secret123"
        data = {"tor_control_password": "${TEST_SHADOW_KEY}", "nested": {"url": "https://${TEST_SHADOW_KEY}.com"}}
        res = interpolate_env_vars(data)
        self.assertEqual(res["tor_control_password"], "secret123")
        self.assertEqual(res["nested"]["url"], "https://secret123.com")

    def test_interpolate_dollar_prefix(self):
        os.environ["TEST_HOST_ENV"] = "target.local"
        data = {"target": "https://$TEST_HOST_ENV/api"}
        res = interpolate_env_vars(data)
        self.assertEqual(res["target"], "https://target.local/api")

    def test_interpolate_unset_var_becomes_empty(self):
        data = {"tor_control_password": "${NONEXISTENT_VAR_XYZ_987}"}
        res = interpolate_env_vars(data)
        self.assertEqual(res["tor_control_password"], "")

    def test_interpolate_lists_and_non_strings(self):
        os.environ["TEST_PORT"] = "9051"
        data = ["${TEST_PORT}", 123, True, {"item": "$TEST_PORT"}]
        res = interpolate_env_vars(data)
        self.assertEqual(res[0], "9051")
        self.assertEqual(res[1], 123)
        self.assertTrue(res[2])
        self.assertEqual(res[3]["item"], "9051")


class TestTomlSchemaValidation(unittest.TestCase):
    def test_valid_config_passes(self):
        valid = {
            "target": "https://example.com/",
            "ffuf_threads": 10,
            "rate_limit": 1.5,
            "proxy_provider": "tor",
            "tor_control_port": 9051,
            "dry_run": True,
        }
        res = validate_toml_config(valid)
        self.assertEqual(res, valid)

    def test_unknown_key_rejected(self):
        invalid = {"target": "https://example.com/", "unknown_malicious_setting": 123}
        with self.assertRaises(ConfigValidationError) as ctx:
            validate_toml_config(invalid)
        self.assertIn("Unknown configuration key", str(ctx.exception))
        self.assertIn("unknown_malicious_setting", str(ctx.exception))

    def test_invalid_type_rejected(self):
        invalid = {"tor_control_port": "9051"}  # String instead of int
        with self.assertRaises(ConfigValidationError) as ctx:
            validate_toml_config(invalid)
        self.assertIn("Invalid type for key 'tor_control_port'", str(ctx.exception))

    def test_value_constraint_failed(self):
        # Port out of range (1-65535)
        with self.assertRaises(ConfigValidationError) as ctx:
            validate_toml_config({"tor_control_port": 999999})
        self.assertIn("Validation failed for key 'tor_control_port'", str(ctx.exception))

        # Invalid proxy provider choice
        with self.assertRaises(ConfigValidationError) as ctx:
            validate_toml_config({"proxy_provider": "invalid_vpn"})
        self.assertIn("Validation failed for key 'proxy_provider'", str(ctx.exception))

        # Negative delay
        with self.assertRaises(ConfigValidationError) as ctx:
            validate_toml_config({"rate_limit": -2.0})
        self.assertIn("Validation failed for key 'rate_limit'", str(ctx.exception))


class TestLoadTomlConfig(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_load_valid_toml_with_interpolation(self):
        os.environ["SR_TEST_DOMAIN"] = "example.net"
        cfg_path = self.tmp / "shadowrecon.toml"
        cfg_path.write_text(
            """
            [shadowrecon]
            target = "https://${SR_TEST_DOMAIN}/"
            ffuf_threads = 8
            proxy_provider = "pool"
            rate_limit = 0.5
            """,
            encoding="utf-8",
        )
        data = load_toml_config(cfg_path, strict=True)
        self.assertEqual(data["target"], "https://example.net/")
        self.assertEqual(data["ffuf_threads"], 8)
        self.assertEqual(data["proxy_provider"], "pool")

    def test_load_invalid_toml_raises_validation_error(self):
        cfg_path = self.tmp / "bad.toml"
        cfg_path.write_text(
            """
            [shadowrecon]
            target = "https://example.com"
            bad_key_here = 42
            """,
            encoding="utf-8",
        )
        with self.assertRaises(ConfigValidationError):
            load_toml_config(cfg_path, strict=True)


if __name__ == "__main__":
    unittest.main()
