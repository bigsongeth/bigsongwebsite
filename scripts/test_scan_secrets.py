#!/usr/bin/env python3
import importlib.util
import unittest
from pathlib import Path
spec = importlib.util.spec_from_file_location("scanner", Path(__file__).with_name("scan_secrets.py"))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)

class ScannerTests(unittest.TestCase):
    def test_runtime_env_is_rejected_even_without_values(self):
        self.assertEqual(scanner.scan(".env.local", "# moved"), [{"path": ".env.local", "line": 1, "rule": "tracked-runtime-env"}])
    def test_example_without_secret_is_allowed(self):
        self.assertEqual(scanner.scan(".env.example", "DATABASE_URL=\nNEXTAUTH_SECRET=\n"), [])
    def test_connection_password_is_reported_without_value(self):
        out = scanner.scan("app.ts", 'const db = "' + 'postgres://' + 'demo:' + 'fixture-only@db.example.invalid/demo";')
        self.assertEqual(out, [{"path": "app.ts", "line": 1, "rule": "database-url-password"}])
        self.assertNotIn("fixture-only", str(out))
    def test_literal_auth_secret_is_rejected(self):
        out = scanner.scan("auth.ts", 'NEXTAUTH_' + 'SECRET = "fixture-only-secret"')
        self.assertEqual(out[0]["rule"], "literal-auth-secret")
    def test_environment_reference_is_allowed(self):
        self.assertEqual(scanner.scan("auth.ts", "const secret = process.env.NEXTAUTH_SECRET;"), [])

    def test_unquoted_known_secret_assignments_are_rejected(self):
        for key in ["NEXTAUTH_SECRET", "POSTGRES_PASSWORD", "OSS_ACCESS_SECRET", "ADMIN_PASSWORD_HASH"]:
            with self.subTest(key=key):
                out = scanner.scan(".env.example", key + "=" + "fixture-only")
                self.assertTrue(any(x["rule"] == "literal-auth-secret" for x in out))
                out = scanner.scan("docker-compose.yml", "  - " + key + "=" + "fixture-only")
                self.assertTrue(any(x["rule"] == "literal-auth-secret" for x in out))
    def test_empty_and_required_runtime_references_are_allowed(self):
        for value in ["", '""', "''", "${POSTGRES_PASSWORD}", "${POSTGRES_PASSWORD:?Set at runtime}", "process.env.OSS_ACCESS_SECRET!"]:
            with self.subTest(value=value):
                self.assertEqual(scanner.scan(".env.example", "POSTGRES_PASSWORD" + "=" + value), [])
    def test_literal_environment_fallback_is_rejected(self):
        value = "${POSTGRES_PASSWORD:-fixture-only}"
        out = scanner.scan("docker-compose.yml", "  - " + "POSTGRES_PASSWORD" + "=" + value)
        self.assertTrue(any(x["rule"] == "literal-auth-secret" for x in out))
    def test_json_style_quoted_secret_is_rejected(self):
        text = '"' + "SESSION_SECRET" + '": "fixture-only"'
        self.assertTrue(scanner.scan("config.json", text))

    def test_typescript_type_declaration_is_not_a_secret(self):
        self.assertEqual(scanner.scan("types.d.ts", "accessKeyId: string;"), [])

if __name__ == "__main__":
    unittest.main(verbosity=2)
