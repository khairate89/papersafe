from io import BytesIO
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path

import app as papersafe


SAMPLE_PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"


class PaperSafeTests(unittest.TestCase):
    def setUp(self):
        self.original_config = papersafe.app.config.copy()
        self.temp_dir = tempfile.TemporaryDirectory(prefix=".papersafe-test-", dir=Path(__file__).resolve().parents[1])
        data_dir = Path(self.temp_dir.name) / "instance"
        upload_dir = data_dir / "uploads"
        upload_dir.mkdir(parents=True)
        papersafe.app.config.update(
            TESTING=True,
            SECRET_KEY="tests-only-synthetic-secret",
            DATABASE=str(data_dir / "test.sqlite3"),
            UPLOAD_FOLDER=str(upload_dir),
            MAX_CONTENT_LENGTH=(
                papersafe.MAX_UPLOAD_BYTES
                + papersafe.MAX_MULTIPART_OVERHEAD_BYTES
            ),
            WTF_CSRF_ENABLED=True,
            WTF_CSRF_CHECK_DEFAULT=True,
        )
        papersafe.init_db(papersafe.app.config["DATABASE"])
        self.client = papersafe.app.test_client()

    def tearDown(self):
        papersafe.app.config.clear()
        papersafe.app.config.update(self.original_config)
        self.temp_dir.cleanup()

    def csrf_token(self, path="/documents"):
        response = self.client.get(path)
        match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(match, f"CSRF token input missing from {path}")
        return match.group(1).decode()

    def register(self, username, password="Synthetic-password-2026!"):
        token = self.csrf_token("/register")
        return self.client.post(
            "/register",
            data={"csrf_token": token, "username": username, "password": password},
            follow_redirects=True,
        )

    def login(self, username, password="Synthetic-password-2026!"):
        token = self.csrf_token("/login")
        return self.client.post(
            "/login",
            data={"csrf_token": token, "username": username, "password": password},
            follow_redirects=True,
        )

    def create_pdf(self, title="Sample document", filename="sample.pdf"):
        token = self.csrf_token("/upload")
        return self.client.post(
            "/upload",
            data={"csrf_token": token, "title": title,
                  "pdf": (BytesIO(SAMPLE_PDF), filename)},
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    def document_id(self, title):
        with papersafe.app.app_context():
            row = papersafe.get_db().execute(
                "SELECT id FROM documents WHERE title = ?", (title,)
            ).fetchone()
            self.assertIsNotNone(row)
            return row["id"]

    def test_registration_and_login(self):
        response = self.register("alice")
        self.assertIn(b"Account created", response.data)
        duplicate = self.register("alice")
        self.assertIn(b"already in use", duplicate.data)
        signed_in = self.login("alice")
        self.assertIn(b"Documents", signed_in.data)

    def test_logout_invalidates_copied_session_cookie(self):
        self.register("alice")
        self.login("alice")
        self.assertEqual(self.client.get("/documents").status_code, 200)
        copied_cookie = self.client.get_cookie("session")
        self.assertIsNotNone(copied_cookie)

        logout = self.client.post(
            "/logout", data={"csrf_token": self.csrf_token()}
        )
        self.assertEqual(logout.status_code, 302)

        replay_client = papersafe.app.test_client()
        replay_client.set_cookie("session", copied_cookie.value)
        replay = replay_client.get("/documents")
        self.assertEqual(replay.status_code, 302)
        self.assertEqual(replay.headers["Location"], "/login")

    def test_fresh_login_works_after_logout(self):
        self.register("alice")
        self.login("alice")
        logout = self.client.post(
            "/logout", data={"csrf_token": self.csrf_token()}
        )
        self.assertEqual(logout.status_code, 302)

        signed_in_again = self.login("alice")
        self.assertIn(b"Documents", signed_in_again.data)
        self.assertEqual(self.client.get("/documents").status_code, 200)

    def test_missing_or_malformed_session_version_is_rejected(self):
        self.register("alice")
        self.login("alice")
        with self.client.session_transaction() as session:
            session.pop("session_version", None)
        missing_version = self.client.get("/documents")
        self.assertEqual(missing_version.status_code, 302)
        self.assertEqual(missing_version.headers["Location"], "/login")

        self.login("alice")
        with self.client.session_transaction() as session:
            session["session_version"] = "not-an-integer"
        malformed_version = self.client.get("/documents")
        self.assertEqual(malformed_version.status_code, 302)
        self.assertEqual(malformed_version.headers["Location"], "/login")

    def test_logout_invalidates_other_active_sessions_for_account(self):
        self.register("alice")
        self.login("alice")

        other_client = papersafe.app.test_client()
        login_page = other_client.get("/login")
        token_match = re.search(
            rb'name="csrf_token" value="([^"]+)"', login_page.data
        )
        self.assertIsNotNone(token_match)
        other_login = other_client.post(
            "/login",
            data={
                "csrf_token": token_match.group(1).decode(),
                "username": "alice",
                "password": "Synthetic-password-2026!",
            },
        )
        self.assertEqual(other_login.status_code, 302)
        self.assertEqual(other_client.get("/documents").status_code, 200)

        logout = self.client.post(
            "/logout", data={"csrf_token": self.csrf_token()}
        )
        self.assertEqual(logout.status_code, 302)
        other_response = other_client.get("/documents")
        self.assertEqual(other_response.status_code, 302)
        self.assertEqual(other_response.headers["Location"], "/login")

    def test_legacy_database_migration_preserves_data_and_uploads(self):
        legacy_db = Path(self.temp_dir.name) / "legacy.sqlite3"
        legacy_uploads = Path(self.temp_dir.name) / "legacy-uploads"
        legacy_uploads.mkdir()
        pdf_bytes = SAMPLE_PDF
        (legacy_uploads / "existing.pdf").write_bytes(pdf_bytes)

        connection = sqlite3.connect(legacy_db)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                stored_name TEXT NOT NULL UNIQUE,
                original_name TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE document_shares (
                document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
                recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                shared_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (document_id, recipient_id)
            );
            INSERT INTO users (id, username, password_hash)
                VALUES (1, 'alice', 'existing-hash-alice');
            INSERT INTO users (id, username, password_hash)
                VALUES (2, 'bob', 'existing-hash-bob');
            INSERT INTO documents
                (id, owner_id, title, stored_name, original_name, size_bytes)
                VALUES (7, 1, 'Existing document', 'existing.pdf',
                        'original.pdf', 44);
            INSERT INTO document_shares (document_id, recipient_id)
                VALUES (7, 2);
            """
        )
        connection.commit()
        connection.close()

        papersafe.init_db(str(legacy_db))

        migrated = sqlite3.connect(legacy_db)
        try:
            user_columns = {
                row[1] for row in migrated.execute("PRAGMA table_info(users)")
            }
            self.assertIn("session_version", user_columns)
            users = migrated.execute(
                "SELECT id, username, password_hash, session_version "
                "FROM users ORDER BY id"
            ).fetchall()
            documents = migrated.execute(
                "SELECT id, owner_id, title, stored_name, original_name, size_bytes "
                "FROM documents"
            ).fetchall()
            shares = migrated.execute(
                "SELECT document_id, recipient_id FROM document_shares"
            ).fetchall()
        finally:
            migrated.close()

        self.assertEqual(
            users,
            [(1, "alice", "existing-hash-alice", 0),
             (2, "bob", "existing-hash-bob", 0)],
        )
        self.assertEqual(
            documents,
            [(7, 1, "Existing document", "existing.pdf", "original.pdf", 44)],
        )
        self.assertEqual(shares, [(7, 2)])
        self.assertEqual((legacy_uploads / "existing.pdf").read_bytes(), pdf_bytes)

    def test_anonymous_and_logout_csrf_protections_remain(self):
        anonymous = self.client.get("/documents")
        self.assertEqual(anonymous.status_code, 302)
        self.assertEqual(anonymous.headers["Location"], "/login")

        self.register("alice")
        self.login("alice")
        missing_csrf = self.client.post("/logout")
        self.assertEqual(missing_csrf.status_code, 400)
        self.assertEqual(self.client.get("/documents").status_code, 200)

    def test_logout_database_error_does_not_claim_success(self):
        self.register("alice")
        self.login("alice")
        with papersafe.app.app_context():
            papersafe.get_db().execute(
                """CREATE TRIGGER reject_session_version_update
                   BEFORE UPDATE OF session_version ON users
                   BEGIN SELECT RAISE(ABORT, 'simulated database failure'); END"""
            )
            papersafe.get_db().commit()

        failed_logout = self.client.post(
            "/logout", data={"csrf_token": self.csrf_token()}
        )
        self.assertEqual(failed_logout.status_code, 500)
        self.assertNotIn(b"logged out", failed_logout.data.lower())
        self.assertEqual(self.client.get("/documents").status_code, 200)

    def test_upload_and_title_search_treats_sqli_as_text(self):
        self.register("alice")
        self.login("alice")
        uploaded = self.create_pdf("private notes")
        self.assertIn(b"PDF uploaded", uploaded.data)

        ordinary = self.client.get("/documents", query_string={"q": "private"})
        self.assertIn(b"private notes", ordinary.data)
        payload = self.client.get(
            "/documents", query_string={"q": "' OR '1'='1' --"}
        )
        self.assertIn(b"No documents match your search", payload.data)
        self.assertNotIn(b"private notes", payload.data)

    def test_csrf_rejects_state_change_without_token(self):
        response = self.client.post(
            "/register",
            data={"username": "alice", "password": "Synthetic-password-2026!"},
        )
        self.assertEqual(response.status_code, 400)

    def test_upload_rejects_wrong_type_and_one_byte_over_file_limit(self):
        self.register("alice")
        self.login("alice")

        before = self.upload_state()
        wrong_extension = self.client.post(
            "/upload",
            data={"csrf_token": self.csrf_token("/upload"),
                  "pdf": (BytesIO(SAMPLE_PDF), "sample.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(wrong_extension.status_code, 302)
        self.assertEqual(self.upload_state(), before)

        before = self.upload_state()
        wrong_content = self.client.post(
            "/upload",
            data={"csrf_token": self.csrf_token("/upload"),
                  "pdf": (BytesIO(b"not a PDF"), "fake.pdf")},
            content_type="multipart/form-data",
        )
        self.assertEqual(wrong_content.status_code, 302)
        self.assertEqual(self.upload_state(), before)

        before = self.upload_state()
        oversized = self.client.post(
            "/upload",
            data={"csrf_token": self.csrf_token("/upload"),
                  "pdf": (BytesIO(b"%PDF-" + b"X" * (papersafe.MAX_UPLOAD_BYTES - 4)), "large.pdf")},
            content_type="multipart/form-data",
        )
        self.assertEqual(oversized.status_code, 302)
        self.assertEqual(self.upload_state(), before)

    def upload_state(self):
        with papersafe.app.app_context():
            count = papersafe.get_db().execute(
                "SELECT COUNT(*) FROM documents"
            ).fetchone()[0]
        stored_files = sorted(
            path.name for path in Path(papersafe.app.config["UPLOAD_FOLDER"]).iterdir()
        )
        return count, stored_files

    def test_upload_accepts_files_through_exact_10_mib_boundary(self):
        self.register("alice")
        self.login("alice")

        for label, size in (
            ("just below", papersafe.MAX_UPLOAD_BYTES - 1),
            ("exactly", papersafe.MAX_UPLOAD_BYTES),
        ):
            before_count, before_files = self.upload_state()
            response = self.client.post(
                "/upload",
                data={
                    "csrf_token": self.csrf_token("/upload"),
                    "title": f"{label} 10 MiB",
                    "pdf": (BytesIO(b"%PDF-" + b"X" * (size - 5)), f"{label}.pdf"),
                },
                content_type="multipart/form-data",
            )
            self.assertEqual(response.status_code, 302)
            after_count, after_files = self.upload_state()
            self.assertEqual(after_count, before_count + 1)
            self.assertEqual(len(after_files), len(before_files) + 1)
            with papersafe.app.app_context():
                saved_size = papersafe.get_db().execute(
                    "SELECT size_bytes FROM documents WHERE title = ?",
                    (f"{label} 10 MiB",),
                ).fetchone()[0]
            self.assertEqual(saved_size, size)

    def test_upload_rejects_request_overall_limit_without_state_change(self):
        self.register("alice")
        self.login("alice")
        before = self.upload_state()
        request_over_limit = papersafe.app.config["MAX_CONTENT_LENGTH"]
        response = self.client.post(
            "/upload",
            data={
                "csrf_token": self.csrf_token("/upload"),
                "title": "request over limit",
                "pdf": (
                    BytesIO(b"%PDF-" + b"X" * (request_over_limit - 4)),
                    "request-over-limit.pdf",
                ),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(self.upload_state(), before)

    def test_owner_shares_and_revokes_without_granting_recipient_owner_rights(self):
        self.register("alice")
        self.login("alice")
        self.create_pdf("Alice private report")
        document_id = self.document_id("Alice private report")

        # Unshared documents remain private and cannot be downloaded or deleted.
        with self.client.session_transaction() as session:
            session.clear()
        self.register("bob")
        self.login("bob")
        self.assertNotIn(b"Alice private report", self.client.get("/documents").data)
        self.assertEqual(self.client.get(f"/documents/{document_id}/download").status_code, 404)
        delete = self.client.post(
            f"/documents/{document_id}/delete",
            data={"csrf_token": self.csrf_token()},
        )
        self.assertEqual(delete.status_code, 404)

        # Owner shares; recipient can list/download, but cannot delete or re-share.
        with self.client.session_transaction() as session:
            session.clear()
        self.login("alice")
        share_response = self.client.post(
            f"/documents/{document_id}/shares",
            data={"csrf_token": self.csrf_token(), "action": "share", "username": "bob"},
        )
        self.assertEqual(share_response.status_code, 302)

        with self.client.session_transaction() as session:
            session.clear()
        self.login("bob")
        shared_list = self.client.get("/documents")
        self.assertIn(b"Alice private report", shared_list.data)
        self.assertIn(b"Shared by alice", shared_list.data)
        download = self.client.get(f"/documents/{document_id}/download")
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.data, SAMPLE_PDF)
        download.close()

        delete = self.client.post(
            f"/documents/{document_id}/delete",
            data={"csrf_token": self.csrf_token()},
        )
        self.assertEqual(delete.status_code, 404)
        reshare = self.client.post(
            f"/documents/{document_id}/shares",
            data={"csrf_token": self.csrf_token(), "action": "share", "username": "charlie"},
        )
        self.assertEqual(reshare.status_code, 404)

        # Owner revokes access; the recipient immediately loses list/download access.
        with self.client.session_transaction() as session:
            session.clear()
        self.login("alice")
        with papersafe.app.app_context():
            recipient_id = papersafe.get_db().execute(
                "SELECT id FROM users WHERE username = ?", ("bob",)
            ).fetchone()["id"]
        revoke = self.client.post(
            f"/documents/{document_id}/shares",
            data={"csrf_token": self.csrf_token(), "action": "revoke",
                  "recipient_id": recipient_id},
        )
        self.assertEqual(revoke.status_code, 302)

        with self.client.session_transaction() as session:
            session.clear()
        self.login("bob")
        self.assertNotIn(b"Alice private report", self.client.get("/documents").data)
        self.assertEqual(self.client.get(f"/documents/{document_id}/download").status_code, 404)

    def test_share_edge_cases_and_csrf(self):
        self.register("alice")
        self.login("alice")
        self.create_pdf("Edge case document")
        document_id = self.document_id("Edge case document")
        endpoint = f"/documents/{document_id}/shares"

        missing_csrf = self.client.post(
            endpoint, data={"action": "share", "username": "bob"}
        )
        self.assertEqual(missing_csrf.status_code, 400)

        missing_user = self.client.post(
            endpoint,
            data={"csrf_token": self.csrf_token(), "action": "share", "username": "nobody"},
            follow_redirects=True,
        )
        self.assertIn(b"No account", missing_user.data)

        self_share = self.client.post(
            endpoint,
            data={"csrf_token": self.csrf_token(), "action": "share", "username": "alice"},
            follow_redirects=True,
        )
        self.assertIn(b"already available to its owner", self_share.data)

        self.register("bob")
        first = self.client.post(
            endpoint,
            data={"csrf_token": self.csrf_token(), "action": "share", "username": "bob"},
            follow_redirects=True,
        )
        self.assertIn(b"Document shared", first.data)
        duplicate = self.client.post(
            endpoint,
            data={"csrf_token": self.csrf_token(), "action": "share", "username": "bob"},
            follow_redirects=True,
        )
        self.assertIn(b"already shared", duplicate.data)

        with papersafe.app.app_context():
            count = papersafe.get_db().execute(
                "SELECT COUNT(*) FROM document_shares WHERE document_id = ?", (document_id,)
            ).fetchone()[0]
            alice_id = papersafe.get_db().execute(
                "SELECT id FROM users WHERE username = ?", ("alice",)
            ).fetchone()["id"]
            with self.assertRaises(sqlite3.IntegrityError):
                papersafe.get_db().execute(
                    "INSERT INTO document_shares (document_id, recipient_id) VALUES (?, ?)",
                    (document_id, alice_id),
                )
            papersafe.get_db().rollback()
        self.assertEqual(count, 1)

    def test_demo_seed_is_repeatable_and_provides_shared_sample(self):
        papersafe.seed_demo_data()
        papersafe.seed_demo_data()
        with papersafe.app.app_context():
            users = papersafe.get_db().execute(
                "SELECT COUNT(*) FROM users WHERE username IN ('alice', 'bob')"
            ).fetchone()[0]
            document = papersafe.get_db().execute(
                """SELECT d.id, d.stored_name, d.owner_id, s.recipient_id
                   FROM documents AS d JOIN document_shares AS s ON s.document_id = d.id
                   WHERE d.title = ?""",
                (papersafe.DEMO_TITLE,),
            ).fetchone()
            share_count = papersafe.get_db().execute(
                "SELECT COUNT(*) FROM document_shares WHERE document_id = ?",
                (document["id"],),
            ).fetchone()[0]
        self.assertEqual(users, 2)
        self.assertIsNotNone(document)
        self.assertEqual(share_count, 1)
        self.assertEqual(
            (Path(papersafe.app.config["UPLOAD_FOLDER"]) / document["stored_name"]).read_bytes(),
            SAMPLE_PDF,
        )

    def test_non_development_requires_configured_secret(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as temp_dir:
            with self.assertRaisesRegex(RuntimeError, "PDF_APP_SECRET must be set"):
                papersafe.resolve_secret_key("production", None, Path(temp_dir) / "secret")

    def test_development_secret_is_random_and_persisted(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as temp_dir:
            secret_file = Path(temp_dir) / "instance" / ".flask_secret"
            first = papersafe.resolve_secret_key("development", None, secret_file)
            second = papersafe.resolve_secret_key("development", None, secret_file)
            self.assertGreaterEqual(len(first), 40)
            self.assertEqual(first, second)
            self.assertEqual(
                papersafe.resolve_secret_key("production", "provided-secret", secret_file),
                "provided-secret",
            )


if __name__ == "__main__":
    unittest.main()

