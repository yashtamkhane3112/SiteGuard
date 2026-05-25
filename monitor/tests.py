from datetime import timedelta
import io
import os
import shutil
import tempfile
import base64
import smtplib

from unittest.mock import Mock, patch

import requests
from cloudinary_storage.storage import RawMediaCloudinaryStorage
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.sessions.models import Session
from django.core import mail
from django.core.management import call_command
from django.core.management.base import CommandError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.exceptions import ImproperlyConfigured
from django.db import IntegrityError, transaction
from django.test.client import RequestFactory
from django.test import TestCase, override_settings
from django.urls import resolve, reverse
from django.utils import timezone

from monitor.apps import (
    log_ai_startup_diagnostics,
    log_database_startup_diagnostics,
    log_analyzer_storage_startup_diagnostics,
    log_session_startup_diagnostics,
)
from monitor.emailing import build_password_reset_email_options, get_email_base_url, send_siteguard_email
from monitor.error_analyzer import parse_log_content
from monitor.forms import ProfileUpdateForm, SiteGuardPasswordResetForm
from monitor.ai.prompts.builders import build_ai_instructions, build_report_prompt, sanitize_text
from monitor.ai.providers.base import AIProviderError, AIProviderUnavailable
from monitor.ai.providers.gemini_provider import GeminiProvider
from monitor.ai.providers.registry import get_default_provider
from monitor.ai.services.analysis import generate_report_analysis, get_report_ai_state
from monitor.models import AIAnalysisCache, Alert, Incident, IncidentEvent, MonitorLog, Notification, ParsedError, UploadedLog, UserProfile, Website
from monitor.storage import AnalyzerUploadStorage, get_uploaded_log_storage, get_uploaded_log_storage_metadata
from siteguard.settings.base import _normalize_config_text
from siteguard.settings.validation import (
    build_production_database_config,
    build_sqlite_database_config,
    get_database_configuration_diagnostics,
    validate_production_configuration,
)
from monitor.utils import (
    analyze_domain,
    build_notification_activity_center,
    cleanup_monitoring_state,
    create_or_update_alert,
    create_notification_from_alert,
    get_favicon_url,
    get_notification_destination,
    get_recent_notifications,
    get_site_status,
    get_user_account_snapshot,
    normalize_domain_display,
    run_single_check,
    safe_url_decode,
    safe_url_encode,
    sync_incident_state,
)
from monitor.views import SiteGuardPasswordResetView, build_reports_context


TEST_PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg=="
)


class AuthFlowTests(TestCase):
    def setUp(self):
        self.request_factory = RequestFactory()

    def test_login_page_creates_default_admin_user(self):
        with self.settings(BOOTSTRAP_ADMIN_ENABLED=True):
            self.client.get(reverse("login"))

        admin_user = User.objects.get(username="admin")
        self.assertEqual(admin_user.email, "admin@example.com")
        self.assertTrue(admin_user.check_password("admin123"))
        self.assertTrue(admin_user.is_superuser)

    def test_login_page_does_not_create_default_admin_when_bootstrap_disabled(self):
        with self.settings(BOOTSTRAP_ADMIN_ENABLED=False):
            self.client.get(reverse("login"))

        self.assertFalse(User.objects.filter(username="admin").exists())

    def test_dashboard_redirects_anonymous_user_to_login(self):
        response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/login/?next=/dashboard/")

    def test_signup_creates_user_and_redirects_to_login(self):
        response = self.client.post(
            reverse("signup"),
            {
                "username": "newuser",
                "password1": "StrongPass123!",
                "password2": "StrongPass123!",
            },
        )

        self.assertRedirects(response, reverse("login"))
        self.assertTrue(User.objects.filter(username="newuser").exists())

    def test_login_redirects_to_dashboard_for_valid_credentials(self):
        User.objects.create_user(username="tester", password="StrongPass123!")

        response = self.client.post(
            reverse("login"),
            {
                "username": "tester",
                "password": "StrongPass123!",
            },
        )

        self.assertRedirects(response, reverse("dashboard"))

    def test_login_sets_persistent_session_cookie_by_default(self):
        User.objects.create_user(username="tester", password="StrongPass123!")

        response = self.client.post(
            reverse("login"),
            {
                "username": "tester",
                "password": "StrongPass123!",
                "remember_me": "on",
            },
        )

        self.assertRedirects(response, reverse("dashboard"))
        self.assertGreaterEqual(self.client.session.get_expiry_age(), settings.SESSION_COOKIE_AGE - 5)
        self.assertFalse(self.client.session.get_expire_at_browser_close())

    def test_login_remember_me_can_be_disabled_for_browser_session_only(self):
        User.objects.create_user(username="tester", password="StrongPass123!")

        response = self.client.post(
            reverse("login"),
            {
                "username": "tester",
                "password": "StrongPass123!",
                "remember_me": "",
            },
        )

        session_cookie = response.cookies[settings.SESSION_COOKIE_NAME]
        self.assertRedirects(response, reverse("dashboard"))
        self.assertEqual(session_cookie.get("max-age", ""), "")
        self.assertTrue(self.client.session.get_expire_at_browser_close())

    def test_authenticated_session_persists_across_new_client_with_same_cookie(self):
        user = User.objects.create_user(username="tester", password="StrongPass123!")

        login_response = self.client.post(
            reverse("login"),
            {
                "username": "tester",
                "password": "StrongPass123!",
                "remember_me": "on",
            },
        )

        self.assertRedirects(login_response, reverse("dashboard"))
        fresh_client = self.client_class()
        fresh_client.cookies = self.client.cookies

        response = fresh_client.get(reverse("dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(int(fresh_client.session["_auth_user_id"]), user.id)

    @override_settings(SESSION_ENGINE="django.contrib.sessions.backends.db")
    def test_authenticated_routes_survive_multiple_requests_with_db_sessions(self):
        User.objects.create_user(username="tester", password="StrongPass123!")

        login_response = self.client.post(
            reverse("login"),
            {
                "username": "tester",
                "password": "StrongPass123!",
                "remember_me": "on",
            },
        )

        self.assertRedirects(login_response, reverse("dashboard"))
        first = self.client.get(reverse("dashboard"))
        second = self.client.get(reverse("alerts"))
        third = self.client.get(reverse("reports"))

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(third.status_code, 200)

    @override_settings(SESSION_ENGINE="django.contrib.sessions.backends.db")
    def test_db_session_survives_worker_reload_simulation(self):
        user = User.objects.create_user(username="tester", password="StrongPass123!")

        login_response = self.client.post(
            reverse("login"),
            {
                "username": "tester",
                "password": "StrongPass123!",
                "remember_me": "on",
            },
        )

        self.assertRedirects(login_response, reverse("dashboard"))
        session_key = self.client.session.session_key
        self.assertTrue(Session.objects.filter(session_key=session_key).exists())

        reloaded_client = self.client_class()
        reloaded_client.cookies = self.client.cookies

        dashboard_response = reloaded_client.get(reverse("dashboard"))

        self.assertEqual(dashboard_response.status_code, 200)
        self.assertEqual(int(reloaded_client.session["_auth_user_id"]), user.id)

    @override_settings(SESSION_ENGINE="django.contrib.sessions.backends.db")
    def test_logout_clears_database_session(self):
        User.objects.create_user(username="tester", password="StrongPass123!")
        self.client.post(
            reverse("login"),
            {
                "username": "tester",
                "password": "StrongPass123!",
                "remember_me": "on",
            },
        )
        session_key = self.client.session.session_key
        self.assertTrue(Session.objects.filter(session_key=session_key).exists())

        response = self.client.get(reverse("logout"))

        self.assertRedirects(response, reverse("login"))
        self.assertFalse(Session.objects.filter(session_key=session_key).exists())

    def test_login_stays_on_page_for_invalid_credentials(self):
        User.objects.create_user(username="tester", password="StrongPass123!")

        response = self.client.post(
            reverse("login"),
            {
                "username": "tester",
                "password": "wrong-password",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid username or password.")

    def test_logout_redirects_to_login_and_clears_session(self):
        User.objects.create_user(username="tester", password="StrongPass123!")
        self.client.login(username="tester", password="StrongPass123!")

        response = self.client.get(reverse("logout"))

        self.assertRedirects(response, reverse("login"))
        dashboard_response = self.client.get(reverse("dashboard"))
        self.assertEqual(dashboard_response.status_code, 302)
        self.assertEqual(dashboard_response.url, "/login/?next=/dashboard/")

    @override_settings(
        SESSION_ENGINE="django.contrib.sessions.backends.signed_cookies",
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE="Lax",
        CSRF_COOKIE_SECURE=True,
        SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"),
        USE_X_FORWARDED_HOST=True,
        ALLOWED_HOSTS=["testserver", "siteguard.onrender.com"],
    )
    def test_login_sets_secure_cookie_and_honors_render_proxy_https(self):
        User.objects.create_user(username="tester", password="StrongPass123!")

        with patch("monitor.views.logger.info") as mock_info:
            response = self.client.post(
                reverse("login"),
                {
                    "username": "tester",
                    "password": "StrongPass123!",
                    "remember_me": "on",
                },
                HTTP_X_FORWARDED_PROTO="https",
                HTTP_X_FORWARDED_HOST="siteguard.onrender.com",
                HTTP_HOST="siteguard.onrender.com",
            )

        session_cookie = response.cookies[settings.SESSION_COOKIE_NAME]
        self.assertRedirects(response, reverse("dashboard"))
        self.assertTrue(session_cookie["secure"])
        self.assertEqual(session_cookie["samesite"], "Lax")
        auth_log_call = next(
            call for call in mock_info.call_args_list
            if call.args and call.args[0] == "User login established session."
        )
        self.assertTrue(auth_log_call.kwargs["extra"]["auth_context"]["request_is_secure"])
        self.assertEqual(auth_log_call.kwargs["extra"]["auth_context"]["forwarded_proto"], "https")
        self.assertEqual(auth_log_call.kwargs["extra"]["auth_context"]["host"], "siteguard.onrender.com")

        dashboard_response = self.client.get(
            reverse("dashboard"),
            HTTP_X_FORWARDED_PROTO="https",
            HTTP_X_FORWARDED_HOST="siteguard.onrender.com",
            HTTP_HOST="siteguard.onrender.com",
        )
        self.assertEqual(dashboard_response.status_code, 200)

    def test_password_reset_page_renders(self):
        response = self.client.get(reverse("password_reset"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Reset Password")

    def test_password_reset_route_uses_custom_view_and_form(self):
        match = resolve(reverse("password_reset"))

        self.assertIs(match.func.view_class, SiteGuardPasswordResetView)
        self.assertIs(match.func.view_class.form_class, SiteGuardPasswordResetForm)

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_password_reset_request_sends_email_for_known_user(self):
        User.objects.create_user(
            username="reset-user",
            password="StrongPass123!",
            email="reset@example.com",
        )

        response = self.client.post(
            reverse("password_reset"),
            {"email": "reset@example.com"},
        )

        self.assertRedirects(response, reverse("password_reset_done"))
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, "[SiteGuard] Password reset instructions for SiteGuard")
        self.assertIn("text/html", [alternative[1] for alternative in mail.outbox[0].alternatives])

    @override_settings(
        EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
        APP_BASE_URL="https://siteguard.onrender.com",
        CANONICAL_BASE_URL="https://siteguard.onrender.com",
        SUPPORT_EMAIL="support@siteguard.example",
    )
    def test_password_reset_email_uses_canonical_https_render_link(self):
        User.objects.create_user(
            username="reset-user",
            password="StrongPass123!",
            email="reset@example.com",
        )

        response = self.client.post(
            reverse("password_reset"),
            {"email": "reset@example.com"},
        )

        self.assertRedirects(response, reverse("password_reset_done"))
        self.assertEqual(len(mail.outbox), 1)
        body = mail.outbox[0].body
        self.assertIn("https://siteguard.onrender.com/reset/", body)
        self.assertNotIn("http://testserver", body)
        self.assertNotIn("localhost", body.lower())

    @override_settings(
        EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
        DEBUG=True,
        APP_BASE_URL="https://siteguard.onrender.com",
        CANONICAL_BASE_URL="https://siteguard.onrender.com",
    )
    def test_password_reset_email_uses_request_host_during_local_development(self):
        User.objects.create_user(
            username="reset-user",
            password="StrongPass123!",
            email="reset@example.com",
        )

        response = self.client.post(
            reverse("password_reset"),
            {"email": "reset@example.com"},
            HTTP_HOST="127.0.0.1:8000",
        )

        self.assertRedirects(response, reverse("password_reset_done"))
        self.assertEqual(len(mail.outbox), 1)
        body = mail.outbox[0].body
        self.assertIn("http://127.0.0.1:8000/reset/", body)
        self.assertNotIn("https://siteguard.onrender.com/reset/", body)

    @override_settings(
        DEBUG=True,
        APP_BASE_URL="https://siteguard.onrender.com",
        CANONICAL_BASE_URL="https://siteguard.onrender.com",
    )
    def test_password_reset_email_options_fall_back_to_localhost_without_request_in_debug(self):
        options = build_password_reset_email_options()

        self.assertEqual(options["domain_override"], "127.0.0.1:8000")
        self.assertFalse(options["use_https"])
        self.assertEqual(options["extra_email_context"]["resolved_base_url"], "http://127.0.0.1:8000")

    @override_settings(
        DEBUG=True,
        APP_BASE_URL="https://siteguard.onrender.com",
        CANONICAL_BASE_URL="https://siteguard.onrender.com",
    )
    def test_email_base_url_uses_request_host_in_debug(self):
        request = self.request_factory.get("/password-reset/", HTTP_HOST="localhost:8000")

        self.assertEqual(get_email_base_url(request), "http://localhost:8000")

    @patch("monitor.forms.send_siteguard_email", return_value=False)
    def test_password_reset_send_failure_does_not_break_request(self, _mock_send_email):
        User.objects.create_user(
            username="reset-user",
            password="StrongPass123!",
            email="reset@example.com",
        )

        response = self.client.post(
            reverse("password_reset"),
            {"email": "reset@example.com"},
        )

        self.assertRedirects(response, reverse("password_reset_done"))


class AdminStabilityTests(TestCase):
    def setUp(self):
        self.temp_media_root = tempfile.mkdtemp()
        self.media_override = override_settings(MEDIA_ROOT=self.temp_media_root)
        self.media_override.enable()
        self.admin_user = User.objects.create_superuser(
            username="admin-user",
            email="admin@example.com",
            password="StrongPass123!",
        )
        self.client.login(username="admin-user", password="StrongPass123!")
        self.regular_user = User.objects.create_user(
            username="staff-target",
            password="StrongPass123!",
        )
        self.website = Website.objects.create(user=self.regular_user, url="https://example.com")
        self.uploaded_log = UploadedLog.objects.create(
            user=self.regular_user,
            filename="server.log",
            file=SimpleUploadedFile("server.log", b"line one", content_type="text/plain"),
            processed=True,
        )
        ParsedError.objects.create(
            uploaded_log=self.uploaded_log,
            error_type="ValueError",
            raw_line="ValueError: invalid payload",
            count=2,
            first_seen_line=14,
        )
        Alert.objects.create(
            website=self.website,
            alert_type=Alert.TYPE_DOWN,
            status=Alert.STATUS_SENT,
            message="example.com is DOWN",
        )

    def tearDown(self):
        self.media_override.disable()
        shutil.rmtree(self.temp_media_root, ignore_errors=True)

    def test_admin_alert_and_parsed_error_changelists_render(self):
        alert_response = self.client.get(reverse("admin:monitor_alert_changelist"))
        parsed_error_response = self.client.get(reverse("admin:monitor_parsederror_changelist"))

        self.assertEqual(alert_response.status_code, 200)
        self.assertEqual(parsed_error_response.status_code, 200)
        self.assertContains(alert_response, "example.com")
        self.assertContains(parsed_error_response, "ValueError")


class OperationsDashboardTests(TestCase):
    def setUp(self):
        self.temp_media_root = tempfile.mkdtemp()
        self.media_override = override_settings(MEDIA_ROOT=self.temp_media_root)
        self.media_override.enable()
        self.internal_user = User.objects.create_superuser(
            username="ops-admin",
            email="ops@example.com",
            password="StrongPass123!",
        )
        self.regular_user = User.objects.create_user(
            username="member-user",
            password="StrongPass123!",
            email="member@example.com",
        )
        self.website = Website.objects.create(user=self.regular_user, url="https://example.com")
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_UP, response_time=124.6)
        Alert.objects.create(
            website=self.website,
            alert_type=Alert.TYPE_DOWN,
            status=Alert.STATUS_FAILED,
            sent_to="member@example.com",
            message="example.com alert delivery failed",
        )
        upload = UploadedLog.objects.create(
            user=self.regular_user,
            filename="runtime.log",
            file=SimpleUploadedFile("runtime.log", b"ValueError: invalid payload", content_type="text/plain"),
            processed=True,
        )
        ParsedError.objects.create(
            uploaded_log=upload,
            error_type="ValueError",
            raw_line="ValueError: invalid payload",
            count=3,
            first_seen_line=22,
            last_seen_line=24,
            category=ParsedError.CATEGORY_DJANGO,
            severity=ParsedError.SEVERITY_HIGH,
        )

    def tearDown(self):
        self.media_override.disable()
        shutil.rmtree(self.temp_media_root, ignore_errors=True)

    def test_operations_dashboard_requires_internal_access(self):
        self.client.login(username="member-user", password="StrongPass123!")

        response = self.client.get(reverse("operations_dashboard"))

        self.assertEqual(response.status_code, 404)

    def test_operations_dashboard_renders_internal_snapshot(self):
        self.client.login(username="ops-admin", password="StrongPass123!")

        response = self.client.get(reverse("operations_dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Operational Health")
        self.assertContains(response, "Core Services")
        self.assertContains(response, "Recent Monitor Execution History")
        self.assertContains(response, "Recent Exception Summaries")
        self.assertContains(response, "example.com")

    def test_favicon_route_redirects_to_static_asset(self):
        response = self.client.get("/favicon.ico")

        self.assertEqual(response.status_code, 301)
        self.assertEqual(response["Location"], "/static/favicon.svg")


class ErrorAnalyzerTests(TestCase):
    def setUp(self):
        self.temp_media_root = tempfile.mkdtemp()
        self.media_override = override_settings(MEDIA_ROOT=self.temp_media_root)
        self.media_override.enable()
        self.user = User.objects.create_user(
            username="analyzer-user",
            password="StrongPass123!",
        )
        self.client.login(username="analyzer-user", password="StrongPass123!")

    def tearDown(self):
        self.media_override.disable()
        shutil.rmtree(self.temp_media_root, ignore_errors=True)

    def test_parse_log_content_classifies_category_severity_and_line_ranges(self):
        parsed = parse_log_content(
            "\n".join([
                "Traceback (most recent call last):",
                '  File "app.py", line 10, in <module>',
                "django.db.utils.OperationalError: database is locked",
                "GET /missing 404",
                "Request timeout reached while calling upstream service",
            ])
        )

        first_error = parsed["parsed_errors"][0]
        self.assertEqual(first_error["category"], ParsedError.CATEGORY_DATABASE)
        self.assertEqual(first_error["severity"], ParsedError.SEVERITY_CRITICAL)
        self.assertEqual(first_error["first_seen_line"], 1)
        self.assertEqual(first_error["last_seen_line"], 3)
        self.assertTrue(any(item["category"] == ParsedError.CATEGORY_HTTP for item in parsed["parsed_errors"]))
        self.assertTrue(any(item["category"] == ParsedError.CATEGORY_TIMEOUT for item in parsed["parsed_errors"]))

    def test_error_analyzer_results_show_classification_and_guidance(self):
        uploaded_log = UploadedLog.objects.create(
            user=self.user,
            filename="server.log",
            file=SimpleUploadedFile(
                "server.log",
                b"Traceback (most recent call last):\ndjango.db.utils.OperationalError: database is locked\n",
                content_type="text/plain",
            ),
            processed=True,
        )
        ParsedError.objects.create(
            uploaded_log=uploaded_log,
            error_type="OperationalError",
            raw_line="django.db.utils.OperationalError: database is locked",
            count=3,
            first_seen_line=1,
            last_seen_line=2,
            category=ParsedError.CATEGORY_DATABASE,
            severity=ParsedError.SEVERITY_CRITICAL,
        )

        response = self.client.get(reverse("error_log_results", args=[uploaded_log.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Database")
        self.assertContains(response, "Critical")
        self.assertContains(response, "Probable Cause")
        self.assertContains(response, "Run pending migrations")

    def test_error_analyzer_results_show_investigation_workspace_controls(self):
        uploaded_log = UploadedLog.objects.create(
            user=self.user,
            filename="multi.log",
            file=SimpleUploadedFile(
                "multi.log",
                b"\n".join([
                    b"2026-05-14 10:16:00 GET /api/orders 500",
                    b"Traceback (most recent call last):",
                    b'  File "app.py", line 10, in <module>',
                    b"django.db.utils.OperationalError: database is locked",
                    b"2026-05-14 10:17:00 GET /api/orders 500",
                    b"django.db.utils.OperationalError: database is locked",
                ]),
                content_type="text/plain",
            ),
            processed=True,
        )
        ParsedError.objects.create(
            uploaded_log=uploaded_log,
            error_type="OperationalError",
            raw_line="django.db.utils.OperationalError: database is locked",
            count=2,
            first_seen_line=2,
            last_seen_line=6,
            category=ParsedError.CATEGORY_DATABASE,
            severity=ParsedError.SEVERITY_CRITICAL,
        )

        response = self.client.get(reverse("error_log_results", args=[uploaded_log.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Operational Timeline")
        self.assertContains(response, "Recurring Error Groups")
        self.assertContains(response, "Copy Traceback")
        self.assertContains(response, "Likely root cause")
        self.assertContains(response, "Recurring only")

    def test_reports_view_includes_error_analytics_section(self):
        uploaded_log = UploadedLog.objects.create(
            user=self.user,
            filename="nginx.log",
            file=SimpleUploadedFile("nginx.log", b"404 route missing", content_type="text/plain"),
            processed=True,
        )
        ParsedError.objects.create(
            uploaded_log=uploaded_log,
            error_type="HTTP 404",
            raw_line="404 route missing",
            count=2,
            first_seen_line=5,
            last_seen_line=5,
            category=ParsedError.CATEGORY_HTTP,
            severity=ParsedError.SEVERITY_LOW,
        )

        response = self.client.get(reverse("reports"))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["error_analytics"]["has_data"])
        self.assertContains(response, "Error Analytics")
        self.assertContains(response, "HTTP 404")

    def test_error_log_upload_accepts_log_files_and_attaches_to_record(self):
        response = self.client.post(
            reverse("error_log_upload"),
            {
                "file": SimpleUploadedFile(
                    "runtime.log",
                    b"TimeoutError: upstream timed out\nTimeoutError: upstream timed out\n",
                    content_type="text/plain",
                )
            },
        )

        uploaded_log = UploadedLog.objects.get(user=self.user, filename="runtime.log")
        self.assertRedirects(response, reverse("error_log_results", args=[uploaded_log.id]))
        self.assertTrue(uploaded_log.processed)
        self.assertTrue(uploaded_log.parsed_errors.exists())

    def test_error_log_upload_accepts_txt_files(self):
        response = self.client.post(
            reverse("error_log_upload"),
            {
                "file": SimpleUploadedFile(
                    "runtime.txt",
                    b"django.db.utils.OperationalError: database is locked\n",
                    content_type="text/plain",
                )
            },
        )

        uploaded_log = UploadedLog.objects.get(user=self.user, filename="runtime.txt")
        self.assertRedirects(response, reverse("error_log_results", args=[uploaded_log.id]))
        self.assertTrue(uploaded_log.processed)

    def test_error_log_upload_accepts_json_diagnostics(self):
        response = self.client.post(
            reverse("error_log_upload"),
            {
                "file": SimpleUploadedFile(
                    "runtime.json",
                    b'{"error":"TimeoutError","message":"upstream timed out"}',
                    content_type="application/json",
                )
            },
        )

        uploaded_log = UploadedLog.objects.get(user=self.user, filename="runtime.json")
        self.assertRedirects(response, reverse("error_log_results", args=[uploaded_log.id]))
        self.assertTrue(uploaded_log.processed)

    def test_error_log_upload_rejects_invalid_binary_payload(self):
        response = self.client.post(
            reverse("error_log_upload"),
            {
                "file": SimpleUploadedFile(
                    "payload.exe",
                    b"MZ\x00\x00binary",
                    content_type="application/x-msdownload",
                )
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Only .txt, .log, and .json diagnostic files are supported.")
        self.assertEqual(UploadedLog.objects.filter(user=self.user).count(), 0)

    @override_settings(
        STORAGES={
            "default": {"BACKEND": "cloudinary_storage.storage.MediaCloudinaryStorage"},
            "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
        }
    )
    def test_uploaded_log_field_uses_analyzer_storage_wrapper(self):
        storage = UploadedLog._meta.get_field("file").storage

        self.assertIsInstance(storage, AnalyzerUploadStorage)

    @override_settings(
        STORAGES={
            "default": {"BACKEND": "cloudinary_storage.storage.MediaCloudinaryStorage"},
            "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
        }
    )
    def test_error_log_upload_uses_cloudinary_raw_storage_in_production_mode(self):
        storage = get_uploaded_log_storage()
        delegate = storage.get_delegate_storage()
        metadata = get_uploaded_log_storage_metadata()

        self.assertIsInstance(storage, AnalyzerUploadStorage)
        self.assertIs(delegate.__class__, RawMediaCloudinaryStorage)
        self.assertEqual(delegate.RESOURCE_TYPE, "raw")
        self.assertEqual(metadata["resource_type"], "raw")
        self.assertEqual(metadata["delegate_class"], "cloudinary_storage.storage.RawMediaCloudinaryStorage")

    def test_avatar_field_storage_remains_separate_from_analyzer_storage(self):
        storage = UserProfile._meta.get_field("avatar").storage

        self.assertNotIsInstance(storage, AnalyzerUploadStorage)

    def test_error_log_results_render_after_upload(self):
        upload_response = self.client.post(
            reverse("error_log_upload"),
            {
                "file": SimpleUploadedFile(
                    "renderable.log",
                    b"Traceback (most recent call last):\ndjango.db.utils.OperationalError: database is locked\n",
                    content_type="text/plain",
                )
            },
        )

        uploaded_log = UploadedLog.objects.get(user=self.user, filename="renderable.log")
        results_response = self.client.get(reverse("error_log_results", args=[uploaded_log.id]))

        self.assertRedirects(upload_response, reverse("error_log_results", args=[uploaded_log.id]))
        self.assertEqual(results_response.status_code, 200)
        self.assertContains(results_response, "renderable.log")
        self.assertContains(results_response, "OperationalError")

    @patch("monitor.views.process_uploaded_log", side_effect=RuntimeError("cloud storage unavailable"))
    @patch("monitor.views.logger.exception")
    def test_error_log_upload_failure_is_handled_gracefully(self, mock_exception, _mock_process):
        response = self.client.post(
            reverse("error_log_upload"),
            {
                "file": SimpleUploadedFile(
                    "failed.log",
                    b"TimeoutError: upstream timed out\n",
                    content_type="text/plain",
                )
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "The diagnostic file could not be stored or analyzed right now.")
        self.assertEqual(UploadedLog.objects.filter(user=self.user, filename="failed.log").count(), 0)
        mock_exception.assert_called_once()

    @patch("monitor.views.logger.warning")
    def test_error_log_upload_rejects_unavailable_storage_gracefully(self, mock_warning):
        storage = UploadedLog._meta.get_field("file").storage
        with patch.object(storage, "get_debug_metadata", return_value={
            "storage_class": "monitor.storage.AnalyzerUploadStorage",
            "delegate_class": "",
            "resource_type": "",
            "active_media_backend": "cloudinary_storage.storage.MediaCloudinaryStorage",
            "available": False,
            "error": "Analyzer upload storage resolved to a non-raw Cloudinary backend.",
        }):
            response = self.client.post(
                reverse("error_log_upload"),
                {
                    "file": SimpleUploadedFile(
                        "failed.log",
                        b"TimeoutError: upstream timed out\n",
                        content_type="text/plain",
                    )
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "storage backend is not available right now")
        self.assertEqual(UploadedLog.objects.filter(user=self.user, filename="failed.log").count(), 0)
        mock_warning.assert_called_once()

    def test_error_analyzer_results_include_ai_explain_panel(self):
        uploaded_log = UploadedLog.objects.create(
            user=self.user,
            filename="server.log",
            file=SimpleUploadedFile("server.log", b"TimeoutError: upstream timed out", content_type="text/plain"),
            processed=True,
        )
        ParsedError.objects.create(
            uploaded_log=uploaded_log,
            error_type="TimeoutError",
            raw_line="TimeoutError: upstream timed out",
            count=3,
            first_seen_line=1,
            category=ParsedError.CATEGORY_TIMEOUT,
            severity=ParsedError.SEVERITY_HIGH,
        )

        response = self.client.get(reverse("error_log_results", args=[uploaded_log.id]))

        self.assertEqual(response.status_code, 200)
        self.assertIn("ai_error_state", response.context)
        self.assertContains(response, "Explain with AI")

    @override_settings(AI_FEATURES_ENABLED=True, GEMINI_API_KEY="test-key", GEMINI_MODEL="test-model")
    @patch("monitor.ai.providers.gemini_provider.genai")
    def test_error_analyzer_ai_generation_caches_result(self, mock_genai):
        uploaded_log = UploadedLog.objects.create(
            user=self.user,
            filename="server.log",
            file=SimpleUploadedFile("server.log", b"TimeoutError: upstream timed out", content_type="text/plain"),
            processed=True,
        )
        ParsedError.objects.create(
            uploaded_log=uploaded_log,
            error_type="TimeoutError",
            raw_line="TimeoutError: upstream timed out",
            count=3,
            first_seen_line=1,
            category=ParsedError.CATEGORY_TIMEOUT,
            severity=ParsedError.SEVERITY_HIGH,
        )
        sdk_model = Mock()
        sdk_model.generate_content.return_value = Mock(text=(
            '{"summary":"Timeouts are recurring.",'
            '"suggested_fixes":["Recommendation: inspect upstream timeout budget."],'
            '"trends":["Timeout category dominates this upload."],'
            '"frequent_issues":["Repeated TimeoutError signature."],'
            '"likely_causes":["Likely upstream saturation or network delay."]}'
        ))
        mock_genai.GenerativeModel.return_value = sdk_model

        response = self.client.post(reverse("generate_error_upload_ai_analysis", args=[uploaded_log.id]))

        self.assertRedirects(response, reverse("error_log_results", args=[uploaded_log.id]))
        cache = AIAnalysisCache.objects.get(user=self.user, scope=AIAnalysisCache.SCOPE_ERROR_UPLOAD)
        self.assertEqual(cache.status, AIAnalysisCache.STATUS_READY)
        self.assertEqual(cache.content["summary"], "Timeouts are recurring.")

    @override_settings(AI_FEATURES_ENABLED=True, GEMINI_API_KEY="test-key", GEMINI_MODEL="test-model")
    @patch("monitor.ai.providers.gemini_provider.genai")
    def test_error_analyzer_ai_generation_uses_graceful_fallback_for_malformed_json(self, mock_genai):
        uploaded_log = UploadedLog.objects.create(
            user=self.user,
            filename="server.log",
            file=SimpleUploadedFile("server.log", b"TimeoutError: upstream timed out", content_type="text/plain"),
            processed=True,
        )
        ParsedError.objects.create(
            uploaded_log=uploaded_log,
            error_type="TimeoutError",
            raw_line="TimeoutError: upstream timed out",
            count=3,
            first_seen_line=1,
            category=ParsedError.CATEGORY_TIMEOUT,
            severity=ParsedError.SEVERITY_HIGH,
        )
        sdk_model = Mock()
        sdk_model.generate_content.return_value = Mock(text='Model commentary without any JSON object.')
        mock_genai.GenerativeModel.return_value = sdk_model

        response = self.client.post(reverse("generate_error_upload_ai_analysis", args=[uploaded_log.id]))

        self.assertRedirects(response, reverse("error_log_results", args=[uploaded_log.id]))
        cache = AIAnalysisCache.objects.get(user=self.user, scope=AIAnalysisCache.SCOPE_ERROR_UPLOAD)
        self.assertEqual(cache.status, AIAnalysisCache.STATUS_READY)
        self.assertIn("could not be structured reliably", cache.content["summary"])


class MonitorEmailAlertTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="monitor-user",
            password="StrongPass123!",
            email="alerts@example.com",
        )
        self.website = Website.objects.create(
            user=self.user,
            url="https://example.com",
        )

    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    @patch("monitor.utils.send_siteguard_email", return_value=True)
    @patch("monitor.utils.requests.get")
    def test_sends_email_only_when_site_transitions_from_up_to_down(self, mock_get, mock_send_email, _mock_ssl):
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_UP, response_time=123)
        mock_get.return_value = Mock(
            status_code=500,
            elapsed=Mock(total_seconds=Mock(return_value=0.123)),
        )

        run_single_check(self.website)

        self.assertEqual(mock_send_email.call_count, 1)
        kwargs = mock_send_email.call_args.kwargs
        self.assertIn("is down", kwargs["subject"].lower())
        self.assertEqual(kwargs["recipients"], [self.user.email])
        self.assertEqual(Alert.objects.filter(website=self.website, alert_type=Alert.TYPE_DOWN).count(), 1)
        self.assertIn("Alert Details:", kwargs["text_body"])
        self.assertIn("HTTP 500", kwargs["text_body"])
        self.assertIn("Incident Started:", kwargs["text_body"])
        self.assertIn("Operational Assessment:", kwargs["text_body"])
        self.assertIn("Current Outage State:", kwargs["text_body"])
        self.assertIn("Alerts Dashboard:", kwargs["text_body"])
        self.assertIn("Open alerts dashboard", kwargs["html_body"])

    @override_settings(DEBUG=True, APP_BASE_URL="https://siteguard.onrender.com", CANONICAL_BASE_URL="https://siteguard.onrender.com")
    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    @patch("monitor.utils.send_siteguard_email", return_value=True)
    @patch("monitor.utils.requests.get")
    def test_operational_alert_email_uses_localhost_links_during_local_development(self, mock_get, mock_send_email, _mock_ssl):
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_UP, response_time=123)
        mock_get.return_value = Mock(
            status_code=500,
            elapsed=Mock(total_seconds=Mock(return_value=0.123)),
        )

        run_single_check(self.website)

        kwargs = mock_send_email.call_args.kwargs
        self.assertIn("http://127.0.0.1:8000/alerts/", kwargs["text_body"])
        self.assertNotIn("https://siteguard.onrender.com/alerts/", kwargs["text_body"])

    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    @patch("monitor.utils.send_siteguard_email", return_value=True)
    @patch("monitor.utils.requests.get")
    def test_does_not_send_duplicate_email_when_active_down_alert_exists(self, mock_get, mock_send_email, _mock_ssl):
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_DOWN, response_time=0)
        incident = Incident.objects.create(
            website=self.website,
            title="Complete Outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_DOWN,
            started_at=MonitorLog.objects.filter(website=self.website).first().checked_at,
            latest_response_time=0,
        )
        Alert.objects.create(
            website=self.website,
            incident=incident,
            alert_type=Alert.TYPE_DOWN,
            status=Alert.STATUS_SENT,
            message="Automated monitoring detected https://example.com as DOWN at 0ms.",
            sent_to=self.user.email,
            response_time=0,
        )
        mock_get.return_value = Mock(
            status_code=500,
            elapsed=Mock(total_seconds=Mock(return_value=0.123)),
        )

        run_single_check(self.website)

        mock_send_email.assert_not_called()

    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    @patch("monitor.utils.send_siteguard_email", return_value=True)
    @patch("monitor.utils.requests.get")
    def test_does_not_create_new_alert_after_acknowledgement_during_same_outage(self, mock_get, mock_send_email, _mock_ssl):
        original_log = MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_DOWN, response_time=0)
        incident = Incident.objects.create(
            website=self.website,
            title="Complete Outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_DOWN,
            started_at=original_log.checked_at,
            latest_response_time=0,
        )
        alert = Alert.objects.create(
            website=self.website,
            incident=incident,
            alert_type=Alert.TYPE_DOWN,
            status=Alert.STATUS_SENT,
            message="Automated monitoring detected https://example.com as DOWN at 0ms.",
            sent_to=self.user.email,
            response_time=0,
            is_read=True,
            read_at=timezone.now(),
        )
        mock_get.return_value = Mock(
            status_code=500,
            elapsed=Mock(total_seconds=Mock(return_value=0.123)),
        )

        run_single_check(self.website)

        self.assertEqual(Alert.objects.filter(website=self.website, incident=incident, alert_type=Alert.TYPE_DOWN).count(), 1)
        mock_send_email.assert_not_called()
        alert.refresh_from_db()
        self.assertTrue(alert.is_read)

    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    @patch("monitor.utils.send_siteguard_email", return_value=True)
    @patch("monitor.utils.requests.get")
    def test_monitor_command_reproduces_down_detection_and_email_attempt(self, mock_get, mock_send_email, _mock_ssl):
        mock_get.return_value = Mock(
            status_code=503,
            elapsed=Mock(total_seconds=Mock(return_value=0.250)),
        )

        stdout = io.StringIO()
        call_command("monitor_sites", stdout=stdout)

        incident = Incident.objects.get(website=self.website, is_resolved=False)
        alert = Alert.objects.get(website=self.website, incident=incident, alert_type=Alert.TYPE_DOWN)
        self.assertEqual(incident.incident_type, Incident.TYPE_OUTAGE)
        self.assertEqual(alert.status, Alert.STATUS_SENT)
        self.assertEqual(mock_send_email.call_count, 1)
        self.assertIn("Starting monitoring cycle...", stdout.getvalue())

    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    @patch("monitor.utils.send_siteguard_email", return_value=True)
    @patch("monitor.utils.requests.get")
    def test_alert_logs_suppression_reason_when_email_notifications_disabled(self, mock_get, mock_send_email, _mock_ssl):
        self.website.email_notifications = False
        self.website.save(update_fields=["email_notifications"])
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_UP, response_time=123)
        mock_get.return_value = Mock(
            status_code=500,
            elapsed=Mock(total_seconds=Mock(return_value=0.123)),
        )

        with patch("monitor.utils.logger.warning") as mock_warning:
            run_single_check(self.website)

        self.assertFalse(mock_send_email.called)
        warning_call = next(
            call for call in mock_warning.call_args_list
            if call.args and call.args[0] == "Operational alert email skipped."
        )
        self.assertEqual(
            warning_call.kwargs["extra"]["email_context"]["reason"],
            "website_email_notifications_disabled",
        )

    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    @patch("monitor.utils.send_siteguard_email", return_value=True)
    @patch("monitor.utils.requests.get")
    def test_alert_logs_dedup_suppression_when_matching_active_alert_exists(self, mock_get, mock_send_email, _mock_ssl):
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_UP, response_time=123)
        mock_get.return_value = Mock(
            status_code=500,
            elapsed=Mock(total_seconds=Mock(return_value=0.123)),
        )
        run_single_check(self.website)
        mock_send_email.reset_mock()
        incident = Incident.objects.get(website=self.website, is_resolved=False)
        alert = Alert.objects.get(website=self.website, incident=incident, alert_type=Alert.TYPE_DOWN)

        with patch("monitor.utils.logger.info") as mock_info:
            create_or_update_alert(
                self.website,
                Alert.TYPE_DOWN,
                alert.message,
                incident=incident,
                response_time=alert.response_time,
            )

        self.assertFalse(mock_send_email.called)
        dedup_call = next(
            call for call in mock_info.call_args_list
            if call.args and call.args[0] == "Operational alert email suppressed by deduplication."
        )
        self.assertEqual(
            dedup_call.kwargs["extra"]["email_context"]["reason"],
            "matching_active_alert",
        )

    @patch("monitor.utils.check_ssl_status", return_value="Invalid")
    @patch("monitor.utils.send_siteguard_email", return_value=True)
    @patch("monitor.utils.requests.get")
    def test_ssl_alert_sends_email_when_tls_check_fails(self, mock_get, mock_send_email, _mock_ssl):
        mock_get.return_value = Mock(
            status_code=200,
            elapsed=Mock(total_seconds=Mock(return_value=0.080)),
        )

        run_single_check(self.website)

        incident = Incident.objects.get(website=self.website, is_resolved=False)
        alert = Alert.objects.get(website=self.website, incident=incident, alert_type=Alert.TYPE_SSL)
        self.assertEqual(incident.incident_type, Incident.TYPE_SSL)
        self.assertEqual(alert.status, Alert.STATUS_SENT)
        self.assertEqual(mock_send_email.call_count, 1)

    def test_create_or_update_alert_logs_delivery_evaluation_with_account_and_website_states(self):
        incident = Incident.objects.create(
            website=self.website,
            title="Complete Outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_DOWN,
            started_at=timezone.now(),
            latest_response_time=0,
        )

        with patch("monitor.utils.logger.info") as mock_info, patch(
            "monitor.utils.send_siteguard_email",
            return_value=True,
        ) as mock_send_email:
            create_or_update_alert(
                self.website,
                Alert.TYPE_DOWN,
                "Automated monitoring detected https://example.com as DOWN.",
                incident=incident,
                response_time=0,
            )

        self.assertEqual(mock_send_email.call_count, 1)
        decision_call = next(
            call for call in mock_info.call_args_list
            if call.args and call.args[0] == "Operational alert delivery evaluated."
        )
        context = decision_call.kwargs["extra"]["email_context"]
        self.assertTrue(context["should_email"])
        self.assertEqual(context["reason"], "email_enabled")
        self.assertEqual(context["recipient"], self.user.email)
        self.assertTrue(context["website_alerts_enabled"])
        self.assertTrue(context["website_email_notifications"])
        self.assertTrue(context["profile_email_alerts_enabled"])
        self.assertTrue(context["profile_incident_alerts_enabled"])

    def test_create_or_update_alert_logs_ssl_alert_type_filter_suppression(self):
        self.user.profile.ssl_alerts_enabled = False
        self.user.profile.save(update_fields=["ssl_alerts_enabled"])
        incident = Incident.objects.create(
            website=self.website,
            title="SSL Certificate Warning",
            incident_type=Incident.TYPE_SSL,
            status=Incident.STATUS_SLOW,
            started_at=timezone.now(),
            latest_response_time=12,
        )

        with patch("monitor.utils.logger.info") as mock_info, patch("monitor.utils.logger.warning") as mock_warning:
            create_or_update_alert(
                self.website,
                Alert.TYPE_SSL,
                "TLS handshake or certificate validation failed during certificate checks.",
                incident=incident,
                response_time=12,
            )

        decision_call = next(
            call for call in mock_info.call_args_list
            if call.args and call.args[0] == "Operational alert delivery evaluated."
        )
        self.assertEqual(
            decision_call.kwargs["extra"]["email_context"]["reason"],
            "account_ssl_alerts_disabled",
        )
        warning_call = next(
            call for call in mock_warning.call_args_list
            if call.args and call.args[0] == "Operational alert email skipped."
        )
        self.assertEqual(
            warning_call.kwargs["extra"]["email_context"]["reason"],
            "account_ssl_alerts_disabled",
        )

    def test_create_or_update_alert_logs_cooldown_suppression_for_reused_alert(self):
        incident = Incident.objects.create(
            website=self.website,
            title="Complete Outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_DOWN,
            started_at=timezone.now(),
            latest_response_time=0,
        )
        alert = Alert.objects.create(
            website=self.website,
            incident=incident,
            alert_type=Alert.TYPE_DOWN,
            status=Alert.STATUS_SENT,
            message="Original outage detail.",
            sent_to=self.user.email,
            response_time=0,
        )

        with patch("monitor.utils.logger.info") as mock_info, patch("monitor.utils.send_siteguard_email") as mock_send_email:
            create_or_update_alert(
                self.website,
                Alert.TYPE_DOWN,
                "Updated outage detail after the same active incident remained open.",
                incident=incident,
                response_time=0,
            )

        mock_send_email.assert_not_called()
        alert.refresh_from_db()
        self.assertEqual(alert.message, "Updated outage detail after the same active incident remained open.")
        cooldown_call = next(
            call for call in mock_info.call_args_list
            if call.args and call.args[0] == "Operational alert email suppressed by cooldown state reuse."
        )
        self.assertEqual(
            cooldown_call.kwargs["extra"]["email_context"]["reason"],
            "reused_existing_alert",
        )


class MonitorStatusSyncTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="status-user",
            password="StrongPass123!",
        )
        self.client.login(username="status-user", password="StrongPass123!")
        self.gmail = Website.objects.create(user=self.user, url="https://gmail.com")
        self.reddit = Website.objects.create(user=self.user, url="https://reddit.com")
        self.google = Website.objects.create(user=self.user, url="https://google.com")

    def test_shared_status_resolver_handles_up_slow_and_down(self):
        up_log = MonitorLog(status=MonitorLog.STATUS_UP, response_time=350)
        slow_log = MonitorLog(status=MonitorLog.STATUS_UP, response_time=2501)
        down_log = MonitorLog(status=MonitorLog.STATUS_DOWN, response_time=100)
        no_response_log = MonitorLog(status=MonitorLog.STATUS_UP, response_time=None)

        self.assertEqual(get_site_status(up_log), "UP")
        self.assertEqual(get_site_status(slow_log), "SLOW")
        self.assertEqual(get_site_status(down_log), "DOWN")
        self.assertEqual(get_site_status(no_response_log), "DOWN")

    def test_dashboard_status_page_and_json_use_same_latest_status_per_site(self):
        MonitorLog.objects.create(website=self.gmail, status=MonitorLog.STATUS_UP, response_time=2501)
        MonitorLog.objects.create(website=self.gmail, status=MonitorLog.STATUS_UP, response_time=110)
        MonitorLog.objects.create(website=self.reddit, status=MonitorLog.STATUS_UP, response_time=400)
        MonitorLog.objects.create(website=self.google, status=MonitorLog.STATUS_UP, response_time=150)
        MonitorLog.objects.create(website=self.google, status=MonitorLog.STATUS_DOWN, response_time=0)

        dashboard_response = self.client.get(reverse("dashboard"))
        status_response = self.client.get(reverse("status"))
        json_response = self.client.get(reverse("dashboard_data"))

        dashboard_sites = {
            site.url: site.status for site in dashboard_response.context["sites"]
        }
        status_sites = {
            site.url: site.status for site in status_response.context["sites"]
        }
        json_sites = {
            site["url"]: site["status"] for site in json_response.json()["sites"]
        }

        expected = {
            "https://gmail.com": "UP",
            "https://reddit.com": "UP",
            "https://google.com": "DOWN",
        }

        self.assertEqual(dashboard_sites, expected)
        self.assertEqual(status_sites, expected)
        self.assertEqual(json_sites, expected)
        self.assertEqual(dashboard_response.context["status"], "DOWN")

    def test_favicon_helper_builds_google_favicon_url(self):
        favicon_url = get_favicon_url("https://gmail.com")

        self.assertEqual(
            favicon_url,
            "https://www.google.com/s2/favicons?domain=gmail.com&sz=64",
        )

    def test_normalize_domain_display_removes_scheme_www_and_trailing_slash(self):
        self.assertEqual(normalize_domain_display("https://www.reddit.com/"), "reddit.com")
        self.assertEqual(normalize_domain_display("https://mail.google.com/"), "mail.google.com")
        self.assertEqual(normalize_domain_display("https://abc-not-real-999.com"), "abc-not-real-999.com")

    @patch("monitor.views.run_single_check")
    def test_check_now_runs_shared_monitoring_logic_and_redirects(self, mock_run_single_check):
        mock_run_single_check.return_value = (
            MonitorLog(website=self.gmail, status=MonitorLog.STATUS_UP, response_time=120, id=88),
            Mock(status_code=200),
        )
        response = self.client.post(reverse("check_now", args=[self.gmail.id]))

        mock_run_single_check.assert_called_once_with(self.gmail)
        self.assertRedirects(response, reverse("status"))

    @patch("monitor.views.logger.info")
    @patch("monitor.views.run_single_check")
    def test_check_now_logs_start_and_completion(self, mock_run_single_check, mock_info):
        mock_run_single_check.return_value = (
            MonitorLog(website=self.gmail, status=MonitorLog.STATUS_DOWN, response_time=0, id=77),
            None,
        )

        response = self.client.post(reverse("check_now", args=[self.gmail.id]))

        self.assertRedirects(response, reverse("status"))
        stages = [
            call.kwargs["extra"]["monitoring_context"]["stage"]
            for call in mock_info.call_args_list
            if call.kwargs.get("extra", {}).get("monitoring_context")
        ]
        self.assertIn("check_now_start", stages)
        self.assertIn("check_now_complete", stages)

    @patch("monitor.views.check_ssl_status", return_value="Valid")
    @patch("monitor.views.get_favicon_url", return_value="https://favicon.test/icon.png")
    def test_dashboard_and_status_include_favicon_and_ssl_metadata(self, mock_favicon, mock_ssl):
        MonitorLog.objects.create(website=self.gmail, status=MonitorLog.STATUS_UP, response_time=100)

        dashboard_response = self.client.get(reverse("dashboard"))
        status_response = self.client.get(reverse("status"))

        dashboard_site = next(
            site for site in dashboard_response.context["sites"]
            if site.url == "https://gmail.com"
        )
        status_site = next(
            site for site in status_response.context["sites"]
            if site.url == "https://gmail.com"
        )

        self.assertEqual(dashboard_site.favicon, "https://favicon.test/icon.png")
        self.assertEqual(status_site.favicon, "https://favicon.test/icon.png")
        self.assertEqual(dashboard_site.ssl_status, "Valid")
        self.assertEqual(status_site.ssl_status, "Valid")
        self.assertEqual(dashboard_site.display_domain, "gmail.com")
        self.assertEqual(status_site.display_domain, "gmail.com")


class IncidentSyncTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="incident-user",
            password="StrongPass123!",
        )
        self.website = Website.objects.create(
            user=self.user,
            url="https://example.com",
        )
        self.client.login(username="incident-user", password="StrongPass123!")

    @patch("monitor.utils.requests.get")
    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    def test_creates_outage_incident_when_site_transitions_to_down(self, _mock_ssl, mock_get):
        MonitorLog.objects.create(
            website=self.website,
            status=MonitorLog.STATUS_UP,
            response_time=120,
        )
        mock_get.return_value = Mock(
            status_code=503,
            elapsed=Mock(total_seconds=Mock(return_value=0.250)),
        )

        run_single_check(self.website)

        incident = Incident.objects.get(website=self.website, is_resolved=False)
        self.assertEqual(incident.status, Incident.STATUS_DOWN)
        self.assertEqual(incident.incident_type, Incident.TYPE_OUTAGE)
        self.assertEqual(incident.title, "Complete Outage")
        self.assertEqual(incident.events.count(), 1)
        self.assertEqual(incident.events.first().event_type, IncidentEvent.TYPE_DETECTED)

    @patch("monitor.utils.logger.info")
    @patch("monitor.utils.requests.get")
    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    def test_existing_down_incident_logs_no_new_alert_trace(self, _mock_ssl, mock_get, mock_info):
        first = Mock(
            status_code=503,
            elapsed=Mock(total_seconds=Mock(return_value=0.250)),
        )
        second = Mock(
            status_code=503,
            elapsed=Mock(total_seconds=Mock(return_value=0.275)),
        )
        mock_get.side_effect = [first, second]
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_UP, response_time=120)

        run_single_check(self.website)
        run_single_check(self.website)

        stages = [
            call.kwargs["extra"]["monitoring_context"]["stage"]
            for call in mock_info.call_args_list
            if call.kwargs.get("extra", {}).get("monitoring_context")
        ]
        self.assertIn("incident_state_alert_triggered", stages)
        self.assertIn("incident_state_existing_incident_no_new_alert", stages)

    @patch("monitor.management.commands.monitor_sites.logger.info")
    @patch("monitor.utils.logger.info")
    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    @patch("monitor.utils.send_siteguard_email", return_value=True)
    @patch("monitor.utils.requests.get")
    def test_monitor_command_logs_scheduler_trace_for_down_alerts(
        self,
        mock_get,
        mock_send_email,
        _mock_ssl,
        mock_utils_info,
        mock_scheduler_info,
    ):
        self.website.user.email = "alerts@example.com"
        self.website.user.save(update_fields=["email"])
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_UP, response_time=100)
        mock_get.return_value = Mock(
            status_code=503,
            elapsed=Mock(total_seconds=Mock(return_value=0.250)),
        )

        call_command("monitor_sites")

        self.assertEqual(mock_send_email.call_count, 1)
        scheduler_stages = [
            call.kwargs["extra"]["monitoring_context"]["stage"]
            for call in mock_scheduler_info.call_args_list
            if call.kwargs.get("extra", {}).get("monitoring_context")
        ]
        utility_stages = [
            call.kwargs["extra"]["monitoring_context"]["stage"]
            for call in mock_utils_info.call_args_list
            if call.kwargs.get("extra", {}).get("monitoring_context")
        ]
        self.assertIn("scheduler_start", scheduler_stages)
        self.assertIn("scheduler_check_complete", scheduler_stages)
        self.assertIn("run_single_check_transition_evaluation", utility_stages)
        self.assertIn("incident_state_alert_triggered", utility_stages)

    def test_incidents_page_includes_read_only_ai_analysis_controls(self):
        Incident.objects.create(
            website=self.website,
            title="Complete Outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_DOWN,
            started_at=timezone.now(),
            latest_response_time=0,
        )

        response = self.client.get(reverse("incidents"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "AI Incident Analysis")
        self.assertContains(response, "Analyze Incident")

    @override_settings(AI_FEATURES_ENABLED=False)
    def test_incident_ai_generation_gracefully_handles_disabled_ai(self):
        incident = Incident.objects.create(
            website=self.website,
            title="Complete Outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_DOWN,
            started_at=timezone.now(),
            latest_response_time=0,
        )

        response = self.client.post(reverse("generate_incident_ai_analysis", args=[incident.id]))

        self.assertRedirects(response, reverse("incidents"))
        cache = AIAnalysisCache.objects.get(user=self.user, scope=AIAnalysisCache.SCOPE_INCIDENT)
        self.assertEqual(cache.status, AIAnalysisCache.STATUS_DISABLED)

    @patch("monitor.utils.requests.get")
    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    def test_creates_performance_incident_for_slow_checks(self, _mock_ssl, mock_get):
        MonitorLog.objects.create(
            website=self.website,
            status=MonitorLog.STATUS_UP,
            response_time=120,
        )
        mock_get.return_value = Mock(
            status_code=200,
            elapsed=Mock(total_seconds=Mock(return_value=2.5)),
        )

        run_single_check(self.website)

        incident = Incident.objects.get(website=self.website, is_resolved=False)
        self.assertEqual(incident.status, Incident.STATUS_SLOW)
        self.assertEqual(incident.incident_type, Incident.TYPE_PERFORMANCE)
        self.assertEqual(incident.title, "High Response Times")

    @patch("monitor.utils.requests.get")
    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    def test_reuses_active_incident_without_duplicates(self, _mock_ssl, mock_get):
        MonitorLog.objects.create(
            website=self.website,
            status=MonitorLog.STATUS_UP,
            response_time=120,
        )
        mock_get.return_value = Mock(
            status_code=503,
            elapsed=Mock(total_seconds=Mock(return_value=0.250)),
        )

        run_single_check(self.website)
        run_single_check(self.website)

        self.assertEqual(Incident.objects.filter(website=self.website, is_resolved=False).count(), 1)
        incident = Incident.objects.get(website=self.website, is_resolved=False)
        self.assertEqual(incident.events.count(), 1)

    @patch("monitor.utils.requests.get")
    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    def test_resolves_active_incident_when_site_recovers(self, _mock_ssl, mock_get):
        MonitorLog.objects.create(
            website=self.website,
            status=MonitorLog.STATUS_UP,
            response_time=120,
        )
        mock_get.return_value = Mock(
            status_code=503,
            elapsed=Mock(total_seconds=Mock(return_value=0.250)),
        )
        run_single_check(self.website)

        mock_get.return_value = Mock(
            status_code=200,
            elapsed=Mock(total_seconds=Mock(return_value=0.150)),
        )
        run_single_check(self.website)

        incident = Incident.objects.get(website=self.website)
        self.assertTrue(incident.is_resolved)
        self.assertEqual(incident.status, Incident.STATUS_RESOLVED)
        self.assertIsNotNone(incident.resolved_at)
        self.assertEqual(incident.events.first().event_type, IncidentEvent.TYPE_RESOLVED)

    def test_incidents_page_renders_real_incident_data(self):
        incident = Incident.objects.create(
            website=self.website,
            title="Complete Outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_DOWN,
            started_at=MonitorLog.objects.create(
                website=self.website,
                status=MonitorLog.STATUS_DOWN,
                response_time=0,
            ).checked_at,
            latest_response_time=0,
        )
        IncidentEvent.objects.create(
            incident=incident,
            event_type=IncidentEvent.TYPE_DETECTED,
            message="Automated monitoring detected https://example.com as DOWN at 0ms.",
        )

        response = self.client.get(reverse("incidents"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Complete Outage")
        self.assertContains(response, "https://example.com")
        self.assertEqual(response.context["active_incidents"], 1)


class AlertSyncTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="alert-user",
            password="StrongPass123!",
            email="alert-user@example.com",
        )
        self.website = Website.objects.create(
            user=self.user,
            url="https://example.com",
        )
        self.client.login(username="alert-user", password="StrongPass123!")

    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    @patch("monitor.utils.send_siteguard_email", return_value=True)
    @patch("monitor.utils.requests.get")
    def test_recovery_alert_is_created_when_incident_resolves(self, mock_get, mock_send_email, _mock_ssl):
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_UP, response_time=100)
        mock_get.return_value = Mock(
            status_code=503,
            elapsed=Mock(total_seconds=Mock(return_value=0.2)),
        )
        run_single_check(self.website)

        mock_get.return_value = Mock(
            status_code=200,
            elapsed=Mock(total_seconds=Mock(return_value=0.1)),
        )
        run_single_check(self.website)

        self.assertTrue(Alert.objects.filter(website=self.website, alert_type=Alert.TYPE_RECOVERY).exists())
        self.assertGreaterEqual(mock_send_email.call_count, 2)
        recovery_email = mock_send_email.call_args_list[-1].kwargs["text_body"]
        self.assertIn("Recovery Summary:", recovery_email)
        self.assertIn("Downtime Duration:", recovery_email)
        self.assertIn("Peak Latency During Window:", recovery_email)

    @patch("monitor.utils.send_siteguard_email", return_value=False)
    def test_retry_failed_alert_action_updates_status(self, _mock_send_email):
        alert = Alert.objects.create(
            website=self.website,
            alert_type=Alert.TYPE_DOWN,
            status=Alert.STATUS_FAILED,
            message="https://example.com is DOWN.",
            sent_to=self.user.email,
            response_time=0,
        )

        response = self.client.post(reverse("retry_alert", args=[alert.id]))

        self.assertRedirects(response, reverse("alerts"))
        alert.refresh_from_db()
        self.assertEqual(alert.status, Alert.STATUS_FAILED)

    def test_mark_alert_read_action_sets_read_state(self):
        alert = Alert.objects.create(
            website=self.website,
            alert_type=Alert.TYPE_DOWN,
            status=Alert.STATUS_SENT,
            message="https://example.com is DOWN.",
        )

        response = self.client.post(reverse("mark_alert_read", args=[alert.id]))

        self.assertRedirects(response, reverse("alerts"))
        alert.refresh_from_db()
        self.assertTrue(alert.is_read)
        self.assertIsNotNone(alert.read_at)

    @patch("monitor.utils.send_siteguard_email", return_value=True)
    @patch("monitor.utils.check_ssl_status", return_value="Invalid")
    @patch("monitor.utils.requests.get")
    def test_ssl_alert_and_incident_are_created_once(self, mock_get, _mock_ssl, _mock_send_email):
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_UP, response_time=100)
        mock_get.return_value = Mock(
            status_code=200,
            elapsed=Mock(total_seconds=Mock(return_value=0.2)),
        )

        run_single_check(self.website)
        run_single_check(self.website)

        self.assertEqual(Alert.objects.filter(website=self.website, alert_type=Alert.TYPE_SSL).count(), 1)
        self.assertEqual(Incident.objects.filter(website=self.website, incident_type=Incident.TYPE_SSL).count(), 1)

    @patch("monitor.utils.send_siteguard_email", return_value=True)
    @patch("monitor.utils.requests.get", side_effect=requests.exceptions.SSLError("certificate verify failed"))
    def test_ssl_request_exception_still_creates_ssl_alert_and_incident(self, _mock_get, _mock_send_email):
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_UP, response_time=100)

        run_single_check(self.website)

        self.assertEqual(Alert.objects.filter(website=self.website, alert_type=Alert.TYPE_SSL).count(), 1)
        self.assertEqual(Incident.objects.filter(website=self.website, incident_type=Incident.TYPE_SSL).count(), 1)
        self.assertEqual(Alert.objects.filter(website=self.website, alert_type=Alert.TYPE_DOWN).count(), 0)
        self.assertEqual(Incident.objects.filter(website=self.website, incident_type=Incident.TYPE_OUTAGE).count(), 0)

    def test_alerts_page_renders_real_alert_data(self):
        alert = Alert.objects.create(
            website=self.website,
            alert_type=Alert.TYPE_DOWN,
            status=Alert.STATUS_SENT,
            message="https://example.com is DOWN.",
            response_time=0,
        )

        response = self.client.get(reverse("alerts"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "https://example.com")
        self.assertContains(response, alert.message)
        self.assertEqual(response.context["recent_alerts_count"], 1)

    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    @patch("monitor.utils.send_siteguard_email", return_value=True)
    @patch("monitor.utils.requests.get")
    def test_down_alert_message_includes_http_reason_and_response_context(self, mock_get, _mock_send_email, _mock_ssl):
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_UP, response_time=100)
        mock_get.return_value = Mock(
            status_code=503,
            elapsed=Mock(total_seconds=Mock(return_value=0.321)),
        )

        run_single_check(self.website)

        alert = Alert.objects.get(website=self.website, alert_type=Alert.TYPE_DOWN)
        self.assertIn("HTTP 503", alert.message)
        self.assertIn("Response metric", alert.message)
        self.assertIn(self.website.url, alert.message)

    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    @patch("monitor.utils.send_siteguard_email", return_value=True)
    @patch("monitor.utils.requests.get", side_effect=requests.Timeout("timed out"))
    def test_timeout_alert_message_includes_timeout_reason(self, _mock_get, _mock_send_email, _mock_ssl):
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_UP, response_time=100)

        run_single_check(self.website)

        alert = Alert.objects.get(website=self.website, alert_type=Alert.TYPE_DOWN)
        self.assertIn("timed out", alert.message.lower())
        self.assertIn("No response", alert.message)


class MonitoringIntegrityTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="integrity-user",
            password="StrongPass123!",
            email="integrity@example.com",
        )
        self.client.login(username="integrity-user", password="StrongPass123!")
        self.website = Website.objects.create(user=self.user, url="https://example.com")
        self.other_website = Website.objects.create(user=self.user, url="https://google.com")

    def test_cleanup_fixes_alert_website_mismatch_from_incident(self):
        incident = Incident.objects.create(
            website=self.website,
            title="Complete Outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_DOWN,
            started_at=timezone.now(),
            latest_response_time=0,
        )
        alert = Alert.objects.create(
            website=self.other_website,
            incident=incident,
            alert_type=Alert.TYPE_DOWN,
            status=Alert.STATUS_SENT,
            message="down",
        )

        cleanup_monitoring_state(user=self.user)

        alert.refresh_from_db()
        self.assertEqual(alert.website, self.website)

    def test_active_incident_uniqueness_constraint_blocks_duplicate_active_incidents(self):
        Incident.objects.create(
            website=self.website,
            title="Complete Outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_DOWN,
            started_at=timezone.now(),
            latest_response_time=0,
        )

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Incident.objects.create(
                    website=self.website,
                    title="Complete Outage",
                    incident_type=Incident.TYPE_OUTAGE,
                    status=Incident.STATUS_DOWN,
                    started_at=timezone.now() + timedelta(minutes=1),
                    latest_response_time=0,
                )

        self.assertEqual(
            Incident.objects.filter(
                website=self.website,
                incident_type=Incident.TYPE_OUTAGE,
                is_resolved=False,
            ).count(),
            1,
        )

    def test_resolved_incidents_do_not_block_new_active_incident_for_same_type(self):
        Incident.objects.create(
            website=self.website,
            title="Complete Outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_RESOLVED,
            started_at=timezone.now() - timedelta(hours=1),
            resolved_at=timezone.now() - timedelta(minutes=30),
            is_resolved=True,
            latest_response_time=0,
        )

        created = Incident.objects.create(
            website=self.website,
            title="Complete Outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_DOWN,
            started_at=timezone.now(),
            latest_response_time=0,
        )

        self.assertFalse(created.is_resolved)
        self.assertEqual(
            Incident.objects.filter(
                website=self.website,
                incident_type=Incident.TYPE_OUTAGE,
                is_resolved=False,
            ).count(),
            1,
        )

    def test_sync_incident_state_reuses_existing_active_incident_when_create_hits_integrity_race(self):
        current_log = MonitorLog.objects.create(
            website=self.website,
            status=MonitorLog.STATUS_DOWN,
            response_time=0,
        )
        existing_incident = Incident.objects.create(
            website=self.website,
            title="Complete Outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_DOWN,
            started_at=current_log.checked_at - timedelta(minutes=1),
            latest_response_time=0,
        )

        with patch("monitor.utils.Incident.objects.create", side_effect=IntegrityError):
            sync_incident_state(self.website, None, current_log, status_code=503, reason="HTTP 503 returned.")

        unresolved = list(
            Incident.objects.filter(
                website=self.website,
                incident_type=Incident.TYPE_OUTAGE,
                is_resolved=False,
            )
        )
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(unresolved[0].id, existing_incident.id)
        self.assertEqual(
            IncidentEvent.objects.filter(
                incident=existing_incident,
                event_type=IncidentEvent.TYPE_DETECTED,
            ).count(),
            0,
        )

    def test_cleanup_normalizes_active_incident_fields_without_weakening_uniqueness(self):
        incident = Incident.objects.create(
            website=self.website,
            title="Wrong title",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_RESOLVED,
            started_at=timezone.now(),
            latest_response_time=2500.889,
        )

        cleanup_monitoring_state(user=self.user)

        incident.refresh_from_db()
        self.assertEqual(incident.title, "Complete Outage")
        self.assertEqual(incident.status, Incident.STATUS_DOWN)
        self.assertFalse(incident.is_resolved)
        self.assertEqual(incident.latest_response_time, 2500.89)

    def test_dashboard_counts_only_unresolved_incidents(self):
        Incident.objects.create(
            website=self.website,
            title="Complete Outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_RESOLVED,
            started_at=timezone.now() - timedelta(hours=1),
            resolved_at=timezone.now(),
            is_resolved=True,
            latest_response_time=0,
        )

        response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.context["incidents"], 0)

    def test_duplicate_active_alerts_are_marked_read_during_cleanup(self):
        incident = Incident.objects.create(
            website=self.website,
            title="Complete Outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_DOWN,
            started_at=timezone.now(),
            latest_response_time=0,
        )
        Alert.objects.create(
            website=self.website,
            incident=incident,
            alert_type=Alert.TYPE_DOWN,
            status=Alert.STATUS_SENT,
            message="same",
            sent_to=self.user.email,
        )
        duplicate = Alert.objects.create(
            website=self.website,
            incident=incident,
            alert_type=Alert.TYPE_DOWN,
            status=Alert.STATUS_SENT,
            message="same",
            sent_to=self.user.email,
        )

        cleanup_monitoring_state(user=self.user)

        duplicate.refresh_from_db()
        unread_count = Alert.objects.filter(
            website=self.website,
            incident=incident,
            alert_type=Alert.TYPE_DOWN,
            is_read=False,
        ).count()
        self.assertEqual(unread_count, 1)
        self.assertTrue(
            Alert.objects.filter(
                website=self.website,
                incident=incident,
                alert_type=Alert.TYPE_DOWN,
                is_read=True,
            ).exists()
        )

    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    @patch("monitor.utils.requests.get")
    def test_timeline_event_message_stays_on_correct_website(self, mock_get, _mock_ssl):
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_UP, response_time=100)
        mock_get.return_value = Mock(
            status_code=503,
            elapsed=Mock(total_seconds=Mock(return_value=0.2)),
        )

        run_single_check(self.website)

        incident = Incident.objects.get(website=self.website, is_resolved=False)
        event = incident.events.get(event_type=IncidentEvent.TYPE_DETECTED)
        self.assertIn(self.website.url, event.message)
        self.assertNotIn(self.other_website.url, event.message)


class ReportingViewsTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="report-user",
            password="StrongPass123!",
            email="report@example.com",
        )
        self.other_user = User.objects.create_user(
            username="other-report-user",
            password="StrongPass123!",
        )
        self.client.login(username="report-user", password="StrongPass123!")
        self.website = Website.objects.create(user=self.user, url="https://example.com")
        self.second_website = Website.objects.create(user=self.user, url="https://slow.example.com")
        self.other_website = Website.objects.create(user=self.other_user, url="https://other.com")

    def test_logs_page_uses_current_user_monitor_logs_only(self):
        own_log = MonitorLog.objects.create(
            website=self.website,
            status=MonitorLog.STATUS_UP,
            response_time=120,
        )
        MonitorLog.objects.create(
            website=self.other_website,
            status=MonitorLog.STATUS_DOWN,
            response_time=0,
        )

        response = self.client.get(reverse("logs"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context["logs"]), 1)
        self.assertEqual(response.context["logs"][0]["url"], self.website.url)
        self.assertEqual(response.context["logs"][0]["response_time_display"], "120 ms")

    def test_reports_page_calculates_real_analytics(self):
        MonitorLog.objects.create(
            website=self.website,
            status=MonitorLog.STATUS_UP,
            response_time=100,
        )
        MonitorLog.objects.create(
            website=self.website,
            status=MonitorLog.STATUS_DOWN,
            response_time=0,
        )
        MonitorLog.objects.create(
            website=self.second_website,
            status=MonitorLog.STATUS_SLOW,
            response_time=2500,
        )
        Incident.objects.create(
            website=self.website,
            title="Complete Outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_DOWN,
            started_at=timezone.now(),
            latest_response_time=0,
        )
        Alert.objects.create(
            website=self.website,
            alert_type=Alert.TYPE_DOWN,
            status=Alert.STATUS_SENT,
            message="down",
            response_time=0,
        )

        response = self.client.get(reverse("reports"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["total_issues_today"], 2)
        self.assertAlmostEqual(response.context["average_uptime"], 33.33, places=2)
        self.assertAlmostEqual(response.context["average_response_time"], 866.67, places=2)
        self.assertEqual(response.context["alert_counts"]["active"], 1)
        self.assertEqual(response.context["ssl_failures"], 0)

    def test_reports_range_filter_excludes_old_logs(self):
        old_time = timezone.now() - timedelta(days=10)
        recent_log = MonitorLog.objects.create(
            website=self.website,
            status=MonitorLog.STATUS_UP,
            response_time=100,
        )
        old_log = MonitorLog.objects.create(
            website=self.website,
            status=MonitorLog.STATUS_DOWN,
            response_time=0,
        )
        MonitorLog.objects.filter(pk=old_log.pk).update(checked_at=old_time)

        response = self.client.get(reverse("reports"), {"range": "7d"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["logs_count"], 1)
        self.assertEqual(response.context["selected_range"], "7d")

    def test_reports_chart_data_has_safe_empty_state(self):
        response = self.client.get(reverse("reports"))

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context["has_monitoring_data"])
        self.assertTrue(all(value == 0 for value in response.context["chart_data"]["uptime_trend"]))

    def test_reports_page_includes_ai_operational_intelligence_panel(self):
        response = self.client.get(reverse("reports"))

        self.assertEqual(response.status_code, 200)
        self.assertIn("ai_report_state", response.context)
        self.assertContains(response, "AI Operational Intelligence")
        self.assertContains(response, "Generate AI Summary")

    @override_settings(AI_FEATURES_ENABLED=False)
    def test_ai_report_generation_falls_back_when_disabled(self):
        response = self.client.post(reverse("generate_report_ai_analysis"), {"range": "7d"})

        self.assertRedirects(response, f"{reverse('reports')}?range=7d")
        cache = AIAnalysisCache.objects.get(user=self.user, scope=AIAnalysisCache.SCOPE_REPORT)
        self.assertEqual(cache.status, AIAnalysisCache.STATUS_DISABLED)
        self.assertEqual(cache.content, {})

    @override_settings(AI_FEATURES_ENABLED=True, GEMINI_API_KEY="test-key", GEMINI_MODEL="test-model")
    @patch("monitor.ai.providers.gemini_provider.genai")
    def test_ai_report_generation_caches_provider_result(self, mock_genai):
        sdk_model = Mock()
        sdk_model.generate_content.return_value = Mock(text=(
            '{"summary":"Latency was elevated.",'
            '"suggested_fixes":["Recommendation: inspect upstream saturation."],'
            '"trends":["Latency increased late in the window."],'
            '"frequent_issues":["Repeated slow checks."],'
            '"likely_causes":["Likely upstream saturation based on latency profile."]}'
        ))
        mock_genai.GenerativeModel.return_value = sdk_model

        response = self.client.post(reverse("generate_report_ai_analysis"), {"range": "7d"})

        self.assertRedirects(response, f"{reverse('reports')}?range=7d")
        cache = AIAnalysisCache.objects.get(user=self.user, scope=AIAnalysisCache.SCOPE_REPORT)
        self.assertEqual(cache.status, AIAnalysisCache.STATUS_READY)
        self.assertEqual(cache.content["summary"], "Latency was elevated.")
        self.assertEqual(cache.provider, "gemini")
        self.assertEqual(sdk_model.generate_content.call_count, 1)

        context = build_reports_context(self.user, "7d")
        generate_report_analysis(self.user, context)
        self.assertEqual(sdk_model.generate_content.call_count, 1)

    @override_settings(AI_FEATURES_ENABLED=True, GEMINI_API_KEY="test-key", GEMINI_MODEL="test-model")
    @patch("monitor.ai.providers.gemini_provider.genai")
    def test_ai_report_generation_uses_graceful_fallback_for_malformed_json(self, mock_genai):
        sdk_model = Mock()
        sdk_model.generate_content.return_value = Mock(text='Here is the result without any JSON object.')
        mock_genai.GenerativeModel.return_value = sdk_model

        response = self.client.post(reverse("generate_report_ai_analysis"), {"range": "7d"})

        self.assertRedirects(response, f"{reverse('reports')}?range=7d")
        cache = AIAnalysisCache.objects.get(user=self.user, scope=AIAnalysisCache.SCOPE_REPORT)
        self.assertEqual(cache.status, AIAnalysisCache.STATUS_READY)
        self.assertIn("could not be structured reliably", cache.content["summary"])

    @override_settings(AI_FEATURES_ENABLED=True, GEMINI_API_KEY="test-key", GEMINI_MODEL="test-model")
    @patch("monitor.ai.providers.gemini_provider.genai")
    def test_ai_provider_failure_is_cached_without_breaking_reports(self, mock_genai):
        sdk_model = Mock()
        sdk_model.generate_content.side_effect = TimeoutError("timed out")
        mock_genai.GenerativeModel.return_value = sdk_model

        response = self.client.post(reverse("generate_report_ai_analysis"), {"range": "7d"})

        self.assertRedirects(response, f"{reverse('reports')}?range=7d")
        cache = AIAnalysisCache.objects.get(user=self.user, scope=AIAnalysisCache.SCOPE_REPORT)
        self.assertEqual(cache.status, AIAnalysisCache.STATUS_FAILED)
        report_response = self.client.get(reverse("reports"))
        self.assertEqual(report_response.status_code, 200)
        self.assertContains(report_response, "AI analysis unavailable")

    @override_settings(AI_FEATURES_ENABLED=True, GEMINI_API_KEY="test-key", GEMINI_MODEL="test-model", AI_RETRY_ATTEMPTS=0)
    @patch("monitor.ai.providers.gemini_provider.genai")
    def test_ai_provider_failure_preserves_existing_ready_cache(self, mock_genai):
        sdk_model = Mock()
        sdk_model.generate_content.side_effect = TimeoutError("timed out")
        mock_genai.GenerativeModel.return_value = sdk_model
        context = build_reports_context(self.user, "7d")
        cache = AIAnalysisCache.objects.create(
            user=self.user,
            scope=AIAnalysisCache.SCOPE_REPORT,
            scope_key="range:7d",
            input_hash="previous-hash",
            status=AIAnalysisCache.STATUS_READY,
            provider="gemini",
            model_name="test-model",
            content={"summary": "Previously generated insight."},
        )

        result = generate_report_analysis(self.user, context, force=True)
        cache.refresh_from_db()

        self.assertEqual(result.id, cache.id)
        self.assertEqual(cache.status, AIAnalysisCache.STATUS_READY)
        self.assertEqual(cache.content["summary"], "Previously generated insight.")
        self.assertEqual(sdk_model.generate_content.call_count, 1)

    @override_settings(AI_PROVIDER="openai", OPENAI_API_KEY="test-key", OPENAI_MODEL="openai-test-model")
    def test_ai_provider_selection_can_use_openai(self):
        provider = get_default_provider()

        self.assertEqual(provider.provider_name, "openai")
        self.assertEqual(provider.model, "openai-test-model")

    def test_ai_prompt_builder_sanitizes_sensitive_values(self):
        sanitized = sanitize_text("token=secret123 user@example.com password:abc")
        prompt = build_report_prompt({"line": sanitized})

        self.assertNotIn("secret123", prompt)
        self.assertNotIn("user@example.com", prompt)
        self.assertIn("[email]", prompt)

    def test_reports_chart_data_generation_has_expected_length(self):
        MonitorLog.objects.create(
            website=self.website,
            status=MonitorLog.STATUS_UP,
            response_time=100,
        )

        response = self.client.get(reverse("reports"), {"range": "30d"})

        self.assertEqual(len(response.context["chart_data"]["labels"]), 30)
        self.assertEqual(len(response.context["chart_data"]["error_trend"]), 30)

    def test_reports_and_logs_use_normalized_domains_for_display(self):
        MonitorLog.objects.create(
            website=self.second_website,
            status=MonitorLog.STATUS_UP,
            response_time=180,
        )

        reports_response = self.client.get(reverse("reports"))
        logs_response = self.client.get(reverse("logs"))

        self.assertEqual(reports_response.context["slowest_websites"][0]["display_domain"], "slow.example.com")
        self.assertEqual(logs_response.context["logs"][0]["display_domain"], "slow.example.com")

    def test_weekly_reports_view_builds_operational_summary_and_history(self):
        now = timezone.now()
        MonitorLog.objects.create(
            website=self.website,
            status=MonitorLog.STATUS_UP,
            response_time=120,
        )
        MonitorLog.objects.create(
            website=self.second_website,
            status=MonitorLog.STATUS_DOWN,
            response_time=0,
        )
        incident = Incident.objects.create(
            website=self.second_website,
            title="Weekly outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_DOWN,
            started_at=now,
            latest_response_time=0,
        )
        Alert.objects.create(
            website=self.second_website,
            incident=incident,
            alert_type=Alert.TYPE_DOWN,
            status=Alert.STATUS_SENT,
            message="slow.example.com is down",
            response_time=0,
        )

        response = self.client.get(reverse("weekly_reports"))

        self.assertEqual(response.status_code, 200)
        self.assertIn("week_key", response.context)
        self.assertGreaterEqual(response.context["alert_count"], 1)
        self.assertGreaterEqual(response.context["incident_count"], 1)
        self.assertTrue(response.context["history"])
        self.assertContains(response, "Unified Operational History")


class GeminiProviderParsingTests(TestCase):
    def setUp(self):
        self.provider = GeminiProvider()

    def _gemini_success_response(self, summary="Recovered after retry."):
        return Mock(text=(
            '{"summary":"' + summary + '",'
            '"suggested_fixes":[],"trends":[],"frequent_issues":[],'
            '"likely_causes":[]}'
        ))

    def _configure_gemini_sdk_mock(self, mock_genai, responses):
        sdk_model = Mock()
        sdk_model.generate_content.side_effect = responses
        mock_genai.GenerativeModel.return_value = sdk_model
        mock_genai.types.GenerationConfig.return_value = Mock()
        return sdk_model

    def _gemini_error(self, status_code):
        error = Exception(f"{status_code} error")
        error.code = status_code
        return error

    @override_settings(GEMINI_API_KEY="test-key", GEMINI_MODEL="gemini-1.5-flash")
    def test_gemini_model_resolution_accepts_supported_model_names(self):
        with self.assertLogs("monitor.ai.providers.gemini_provider", level="INFO") as captured:
            provider = GeminiProvider()
        self.assertEqual(provider._normalized_model_name(), "gemini-1.5-flash")
        self.assertEqual(provider._resolved_model_path(), "models/gemini-1.5-flash")
        self.assertIn("AI provider initialized: provider=gemini model=models/gemini-1.5-flash api_key_present=True", "\n".join(captured.output))

        with override_settings(GEMINI_MODEL="gemini-1.5-flash-latest"):
            provider = GeminiProvider()
            self.assertEqual(provider._normalized_model_name(), "gemini-1.5-flash-latest")
            self.assertEqual(provider._resolved_model_path(), "models/gemini-1.5-flash-latest")

        with override_settings(GEMINI_MODEL="gemini-2.5-flash"):
            provider = GeminiProvider()
            self.assertEqual(provider._normalized_model_name(), "gemini-2.5-flash")
            self.assertEqual(provider._resolved_model_path(), "models/gemini-2.5-flash")

    @override_settings(GEMINI_API_KEY="test-key", GEMINI_MODEL="models/gemini-1.5-flash")
    def test_gemini_model_resolution_accepts_single_models_prefix(self):
        provider = GeminiProvider()

        self.assertEqual(provider._normalized_model_name(), "gemini-1.5-flash")
        self.assertEqual(provider._resolved_model_path(), "models/gemini-1.5-flash")

    @override_settings(GEMINI_API_KEY="test-key", GEMINI_MODEL='  "models/gemini-1.5-flash-latest"  ')
    def test_gemini_model_resolution_strips_quotes_and_whitespace(self):
        provider = GeminiProvider()

        self.assertEqual(provider.model, "models/gemini-1.5-flash-latest")
        self.assertEqual(provider._normalized_model_name(), "gemini-1.5-flash-latest")
        self.assertEqual(provider._resolved_model_path(), "models/gemini-1.5-flash-latest")

    @override_settings(GEMINI_API_KEY="test-key", GEMINI_MODEL="models/models/gemini-1.5-flash")
    def test_gemini_model_resolution_rejects_duplicate_models_prefix(self):
        provider = GeminiProvider()

        with self.assertRaisesMessage(AIProviderUnavailable, "Gemini model configuration is invalid."):
            provider._resolved_model_path()

    @override_settings(GEMINI_API_KEY="test-key", GEMINI_MODEL="gemini 1.5 flash")
    def test_gemini_model_resolution_rejects_malformed_model_name(self):
        provider = GeminiProvider()

        with self.assertRaisesMessage(AIProviderUnavailable, "Gemini model configuration is invalid."):
            provider._resolved_model_path()

    @override_settings(GEMINI_API_KEY="test-key", GEMINI_MODEL="gemini-1.5-flash")
    @patch("monitor.ai.providers.gemini_provider.genai")
    def test_gemini_sdk_initialization_uses_configure_and_generative_model(self, mock_genai):
        provider = GeminiProvider()
        sdk_model = self._configure_gemini_sdk_mock(
            mock_genai,
            [self._gemini_success_response("SDK response.")],
        )

        provider.generate_json(instructions="Return JSON.", input_text="payload")

        mock_genai.configure.assert_called_once_with(api_key="test-key")
        mock_genai.GenerativeModel.assert_called_once_with(
            "models/gemini-1.5-flash",
            system_instruction="Return JSON.",
        )
        sdk_model.generate_content.assert_called_once_with(
            "payload",
            generation_config=mock_genai.types.GenerationConfig.return_value,
            request_options={"timeout": 20},
        )

    @override_settings(
        GEMINI_API_KEY="test-key",
        GEMINI_MODEL="gemini-1.5-flash",
        AI_RETRY_ATTEMPTS=2,
        AI_RETRY_BACKOFF_SECONDS=0.01,
    )
    @patch("monitor.ai.providers.gemini_provider.genai")
    def test_gemini_404_is_non_retryable_and_fails_gracefully(self, mock_genai):
        provider = GeminiProvider()
        sdk_model = self._configure_gemini_sdk_mock(mock_genai, [self._gemini_error(404)])

        with self.assertRaisesMessage(AIProviderUnavailable, "Gemini model models/gemini-1.5-flash is unavailable."):
            provider.generate_json(instructions="Return JSON.", input_text="payload")

        self.assertEqual(sdk_model.generate_content.call_count, 1)

    @override_settings(GEMINI_API_KEY="test-key", GEMINI_MODEL="models/gemini-1.5-flash-latest")
    @patch("monitor.ai.providers.gemini_provider.genai")
    def test_gemini_unavailable_model_populates_listing_diagnostics(self, mock_genai):
        provider = GeminiProvider()
        sdk_model = self._configure_gemini_sdk_mock(mock_genai, [self._gemini_error(404)])
        model_one = Mock()
        model_one.name = "models/gemini-1.5-flash"
        model_one.supported_generation_methods = ["generateContent"]
        model_two = Mock()
        model_two.name = "models/gemini-1.5-flash-8b"
        model_two.supported_generation_methods = ["generateContent"]
        mock_genai.list_models.return_value = [model_one, model_two]

        with self.assertRaises(AIProviderUnavailable):
            provider.generate_json(instructions="Return JSON.", input_text="payload")

        diagnostics = provider.get_last_diagnostics()
        self.assertEqual(diagnostics["resolved_model"], "models/gemini-1.5-flash-latest")
        self.assertEqual(diagnostics["suggested_model"], "models/gemini-1.5-flash")
        self.assertIn("models/gemini-1.5-flash", diagnostics["available_models"])
        self.assertEqual(sdk_model.generate_content.call_count, 1)

    def test_gemini_parser_accepts_fenced_json(self):
        content = self.provider._parse_json_output(
            '```json\n'
            '{"summary":"DNS instability.","likely_root_cause":"Likely DNS provider instability.","impact":"Intermittent resolution failures may delay checks.","recommendations":["Recommendation: verify DNS provider health."],"confidence":"medium"}'
            '\n```'
        )

        self.assertEqual(content["summary"], "DNS instability.")
        self.assertEqual(content["suggested_fixes"], ["Recommendation: verify DNS provider health."])
        self.assertEqual(content["likely_root_cause"], "Likely DNS provider instability.")
        self.assertEqual(content["confidence"], "medium")

    def test_gemini_parser_accepts_plain_json(self):
        content = self.provider._parse_json_output(
            '{"summary":"Stable response.","likely_root_cause":"","impact":"No measurable user impact detected.","recommendations":[],"confidence":"high"}'
        )

        self.assertEqual(content["summary"], "Stable response.")
        self.assertEqual(content["recommendations"], [])

    def test_gemini_parser_accepts_wrapped_json(self):
        content = self.provider._parse_json_output(
            'Here is the operational analysis:\n\n'
            '{"summary":"Latency increased.","likely_root_cause":"Likely upstream saturation.","impact":"Users may see slower page loads.","recommendations":["Recommendation: inspect upstream saturation."],"confidence":"medium","trends":["Latency degradation is recurring."]}'
            '\n\nThis suggests further investigation.'
        )

        self.assertEqual(content["summary"], "Latency increased.")
        self.assertEqual(content["trends"], ["Latency degradation is recurring."])

    def test_gemini_parser_accepts_json_with_markdown_wrapper_label(self):
        content = self.provider._parse_json_output(
            'JSON:\n'
            '```json\n'
            '{"summary":"Wrapped by markdown label.","likely_root_cause":"","impact":"No additional impact inferred.","recommendations":[],"confidence":"low"}\n'
            '```'
        )

        self.assertEqual(content["summary"], "Wrapped by markdown label.")

    def test_gemini_parser_falls_back_on_malformed_json(self):
        with self.assertLogs("monitor.ai.providers.gemini_provider", level="WARNING") as captured:
            content = self.provider._parse_json_output('```json\n{"summary": "broken",\n```')

        self.assertIn("Gemini JSON parse failed.", "\n".join(captured.output))
        self.assertIn("Gemini JSON fallback activated.", "\n".join(captured.output))
        self.assertIn("could not be structured reliably", content["summary"])

    def test_gemini_parser_repairs_trailing_commas(self):
        content = self.provider._parse_json_output(
            '{"summary":"Trailing comma cleanup.","likely_root_cause":"Likely transient provider formatting issue.","impact":"No direct production impact inferred.","recommendations":["Retry later",],"confidence":"medium",}'
        )

        self.assertEqual(content["summary"], "Trailing comma cleanup.")
        self.assertEqual(content["suggested_fixes"], ["Retry later"])

    def test_gemini_parser_normalizes_partial_json(self):
        content = self.provider._parse_json_output('{"summary":"Partial but usable."}')

        self.assertEqual(content["summary"], "Partial but usable.")
        self.assertEqual(content["confidence"], "low")
        self.assertEqual(content["suggested_fixes"], [])
        self.assertEqual(content["likely_root_cause"], "")

    def test_gemini_parser_repairs_truncated_partial_json(self):
        content = self.provider._parse_json_output(
            '{"summary":"Truncated but recoverable.","recommendations":["Check DNS"]'
        )

        self.assertEqual(content["summary"], "Truncated but recoverable.")
        self.assertEqual(content["suggested_fixes"], ["Check DNS"])

    def test_gemini_parser_accepts_commentary_wrapped_fenced_json(self):
        content = self.provider._parse_json_output(
            'Here is the requested JSON:\n```json\n'
            '{"summary":"Commentary stripped.","likely_root_cause":"Likely upstream saturation.","impact":"Timeout spikes may degrade request completion.","recommendations":[],"confidence":"medium","frequent_issues":["Timeout spikes"]}'
            '\n```\nAdditional note ignored.'
        )

        self.assertEqual(content["summary"], "Commentary stripped.")
        self.assertEqual(content["frequent_issues"], ["Timeout spikes"])
        self.assertEqual(content["root_cause_hints"], ["Likely upstream saturation."])

    def test_gemini_parser_falls_back_on_non_json_output(self):
        content = self.provider._parse_json_output("The service looks mostly healthy.")

        self.assertIn("could not be structured reliably", content["summary"])
        self.assertEqual(content["confidence"], "low")

    def test_gemini_parser_accepts_valid_nested_json(self):
        content = self.provider._parse_json_output(
            'Preface ignored.\n'
            '{"summary":"Nested payload accepted.","likely_root_cause":"Likely upstream backlog.","impact":"Queue latency may increase.","recommendations":["Review queue depth"],"confidence":"medium","trends":["Nested telemetry repeated"],'
            '"frequent_issues":[{"pattern":"queue saturation"}],"likely_causes":[{"cause":"upstream backlog"}],"meta":{"ignored":true}}'
            '\nTrailing note ignored.'
        )

        self.assertEqual(content["summary"], "Nested payload accepted.")
        self.assertEqual(content["frequent_issues"], ['{"pattern": "queue saturation"}'])
        self.assertEqual(content["likely_causes"], ['{"cause": "upstream backlog"}'])

    def test_gemini_parser_accepts_missing_fields_with_defaults(self):
        content = self.provider._parse_json_output('{"summary":"Only summary provided."}')

        self.assertEqual(content["summary"], "Only summary provided.")
        self.assertEqual(content["likely_root_cause"], "")
        self.assertEqual(content["recommendations"], [])
        self.assertEqual(content["confidence"], "low")

    def test_gemini_parser_empty_response_uses_fallback_payload(self):
        content = self.provider._parse_json_output("")

        self.assertIn("could not be structured reliably", content["summary"])
        self.assertEqual(content["confidence"], "low")

    def test_gemini_prompt_explicitly_rejects_markdown(self):
        instructions = build_ai_instructions()

        self.assertIn("Return STRICT RAW VALID JSON ONLY", instructions)
        self.assertIn("No markdown", instructions)
        self.assertIn("No code fences", instructions)
        self.assertIn("No commentary", instructions)
        self.assertIn("Do not wrap the JSON", instructions)

    @override_settings(GEMINI_API_KEY="test-key", GEMINI_MODEL="test-model", AI_DEBUG_RAW_OUTPUT=True)
    @patch("monitor.ai.providers.gemini_provider.genai")
    def test_gemini_parser_logs_raw_output_preview_in_debug_mode(self, mock_genai):
        provider = GeminiProvider()
        self._configure_gemini_sdk_mock(
            mock_genai,
            [Mock(
                text='Here is the requested JSON: {"summary":"Preview diagnostics.","suggested_fixes":[],"trends":[],"frequent_issues":[],"likely_causes":[]}',
                candidates=[Mock()],
            )],
        )

        with patch("monitor.ai.providers.gemini_provider.logger.debug") as mock_debug:
            provider.generate_json(instructions="Return JSON.", input_text="payload")

        diagnostic_call = next(
            call for call in mock_debug.call_args_list
            if call.args and call.args[0] == "Gemini raw response diagnostics."
        )
        self.assertIn("Preview diagnostics.", diagnostic_call.kwargs["extra"]["raw_output_preview"])
        self.assertTrue(diagnostic_call.kwargs["extra"]["raw_output_debug_enabled"])

    @override_settings(
        GEMINI_API_KEY="test-key",
        GEMINI_MODEL="test-model",
        AI_RETRY_ATTEMPTS=2,
        AI_RETRY_BACKOFF_SECONDS=0.01,
    )
    @patch("monitor.ai.providers.gemini_provider.time.sleep")
    @patch("monitor.ai.providers.gemini_provider.genai")
    def test_gemini_retries_transient_status_and_recovers(self, mock_genai, mock_sleep):
        provider = GeminiProvider()
        sdk_model = self._configure_gemini_sdk_mock(mock_genai, [
            self._gemini_error(503),
            self._gemini_error(502),
            self._gemini_success_response("Recovered after transient Gemini outage."),
        ])

        content = provider.generate_json(instructions="Return JSON.", input_text="payload")

        self.assertEqual(content["summary"], "Recovered after transient Gemini outage.")
        self.assertEqual(sdk_model.generate_content.call_count, 3)
        self.assertEqual(mock_sleep.call_count, 2)

    @override_settings(
        GEMINI_API_KEY="test-key",
        GEMINI_MODEL="test-model",
        AI_RETRY_ATTEMPTS=1,
        AI_RETRY_BACKOFF_SECONDS=0.01,
    )
    @patch("monitor.ai.providers.gemini_provider.time.sleep")
    @patch("monitor.ai.providers.gemini_provider.genai")
    def test_gemini_retries_timeout_and_recovers(self, mock_genai, mock_sleep):
        provider = GeminiProvider()
        sdk_model = self._configure_gemini_sdk_mock(mock_genai, [
            TimeoutError("timed out"),
            self._gemini_success_response("Recovered after timeout."),
        ])

        content = provider.generate_json(instructions="Return JSON.", input_text="payload")

        self.assertEqual(content["summary"], "Recovered after timeout.")
        self.assertEqual(sdk_model.generate_content.call_count, 2)
        self.assertEqual(mock_sleep.call_count, 1)

    @override_settings(
        GEMINI_API_KEY="test-key",
        GEMINI_MODEL="test-model",
        AI_RETRY_ATTEMPTS=2,
        AI_RETRY_BACKOFF_SECONDS=0.01,
    )
    @patch("monitor.ai.providers.gemini_provider.time.sleep")
    @patch("monitor.ai.providers.gemini_provider.genai")
    def test_gemini_persistent_provider_outage_fails_safely(self, mock_genai, mock_sleep):
        provider = GeminiProvider()
        sdk_model = self._configure_gemini_sdk_mock(mock_genai, [
            self._gemini_error(503),
            self._gemini_error(503),
            self._gemini_error(503),
        ])

        with self.assertRaisesMessage(AIProviderError, "transient status 503 after 3 attempt"):
            provider.generate_json(instructions="Return JSON.", input_text="payload")

        self.assertEqual(sdk_model.generate_content.call_count, 3)
        self.assertEqual(mock_sleep.call_count, 2)


class UtilityHelperTests(TestCase):
    def test_safe_url_encode_and_decode_support_unicode(self):
        encoded = safe_url_encode("https://example.com/नमस्ते world")
        decoded = safe_url_decode(encoded["result"])

        self.assertTrue(encoded["success"])
        self.assertIn("%E0%A4%A8%E0%A4%AE", encoded["result"])
        self.assertTrue(decoded["success"])
        self.assertEqual(decoded["result"], "https://example.com/नमस्ते world")

    def test_safe_url_decode_rejects_invalid_percent_encoding(self):
        decoded = safe_url_decode("https%://example.com/%ZZ")

        self.assertFalse(decoded["success"])
        self.assertEqual(decoded["error"], "Invalid percent-encoding sequence.")


class AIConfigurationDiagnosticsTests(TestCase):
    def test_normalize_config_text_strips_quotes_and_whitespace(self):
        self.assertEqual(
            _normalize_config_text('  "models/gemini-1.5-flash-latest"  ', default="gemini-1.5-flash"),
            "models/gemini-1.5-flash-latest",
        )
        self.assertEqual(
            _normalize_config_text("   ", default="gemini-1.5-flash"),
            "gemini-1.5-flash",
        )

    @override_settings(
        AI_FEATURES_ENABLED=True,
        AI_PROVIDER="gemini",
        GEMINI_MODEL='  "models/gemini-1.5-flash-latest"  ',
        GEMINI_API_KEY="test-key",
    )
    def test_startup_diagnostics_log_resolved_model(self):
        with self.assertLogs("siteguard.runtime", level="INFO") as captured:
            log_ai_startup_diagnostics()

        combined_output = "\n".join(captured.output)
        self.assertIn("AI startup diagnostics:", combined_output)
        self.assertIn("AI_FEATURES_ENABLED=True", combined_output)
        self.assertIn("AI_PROVIDER=gemini", combined_output)
        self.assertIn("GEMINI_MODEL=models/gemini-1.5-flash-latest", combined_output)
        self.assertIn("GEMINI_API_KEY_PRESENT=True", combined_output)


class SessionConfigurationDiagnosticsTests(TestCase):
    def test_build_production_database_config_parses_database_url(self):
        database_config = build_production_database_config(
            database_url="postgresql://siteguard:secret@ep-neon.internal:5432/siteguard_prod?sslmode=require",
            sqlite_path="db.sqlite3",
            sqlite_timeout=20,
        )

        self.assertEqual(database_config["ENGINE"], "django.db.backends.postgresql")
        self.assertEqual(database_config["HOST"], "ep-neon.internal")
        self.assertEqual(database_config["PORT"], 5432)
        self.assertEqual(database_config["NAME"], "siteguard_prod")
        self.assertEqual(database_config["USER"], "siteguard")
        self.assertEqual(database_config["OPTIONS"]["sslmode"], "require")
        self.assertEqual(database_config["OPTIONS"]["connect_timeout"], 10)
        self.assertEqual(database_config["CONN_MAX_AGE"], 600)
        self.assertTrue(database_config["CONN_HEALTH_CHECKS"])

    def test_build_production_database_config_falls_back_to_sqlite_without_database_url(self):
        database_config = build_production_database_config(
            database_url="",
            sqlite_path="data/siteguard.sqlite3",
            sqlite_timeout=30,
        )

        self.assertEqual(
            database_config,
            build_sqlite_database_config(
                sqlite_path="data/siteguard.sqlite3",
                sqlite_timeout=30,
            ),
        )

    def test_get_database_configuration_diagnostics_reports_postgres_details(self):
        diagnostics = get_database_configuration_diagnostics(
            {
                "ENGINE": "django.db.backends.postgresql",
                "HOST": "ep-neon.internal",
                "NAME": "siteguard_prod",
                "OPTIONS": {"sslmode": "require"},
            }
        )

        self.assertEqual(diagnostics["engine"], "django.db.backends.postgresql")
        self.assertEqual(diagnostics["host"], "ep-neon.internal")
        self.assertEqual(diagnostics["name"], "siteguard_prod")
        self.assertEqual(diagnostics["ssl_mode"], "require")

    @override_settings(
        DATABASES={
            "default": {
                "ENGINE": "django.db.backends.postgresql",
                "HOST": "ep-neon.internal",
                "NAME": "siteguard_prod",
                "OPTIONS": {"sslmode": "require"},
            }
        }
    )
    @patch("monitor.apps.connection")
    def test_database_startup_diagnostics_log_runtime_configuration(self, mock_connection):
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1,)
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connection.introspection.table_names.return_value = ["auth_user", "django_session"]

        with self.assertLogs("siteguard.runtime", level="INFO") as captured:
            log_database_startup_diagnostics()

        combined_output = "\n".join(captured.output)
        self.assertIn("Database startup diagnostics:", combined_output)
        self.assertIn("engine=django.db.backends.postgresql", combined_output)
        self.assertIn("host=ep-neon.internal", combined_output)
        self.assertIn("name=siteguard_prod", combined_output)
        self.assertIn("ssl_mode=require", combined_output)
        self.assertIn("connection_health=healthy", combined_output)

    @override_settings(
        SESSION_ENGINE="django.contrib.sessions.backends.db",
        SESSION_COOKIE_AGE=604800,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_SAVE_EVERY_REQUEST=True,
        SESSION_EXPIRE_AT_BROWSER_CLOSE=False,
        CSRF_COOKIE_SECURE=True,
        CSRF_COOKIE_SAMESITE="Lax",
        SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"),
        USE_X_FORWARDED_HOST=True,
    )
    def test_session_startup_diagnostics_log_runtime_configuration(self):
        with self.assertLogs("siteguard.runtime", level="INFO") as captured:
            log_session_startup_diagnostics()

        combined_output = "\n".join(captured.output)
        self.assertIn("Session startup diagnostics:", combined_output)
        self.assertIn("engine=django.contrib.sessions.backends.db", combined_output)
        self.assertIn("cookie_age=604800", combined_output)
        self.assertIn("secure=True", combined_output)
        self.assertIn("proxy_ssl_header=('HTTP_X_FORWARDED_PROTO', 'https')", combined_output)
        self.assertIn("use_x_forwarded_host=True", combined_output)
        self.assertIn("backend_health=healthy", combined_output)

    @override_settings(
        STORAGES={
            "default": {"BACKEND": "cloudinary_storage.storage.MediaCloudinaryStorage"},
            "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
        }
    )
    def test_analyzer_storage_startup_diagnostics_log_runtime_configuration(self):
        with self.assertLogs("siteguard.runtime", level="INFO") as captured:
            log_analyzer_storage_startup_diagnostics()

        combined_output = "\n".join(captured.output)
        self.assertIn("Analyzer storage startup diagnostics:", combined_output)
        self.assertIn("field_storage=monitor.storage.AnalyzerUploadStorage", combined_output)
        self.assertIn("delegate=cloudinary_storage.storage.RawMediaCloudinaryStorage", combined_output)
        self.assertIn("resource_type=raw", combined_output)
        self.assertIn("active_media_backend=cloudinary_storage.storage.MediaCloudinaryStorage", combined_output)


class ProductionEmailValidationTests(TestCase):
    def _base_validation_kwargs(self, **overrides):
        kwargs = {
            "secret_key": "SiteGuard-Prod-Secret-Key-1234567890-abcdefghijklmnopqrstuvwxyz",
            "debug": False,
            "allowed_hosts": ["siteguard.onrender.com"],
            "app_base_url": "https://siteguard.onrender.com",
            "csrf_trusted_origins": ["https://siteguard.onrender.com"],
            "email_backend": "monitor.emailing.BrevoEmailBackend",
            "email_host": "",
            "email_use_tls": True,
            "email_use_ssl": False,
            "email_timeout": 15,
            "brevo_api_key": "brevo-api-key",
            "default_from_email": "SiteGuard Alerts <sender@example.com>",
            "cloudinary_storage": {
                "CLOUD_NAME": "cloud",
                "API_KEY": "key",
                "API_SECRET": "secret",
            },
            "storages": {
                "default": {
                    "BACKEND": "cloudinary_storage.storage.MediaCloudinaryStorage",
                }
            },
            "cron_secret": "cron-secret-value",
        }
        kwargs.update(overrides)
        return kwargs

    def test_production_validation_accepts_brevo_backend_class(self):
        validate_production_configuration(**self._base_validation_kwargs())

    def test_production_validation_rejects_console_backend(self):
        with self.assertRaisesMessage(ImproperlyConfigured, "Development email backends are not allowed in production."):
            validate_production_configuration(
                **self._base_validation_kwargs(
                    email_backend="django.core.mail.backends.console.EmailBackend"
                )
            )

    def test_production_validation_rejects_file_backend(self):
        with self.assertRaisesMessage(ImproperlyConfigured, "Development email backends are not allowed in production."):
            validate_production_configuration(
                **self._base_validation_kwargs(
                    email_backend="django.core.mail.backends.filebased.EmailBackend"
                )
            )

    def test_production_validation_rejects_locmem_backend(self):
        with self.assertRaisesMessage(ImproperlyConfigured, "Development email backends are not allowed in production."):
            validate_production_configuration(
                **self._base_validation_kwargs(
                    email_backend="django.core.mail.backends.locmem.EmailBackend"
                )
            )


class TestAIProviderCommandTests(TestCase):
    @override_settings(
        AI_FEATURES_ENABLED=True,
        AI_PROVIDER="gemini",
        GEMINI_API_KEY="test-key",
        GEMINI_MODEL='models/gemini-1.5-flash-latest',
    )
    @patch("monitor.ai.providers.gemini_provider.genai")
    def test_test_ai_provider_command_reports_success(self, mock_genai):
        sdk_model = Mock()
        sdk_model.generate_content.return_value = Mock(text=(
            '{"summary":"Self-test OK","suggested_fixes":[],"trends":[],"frequent_issues":[],"likely_causes":[]}'
        ))
        mock_genai.GenerativeModel.return_value = sdk_model
        mock_genai.types.GenerationConfig.return_value = Mock()

        stdout = io.StringIO()
        call_command("test_ai_provider", stdout=stdout)
        output = stdout.getvalue()

        self.assertIn("Testing AI provider configuration...", output)
        self.assertIn("Resolved Gemini model: models/gemini-1.5-flash-latest", output)
        self.assertIn("Gemini API key configured: True", output)
        self.assertIn("AI provider self-test passed.", output)
        self.assertIn("Summary: Self-test OK", output)

    @override_settings(
        AI_FEATURES_ENABLED=True,
        AI_PROVIDER="gemini",
        GEMINI_API_KEY="test-key",
        GEMINI_MODEL='models/gemini-1.5-flash-latest',
    )
    @patch("monitor.ai.providers.gemini_provider.genai")
    def test_test_ai_provider_command_reports_available_models_when_model_unavailable(self, mock_genai):
        sdk_model = Mock()
        error = Exception("404 error")
        error.code = 404
        sdk_model.generate_content.side_effect = error
        mock_genai.GenerativeModel.return_value = sdk_model
        mock_genai.types.GenerationConfig.return_value = Mock()
        available_model = Mock()
        available_model.name = "models/gemini-1.5-flash"
        available_model.supported_generation_methods = ["generateContent"]
        mock_genai.list_models.return_value = [available_model]

        stdout = io.StringIO()
        call_command("test_ai_provider", stdout=stdout)
        output = stdout.getvalue()

        self.assertIn("Provider unavailable: Gemini model models/gemini-1.5-flash-latest is unavailable.", output)
        self.assertIn("Configured model: models/gemini-1.5-flash-latest", output)
        self.assertIn("Resolved model: models/gemini-1.5-flash-latest", output)
        self.assertIn("Suggested model: models/gemini-1.5-flash", output)
        self.assertIn("Available Gemini models:", output)
        self.assertIn("models/gemini-1.5-flash", output)

    def test_analyze_domain_rejects_private_or_invalid_hosts(self):
        invalid = analyze_domain("localhost")
        private = analyze_domain("127.0.0.1")

        self.assertIn("not allowed", invalid["error_message"].lower())
        self.assertIn("not allowed", private["error_message"].lower())

    @patch("monitor.utils.requests.get")
    @patch("monitor.utils.fetch_ssl_details")
    @patch("monitor.utils.lookup_dns_records")
    @patch("monitor.utils.resolve_hostname", return_value="142.250.183.14")
    def test_analyze_domain_collects_realistic_domain_metadata(
        self,
        _mock_resolve,
        mock_dns,
        mock_ssl,
        mock_get,
    ):
        mock_dns.return_value = {
            "A": ["142.250.183.14"],
            "MX": ["10 smtp.google.com"],
            "NS": ["ns1.google.com", "ns2.google.com"],
            "TXT": ["v=spf1 include:_spf.google.com ~all"],
        }
        mock_ssl.return_value = {
            "valid": True,
            "issuer": "Google Trust Services",
            "expiry_date": "2030-01-01",
            "days_remaining": 100,
            "error": "",
        }
        mock_get.return_value = Mock(
            status_code=200,
            headers={
                "server": "gws",
                "content-type": "text/html; charset=utf-8",
                "cache-control": "private, max-age=0",
                "x-frame-options": "SAMEORIGIN",
                "strict-transport-security": "max-age=31536000",
                "x-content-type-options": "nosniff",
                "content-security-policy": "default-src 'self'",
                "referrer-policy": "strict-origin-when-cross-origin",
            },
        )

        result = analyze_domain("google.com")

        self.assertEqual(result["domain"], "google.com")
        self.assertEqual(result["ip_address"], "142.250.183.14")
        self.assertTrue(result["reachable"])
        self.assertTrue(result["ssl_valid"])
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["nameserver_count"], 2)
        self.assertEqual(result["security_state"], "Warning")
        self.assertEqual(result["dns_records"]["MX"], ["10 smtp.google.com"])

    @patch("monitor.utils.requests.get", side_effect=requests.Timeout)
    @patch("monitor.utils.fetch_ssl_details", return_value={"valid": False, "issuer": "", "expiry_date": "", "days_remaining": None, "error": "timeout"})
    @patch("monitor.utils.lookup_dns_records", return_value={"A": ["93.184.216.34"], "MX": [], "NS": [], "TXT": []})
    @patch("monitor.utils.resolve_hostname", return_value="93.184.216.34")
    def test_analyze_domain_handles_timeout_without_crashing(self, _mock_resolve, _mock_dns, _mock_ssl, _mock_get):
        result = analyze_domain("example.com")

        self.assertEqual(result["error_message"], "Request timed out.")
        self.assertEqual(result["latency"]["state"], "SLOW")
        self.assertFalse(result["reachable"])

    @patch("monitor.utils.requests.get", side_effect=requests.RequestException("offline"))
    @patch("monitor.utils.fetch_ssl_details", return_value={"valid": False, "issuer": "", "expiry_date": "", "days_remaining": None, "error": ""})
    @patch("monitor.utils.resolve_hostname", return_value="93.184.216.34")
    def test_dns_lookup_fallback_returns_a_record_without_dnspython(self, _mock_resolve, _mock_ssl, _mock_get):
        with patch("monitor.utils.dns_resolver", None):
            result = analyze_domain("example.com")

        self.assertIn("93.184.216.34", result["dns_records"]["A"])


class UtilitiesViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="utility-user",
            password="StrongPass123!",
            email="utility@example.com",
        )
        self.client.login(username="utility-user", password="StrongPass123!")

    def test_utilities_page_requires_authentication(self):
        self.client.logout()

        response = self.client.get(reverse("utilities"))

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)

    def test_utilities_encode_submission_renders_real_result(self):
        response = self.client.post(reverse("utilities"), {
            "utility_action": "encode",
            "encode_input": "hello world",
        })

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["encode_result"]["result"], "hello%20world")
        self.assertContains(response, "hello%20world")

    def test_utilities_decode_invalid_input_renders_error_state(self):
        response = self.client.post(reverse("utilities"), {
            "utility_action": "decode",
            "decode_input": "%ZZ",
        })

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context["decode_result"]["success"])
        self.assertContains(response, "Invalid percent-encoding sequence.")

    @patch("monitor.views.analyze_domain")
    def test_utilities_domain_result_shows_already_monitored_state(self, mock_analyze_domain):
        Website.objects.create(user=self.user, url="https://google.com")
        mock_analyze_domain.return_value = {
            "input": "google.com",
            "domain": "google.com",
            "url": "https://google.com",
            "ip_address": "8.8.8.8",
            "reachable": True,
            "ssl_valid": True,
            "response_time": 120.5,
            "status": 200,
            "error_message": "",
            "nameserver_count": 2,
            "security_state": "Secure",
            "dns_records": {"A": ["8.8.8.8"], "MX": [], "NS": ["ns1.google.com", "ns2.google.com"], "TXT": []},
            "ssl_details": {"valid": True, "issuer": "Google", "expiry_date": "2030-01-01", "days_remaining": 100, "error": ""},
            "headers": {
                "server": "gws",
                "content_type": "text/html",
                "cache_control": "private",
                "x_frame_options": "SAMEORIGIN",
                "strict_transport_security": "max-age=31536000",
                "security_headers": {},
                "missing_security_headers": [],
                "weak_configurations": [],
            },
            "latency": {"response_time": 120.5, "status_code": 200, "reachable": True, "state": "UP", "is_slow": False},
        }

        response = self.client.post(reverse("utilities"), {
            "utility_action": "domain_check",
            "domain_input": "google.com",
        })

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["domain_result"]["already_monitored"])
        self.assertContains(response, "Already Monitored")

    @patch("monitor.views.analyze_domain")
    def test_add_to_monitoring_creates_website_and_preserves_result_context(self, mock_analyze_domain):
        mock_analyze_domain.return_value = {
            "input": "example.com",
            "domain": "example.com",
            "url": "https://example.com",
            "ip_address": "93.184.216.34",
            "reachable": False,
            "ssl_valid": False,
            "response_time": None,
            "status": None,
            "error_message": "Request timed out.",
            "nameserver_count": 0,
            "security_state": "Timeout",
            "dns_records": {"A": ["93.184.216.34"], "MX": [], "NS": [], "TXT": []},
            "ssl_details": {"valid": False, "issuer": "", "expiry_date": "", "days_remaining": None, "error": "timeout"},
            "headers": {
                "server": "",
                "content_type": "",
                "cache_control": "",
                "x_frame_options": "",
                "strict_transport_security": "",
                "security_headers": {},
                "missing_security_headers": [],
                "weak_configurations": [],
            },
            "latency": {"response_time": None, "status_code": None, "reachable": False, "state": "SLOW", "is_slow": False},
        }

        response = self.client.post(reverse("utilities"), {
            "utility_action": "add_to_monitoring",
            "monitor_domain": "example.com",
        })

        self.assertEqual(response.status_code, 200)
        self.assertTrue(Website.objects.filter(user=self.user, url="https://example.com").exists())
        self.assertContains(response, "Domain added to monitoring.")
        self.assertTrue(response.context["domain_result"]["already_monitored"])

    def test_add_to_monitoring_rejects_private_hosts_with_validation_feedback(self):
        response = self.client.post(reverse("utilities"), {
            "utility_action": "add_to_monitoring",
            "monitor_domain": "localhost",
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Local, private, and reserved hosts are not allowed.")
        self.assertFalse(Website.objects.filter(user=self.user, url="https://localhost").exists())


ACCOUNT_TEST_MEDIA_ROOT = os.path.join(os.path.dirname(__file__), "_test_media")
os.makedirs(ACCOUNT_TEST_MEDIA_ROOT, exist_ok=True)


@override_settings(MEDIA_ROOT=ACCOUNT_TEST_MEDIA_ROOT)
class AccountManagementTests(TestCase):
    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(ACCOUNT_TEST_MEDIA_ROOT, ignore_errors=True)

    def setUp(self):
        self.user = User.objects.create_user(
            username="account-user",
            password="StrongPass123!",
            email="account@example.com",
        )
        self.other_user = User.objects.create_user(
            username="other-user",
            password="StrongPass123!",
            email="other@example.com",
        )
        self.client.login(username="account-user", password="StrongPass123!")
        self.website = Website.objects.create(user=self.user, url="https://example.com")
        Incident.objects.create(
            website=self.website,
            title="Complete Outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_RESOLVED,
            started_at=timezone.now() - timedelta(hours=1),
            resolved_at=timezone.now(),
            is_resolved=True,
            latest_response_time=0,
        )
        Alert.objects.create(
            website=self.website,
            alert_type=Alert.TYPE_DOWN,
            status=Alert.STATUS_SENT,
            message="down",
            response_time=0,
        )

    def test_user_profile_is_auto_created(self):
        self.assertTrue(UserProfile.objects.filter(user=self.user).exists())
        self.assertEqual(self.user.profile.monitoring_frequency, UserProfile.FREQ_5_MIN)

    def test_profile_page_uses_real_user_data(self):
        response = self.client.get(reverse("profile"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "account-user")
        self.assertContains(response, "account@example.com")
        self.assertContains(response, "1")
        self.assertNotContains(response, "John Doe")

    def test_profile_update_persists_username_email_and_avatar(self):
        avatar = SimpleUploadedFile("avatar.png", TEST_PNG_BYTES, content_type="image/png")

        response = self.client.post(
            reverse("profile"),
            {
                "profile_action": "update_profile",
                "username": "updated-user",
                "email": "updated@example.com",
                "avatar": avatar,
            },
        )

        self.assertRedirects(response, reverse("profile"))
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, "updated-user")
        self.assertEqual(self.user.email, "updated@example.com")
        self.assertTrue(bool(self.user.profile.avatar))
        snapshot = get_user_account_snapshot(self.user)
        self.assertTrue(snapshot["has_avatar"])
        self.assertTrue(snapshot["avatar_url"].startswith("/media/avatars/"))

    def test_profile_avatar_field_supports_cloudinary_length_names(self):
        avatar_field = UserProfile._meta.get_field("avatar")

        self.assertEqual(avatar_field.max_length, 500)

    def test_profile_update_persists_long_avatar_storage_name(self):
        avatar = SimpleUploadedFile("avatar.png", TEST_PNG_BYTES, content_type="image/png")
        long_avatar_name = "avatars/" + ("nested-folder/" * 20) + "cloudinary-avatar.png"
        storage = UserProfile._meta.get_field("avatar").storage

        with patch.object(storage, "save", return_value=long_avatar_name), patch.object(storage, "delete") as mock_delete:
            form = ProfileUpdateForm(
                data={
                    "username": "account-user",
                    "email": "account@example.com",
                },
                files={"avatar": avatar},
                user=self.user,
                profile=self.user.profile,
            )

            self.assertTrue(form.is_valid(), form.errors)
            _user, profile = form.save()

        self.assertEqual(profile.avatar.name, long_avatar_name)
        self.assertGreater(len(long_avatar_name), 100)
        mock_delete.assert_not_called()

    def test_profile_avatar_renders_after_upload_and_refresh(self):
        avatar = SimpleUploadedFile("avatar.png", TEST_PNG_BYTES, content_type="image/png")

        self.client.post(
            reverse("profile"),
            {
                "profile_action": "update_profile",
                "username": "account-user",
                "email": "account@example.com",
                "avatar": avatar,
            },
        )

        self.user.refresh_from_db()
        snapshot = get_user_account_snapshot(self.user)
        response = self.client.get(reverse("profile"))

        self.assertTrue(snapshot["has_avatar"])
        self.assertContains(response, snapshot["avatar_url"])
        self.assertContains(response, 'id="avatarPreview"')
        self.assertContains(response, 'id="headerAvatarImage"')
        image_response = self.client.get(snapshot["avatar_url"])
        self.assertEqual(image_response.status_code, 200)

    @override_settings(DEBUG=False)
    def test_media_urlpatterns_remain_available_when_debug_is_false(self):
        match = resolve("/media/avatars/example.png")

        self.assertEqual(match.func.__name__, "serve_media")
        self.assertEqual(match.kwargs["path"], "avatars/example.png")

    def test_profile_update_rejects_invalid_avatar_payload(self):
        avatar = SimpleUploadedFile("avatar.png", b"not-an-image", content_type="image/png")

        response = self.client.post(
            reverse("profile"),
            {
                "profile_action": "update_profile",
                "username": "account-user",
                "email": "account@example.com",
                "avatar": avatar,
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Fix the highlighted profile fields below before saving.")
        self.assertContains(response, "Upload a valid image")

    def test_profile_update_rejects_duplicate_email(self):
        response = self.client.post(
            reverse("profile"),
            {
                "profile_action": "update_profile",
                "username": "account-user",
                "email": "other@example.com",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "already in use")
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "account@example.com")

    def test_profile_page_falls_back_cleanly_when_avatar_file_is_missing(self):
        avatar = SimpleUploadedFile("avatar.png", TEST_PNG_BYTES, content_type="image/png")
        self.client.post(
            reverse("profile"),
            {
                "profile_action": "update_profile",
                "username": "account-user",
                "email": "account@example.com",
                "avatar": avatar,
            },
        )

        self.user.refresh_from_db()
        avatar_name = self.user.profile.avatar.name
        self.user.profile.avatar.storage.delete(avatar_name)

        snapshot = get_user_account_snapshot(self.user)
        response = self.client.get(reverse("profile"))

        self.assertFalse(snapshot["has_avatar"])
        self.assertEqual(snapshot["avatar_url"], "")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "avatarPreviewFallback")
        self.assertNotContains(response, avatar_name)

    def test_password_change_updates_hash_and_keeps_session_valid(self):
        response = self.client.post(
            reverse("profile"),
            {
                "profile_action": "change_password",
                "old_password": "StrongPass123!",
                "new_password1": "NewStrongPass123!",
                "new_password2": "NewStrongPass123!",
            },
        )

        self.assertRedirects(response, reverse("profile"))
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("NewStrongPass123!"))
        follow_up = self.client.get(reverse("profile"))
        self.assertEqual(follow_up.status_code, 200)

    def test_password_change_rejects_invalid_current_password_with_feedback(self):
        response = self.client.post(
            reverse("profile"),
            {
                "profile_action": "change_password",
                "old_password": "WrongPass123!",
                "new_password1": "NewStrongPass123!",
                "new_password2": "NewStrongPass123!",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Password change failed")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("StrongPass123!"))
        self.assertEqual(self.client.get(reverse("profile")).status_code, 200)

    def test_password_change_rejects_confirmation_mismatch(self):
        response = self.client.post(
            reverse("profile"),
            {
                "profile_action": "change_password",
                "old_password": "StrongPass123!",
                "new_password1": "NewStrongPass123!",
                "new_password2": "MismatchPass123!",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Password change failed")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("StrongPass123!"))

    def test_settings_persist_preferences_and_monitoring_frequency(self):
        response = self.client.post(
            reverse("settings"),
            {
                "timezone": "Asia/Calcutta",
                "email_alerts_enabled": "on",
                "ssl_alerts_enabled": "",
                "incident_alerts_enabled": "on",
                "marketing_emails_enabled": "on",
                "monitoring_frequency": UserProfile.FREQ_15_MIN,
                "two_factor_enabled": "on",
            },
        )

        self.assertRedirects(response, reverse("settings"))
        profile = self.user.profile
        profile.refresh_from_db()
        self.assertEqual(profile.timezone, "Asia/Calcutta")
        self.assertTrue(profile.email_alerts_enabled)
        self.assertFalse(profile.ssl_alerts_enabled)
        self.assertTrue(profile.incident_alerts_enabled)
        self.assertTrue(profile.marketing_emails_enabled)
        self.assertEqual(profile.monitoring_frequency, UserProfile.FREQ_15_MIN)
        self.assertTrue(profile.two_factor_enabled)

    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    @patch("monitor.utils.send_siteguard_email", return_value=True)
    @patch("monitor.utils.requests.get")
    def test_account_alert_preferences_affect_email_delivery(self, mock_get, mock_send_email, _mock_ssl):
        self.user.profile.email_alerts_enabled = False
        self.user.profile.save(update_fields=["email_alerts_enabled"])
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_UP, response_time=100)
        mock_get.return_value = Mock(
            status_code=503,
            elapsed=Mock(total_seconds=Mock(return_value=0.123)),
        )

        run_single_check(self.website)

        mock_send_email.assert_not_called()
        self.assertTrue(Alert.objects.filter(website=self.website, alert_type=Alert.TYPE_DOWN).exists())

    def test_profile_and_settings_require_authentication(self):
        self.client.logout()

        profile_response = self.client.get(reverse("profile"))
        settings_response = self.client.get(reverse("settings"))

        self.assertEqual(profile_response.status_code, 302)
        self.assertEqual(settings_response.status_code, 302)
        self.assertIn("/login/", profile_response.url)
        self.assertIn("/login/", settings_response.url)

    def test_delete_account_requires_password_and_confirmation_then_logs_out(self):
        response = self.client.post(
            reverse("profile"),
            {
                "profile_action": "delete_account",
                "password": "StrongPass123!",
                "confirm_delete": "on",
            },
        )

        self.assertRedirects(response, reverse("index"))
        self.assertFalse(User.objects.filter(username="account-user").exists())

    def test_delete_account_requires_confirmation_checkbox(self):
        response = self.client.post(
            reverse("profile"),
            {
                "profile_action": "delete_account",
                "password": "StrongPass123!",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Confirm account deletion to continue.")
        self.assertTrue(User.objects.filter(username="account-user").exists())


class EmailDiagnosticsTests(TestCase):
    @override_settings(
        EMAIL_BACKEND="brevo_api",
        BREVO_API_KEY="",
        DEFAULT_FROM_EMAIL="SiteGuard Alerts <sender@example.com>",
    )
    def test_send_siteguard_email_returns_false_when_brevo_api_is_incomplete(self):
        sent = send_siteguard_email(
            subject="Diagnostic test",
            text_body="Hello",
            recipients=["user@example.com"],
            log_context={"flow": "unit_test"},
        )

        self.assertFalse(sent)

    @override_settings(
        EMAIL_BACKEND="brevo_api",
        BREVO_API_KEY="brevo-api-key",
        DEFAULT_FROM_EMAIL="SiteGuard Alerts <user@example.com>",
    )
    @patch("monitor.emailing.requests.post")
    def test_send_siteguard_email_uses_brevo_api_transport(self, mock_post):
        mock_post.return_value = Mock(
            status_code=201,
            content=b'{"messageId":"<brevo-message-id>"}',
            json=Mock(return_value={"messageId": "<brevo-message-id>"}),
            raise_for_status=Mock(),
        )
        sent = send_siteguard_email(
            subject="Diagnostic test",
            text_body="Hello",
            recipients=["user@example.com"],
            log_context={"flow": "unit_test"},
        )

        self.assertTrue(sent)
        mock_post.assert_called_once()
        self.assertEqual(mock_post.call_args.kwargs["headers"]["api-key"], "brevo-api-key")
        self.assertEqual(mock_post.call_args.kwargs["json"]["textContent"], "Hello")

    @override_settings(
        EMAIL_BACKEND="brevo_api",
        BREVO_API_KEY="brevo-api-key",
        DEFAULT_FROM_EMAIL="SiteGuard Alerts <user@example.com>",
    )
    @patch("monitor.emailing.requests.post", side_effect=requests.Timeout("timed out"))
    def test_send_siteguard_email_can_surface_brevo_timeout_for_test_flow(self, _mock_post):
        with self.assertRaises(requests.Timeout):
            send_siteguard_email(
                subject="Diagnostic test",
                text_body="Hello",
                recipients=["user@example.com"],
                log_context={"flow": "unit_test"},
                raise_on_error=True,
            )

    @override_settings(
        EMAIL_BACKEND="brevo_api",
        BREVO_API_KEY="brevo-api-key",
        DEFAULT_FROM_EMAIL="SiteGuard Alerts <user@example.com>",
    )
    @patch("monitor.emailing.requests.post", side_effect=requests.Timeout("timed out"))
    def test_test_email_command_surfaces_real_brevo_error(self, _mock_post):
        stdout = io.StringIO()
        call_command("test_email", "user@example.com", stdout=stdout)
        output = stdout.getvalue()
        self.assertIn("Email diagnostics:", output)
        self.assertIn("'configured': True", output)
        self.assertIn("'provider': 'brevo_api'", output)
        self.assertIn("Timeout", output)

    @override_settings(
        EMAIL_BACKEND="brevo_api",
        BREVO_API_KEY="brevo-api-key",
        DEFAULT_FROM_EMAIL="SiteGuard Alerts <sender@example.com>",
    )
    @patch("monitor.emailing.requests.post")
    def test_send_siteguard_email_uses_html_content_for_brevo_api_requests(self, mock_post):
        mock_post.return_value = Mock(
            status_code=201,
            content=b'{"messageId":"<brevo-message-id>"}',
            json=Mock(return_value={"messageId": "<brevo-message-id>"}),
            raise_for_status=Mock(),
        )
        sent = send_siteguard_email(
            subject="Diagnostic test",
            text_body="Hello",
            html_body="<p>Hello</p>",
            recipients=["user@example.com"],
            log_context={"flow": "unit_test"},
        )

        self.assertTrue(sent)
        self.assertEqual(mock_post.call_args.kwargs["json"]["htmlContent"], "<p>Hello</p>")


class AdminBootstrapCommandTests(TestCase):
    def setUp(self):
        self.env_patch = patch.dict(
            os.environ,
            {
                "DJANGO_ADMIN_USERNAME": "render-admin",
                "DJANGO_ADMIN_EMAIL": "render-admin@example.com",
                "DJANGO_ADMIN_PASSWORD": "StrongAdminPass123!",
            },
            clear=False,
        )
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()

    def test_bootstrap_admin_command_creates_superuser(self):
        stdout = io.StringIO()

        call_command("bootstrap_admin", stdout=stdout)

        user = User.objects.get(username="render-admin")
        output = stdout.getvalue()
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_active)
        self.assertTrue(user.check_password("StrongAdminPass123!"))
        self.assertIn('created superuser "render-admin" successfully', output)
        self.assertNotIn("StrongAdminPass123!", output)

    def test_bootstrap_admin_command_updates_existing_user_idempotently(self):
        user = User.objects.create_user(
            username="render-admin",
            email="old@example.com",
            password="OldPassword123!",
            is_staff=False,
            is_superuser=False,
            is_active=False,
        )
        stdout = io.StringIO()

        call_command("bootstrap_admin", stdout=stdout)

        user.refresh_from_db()
        output = stdout.getvalue()
        self.assertEqual(User.objects.filter(username="render-admin").count(), 1)
        self.assertEqual(user.email, "render-admin@example.com")
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_active)
        self.assertTrue(user.check_password("StrongAdminPass123!"))
        self.assertIn('updated superuser "render-admin" successfully', output)
        self.assertNotIn("StrongAdminPass123!", output)

    def test_bootstrap_admin_command_can_claim_existing_email_safely(self):
        user = User.objects.create_user(
            username="legacy-admin",
            email="render-admin@example.com",
            password="OldPassword123!",
            is_staff=False,
            is_superuser=False,
            is_active=False,
        )

        call_command("bootstrap_admin", stdout=io.StringIO())

        user.refresh_from_db()
        self.assertEqual(user.username, "render-admin")
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_active)
        self.assertTrue(user.check_password("StrongAdminPass123!"))

    def test_bootstrap_admin_command_fails_clearly_when_env_missing(self):
        with patch.dict(os.environ, {"DJANGO_ADMIN_PASSWORD": ""}, clear=False):
            with self.assertRaisesMessage(CommandError, "DJANGO_ADMIN_PASSWORD"):
                call_command("bootstrap_admin", stdout=io.StringIO())


class ImmediateMonitoringTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="instant-user",
            password="StrongPass123!",
            email="instant@example.com",
        )
        self.client.login(username="instant-user", password="StrongPass123!")

    @patch("monitor.views.run_single_check")
    def test_add_website_runs_initial_monitoring_immediately(self, mock_run_single_check):
        response = self.client.post(reverse("add_website"), {"url": "example.com"})

        self.assertRedirects(response, reverse("dashboard"))
        website = Website.objects.get(user=self.user, url="https://example.com")
        mock_run_single_check.assert_called_once_with(website)

    @patch("monitor.views.run_single_check", side_effect=RuntimeError("network unavailable"))
    def test_add_website_keeps_site_when_initial_check_fails(self, mock_run_single_check):
        response = self.client.post(reverse("add_website"), {"url": "example.com"}, follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(Website.objects.filter(user=self.user, url="https://example.com").exists())
        self.assertContains(
            response,
            "Website added, but the initial monitoring check could not complete.",
        )
        mock_run_single_check.assert_called_once()


class NotificationAndSearchTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="notify-user",
            password="StrongPass123!",
            email="notify@example.com",
        )
        self.client.login(username="notify-user", password="StrongPass123!")
        self.website = Website.objects.create(user=self.user, url="https://example.com")

    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    @patch("monitor.utils.requests.get")
    def test_outage_notification_is_created_once_without_spam(self, mock_get, _mock_ssl):
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_UP, response_time=100)
        mock_get.return_value = Mock(
            status_code=503,
            elapsed=Mock(total_seconds=Mock(return_value=0.2)),
        )

        run_single_check(self.website)
        run_single_check(self.website)

        notifications = Notification.objects.filter(user=self.user, notification_type=Notification.TYPE_OUTAGE)
        self.assertEqual(notifications.count(), 1)

    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    @patch("monitor.utils.requests.get")
    def test_recovery_notification_is_created(self, mock_get, _mock_ssl):
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_UP, response_time=100)
        mock_get.return_value = Mock(
            status_code=503,
            elapsed=Mock(total_seconds=Mock(return_value=0.2)),
        )
        run_single_check(self.website)

        mock_get.return_value = Mock(
            status_code=200,
            elapsed=Mock(total_seconds=Mock(return_value=0.1)),
        )
        run_single_check(self.website)

        self.assertTrue(Notification.objects.filter(user=self.user, notification_type=Notification.TYPE_RECOVERY).exists())

    def test_notifications_page_filters_and_mark_read_work(self):
        unread = Notification.objects.create(
            user=self.user,
            title="Critical outage",
            message="example.com down",
            notification_type=Notification.TYPE_OUTAGE,
            severity=Notification.SEVERITY_CRITICAL,
            related_website=self.website,
        )
        Notification.objects.create(
            user=self.user,
            title="Weekly report",
            message="report ready",
            notification_type=Notification.TYPE_REPORT,
            severity=Notification.SEVERITY_INFO,
            related_website=self.website,
            is_read=True,
        )

        response = self.client.get(reverse("notifications"), {"severity": "critical", "unread": "1"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Critical outage")
        self.assertEqual(len(response.context["notifications"]), 1)
        self.assertEqual(response.context["notifications"][0].title, "Critical outage")

        mark_response = self.client.post(reverse("mark_notification_read", args=[unread.id]), {"next": reverse("notifications")})
        self.assertRedirects(mark_response, reverse("notifications"))
        unread.refresh_from_db()
        self.assertTrue(unread.is_read)

    def test_notifications_page_supports_query_filter_and_groups(self):
        Notification.objects.create(
            user=self.user,
            title="SSL warning for example.com",
            message="certificate warning",
            notification_type=Notification.TYPE_SSL,
            severity=Notification.SEVERITY_WARNING,
            related_website=self.website,
        )
        Notification.objects.create(
            user=self.user,
            title="Weekly report ready",
            message="report generated",
            notification_type=Notification.TYPE_REPORT,
            severity=Notification.SEVERITY_INFO,
            is_read=True,
        )

        response = self.client.get(reverse("notifications"), {"q": "certificate"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "SSL warning for example.com")
        self.assertEqual(len(response.context["notifications"]), 1)
        self.assertEqual(response.context["notifications"][0].title, "SSL warning for example.com")
        self.assertEqual(len(response.context["notification_groups"]), 1)
        self.assertEqual(response.context["notification_groups"][0]["title"], "Unread")

    def test_create_notification_from_alert_reuses_recent_matching_notification(self):
        incident = Incident.objects.create(
            website=self.website,
            title="Complete Outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_DOWN,
            started_at=timezone.now(),
            latest_response_time=0,
        )
        alert = Alert.objects.create(
            website=self.website,
            incident=incident,
            alert_type=Alert.TYPE_DOWN,
            status=Alert.STATUS_SENT,
            message="example.com is down",
            response_time=0,
        )

        first = create_notification_from_alert(alert)
        first.is_read = True
        first.save(update_fields=["is_read"])
        second = create_notification_from_alert(alert)

        self.assertEqual(first.id, second.id)
        self.assertEqual(Notification.objects.filter(user=self.user, related_incident=incident).count(), 1)

    def test_notifications_view_cleans_up_old_read_items_and_prioritizes_unread(self):
        stale = Notification.objects.create(
            user=self.user,
            title="Old weekly report",
            message="older operational context",
            notification_type=Notification.TYPE_REPORT,
            severity=Notification.SEVERITY_INFO,
            is_read=True,
        )
        Notification.objects.filter(id=stale.id).update(created_at=timezone.now() - timedelta(days=60))

        warning_read = Notification.objects.create(
            user=self.user,
            title="Read warning",
            message="already reviewed",
            notification_type=Notification.TYPE_WARNING,
            severity=Notification.SEVERITY_WARNING,
            is_read=True,
        )
        critical_unread = Notification.objects.create(
            user=self.user,
            title="Unread outage",
            message="needs action",
            notification_type=Notification.TYPE_OUTAGE,
            severity=Notification.SEVERITY_CRITICAL,
            is_read=False,
            related_website=self.website,
        )

        response = self.client.get(reverse("notifications"))

        self.assertEqual(response.status_code, 200)
        self.assertFalse(Notification.objects.filter(id=stale.id).exists())
        self.assertEqual(response.context["notifications"][0].id, critical_unread.id)
        self.assertIn("Unread", [group["title"] for group in response.context["notification_groups"]])
        self.assertTrue(Notification.objects.filter(id=warning_read.id).exists())

    def test_recent_notifications_prioritize_unread_before_read_items(self):
        older_unread = Notification.objects.create(
            user=self.user,
            title="Unread warning",
            message="requires acknowledgement",
            notification_type=Notification.TYPE_WARNING,
            severity=Notification.SEVERITY_WARNING,
            is_read=False,
        )
        Notification.objects.filter(id=older_unread.id).update(created_at=timezone.now() - timedelta(hours=2))
        older_unread.refresh_from_db()

        newer_read = Notification.objects.create(
            user=self.user,
            title="Read report",
            message="already reviewed",
            notification_type=Notification.TYPE_REPORT,
            severity=Notification.SEVERITY_INFO,
            is_read=True,
        )

        recent = get_recent_notifications(self.user, limit=2)

        self.assertEqual(recent[0].id, older_unread.id)
        self.assertEqual(recent[1].id, newer_read.id)

    def test_report_notification_resolves_to_weekly_report_destination_and_activity_center(self):
        report_notification = Notification.objects.create(
            user=self.user,
            title="Weekly report ready for 2026-W20",
            message="report generated",
            notification_type=Notification.TYPE_REPORT,
            severity=Notification.SEVERITY_INFO,
        )

        destination = get_notification_destination(report_notification)
        activity_center = build_notification_activity_center(self.user)

        self.assertEqual(destination, reverse("weekly_report_detail", args=["2026-W20"]))
        self.assertTrue(any(section["title"] == "Recovery + Reports" for section in activity_center["sections"]))

    def test_mark_all_notifications_read_and_delete(self):
        first = Notification.objects.create(
            user=self.user,
            title="First",
            message="one",
            notification_type=Notification.TYPE_INFO,
            severity=Notification.SEVERITY_INFO,
        )
        second = Notification.objects.create(
            user=self.user,
            title="Second",
            message="two",
            notification_type=Notification.TYPE_WARNING,
            severity=Notification.SEVERITY_WARNING,
        )

        response = self.client.post(reverse("mark_all_notifications_read"), {"next": reverse("notifications")})
        self.assertRedirects(response, reverse("notifications"))
        self.assertEqual(Notification.objects.filter(user=self.user, is_read=False).count(), 0)

        delete_response = self.client.post(reverse("delete_notification", args=[first.id]), {"next": reverse("notifications")})
        self.assertRedirects(delete_response, reverse("notifications"))
        self.assertFalse(Notification.objects.filter(id=first.id).exists())
        self.assertTrue(Notification.objects.filter(id=second.id).exists())

    def test_reports_view_creates_weekly_report_notification(self):
        response = self.client.get(reverse("reports"))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(Notification.objects.filter(user=self.user, notification_type=Notification.TYPE_REPORT).exists())

    def test_global_search_results_and_suggestions_render_real_data(self):
        Notification.objects.create(
            user=self.user,
            title="SSL warning for example.com",
            message="certificate warning",
            notification_type=Notification.TYPE_SSL,
            severity=Notification.SEVERITY_WARNING,
            related_website=self.website,
        )
        incident = Incident.objects.create(
            website=self.website,
            title="Complete Outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_DOWN,
            started_at=timezone.now(),
            latest_response_time=0,
        )
        Alert.objects.create(
            website=self.website,
            incident=incident,
            alert_type=Alert.TYPE_DOWN,
            status=Alert.STATUS_SENT,
            message="example.com down",
        )
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_DOWN, response_time=0)

        response = self.client.get(reverse("search"), {"q": "example"})
        suggestions = self.client.get(reverse("search_suggestions"), {"q": "example"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Websites")
        self.assertContains(response, "Notifications")
        self.assertContains(response, "Logs")
        self.assertEqual(suggestions.status_code, 200)
        self.assertGreater(len(suggestions.json()["results"]), 0)

    def test_legal_pages_and_shared_glass_header_load(self):
        dashboard_response = self.client.get(reverse("dashboard"))
        privacy_response = self.client.get(reverse("legal_page", args=["privacy"]))
        terms_response = self.client.get(reverse("legal_page", args=["terms"]))

        self.assertEqual(dashboard_response.status_code, 200)
        self.assertContains(dashboard_response, "unified-glass-header")
        self.assertEqual(privacy_response.status_code, 200)
        self.assertContains(privacy_response, "Privacy Policy")
        self.assertEqual(terms_response.status_code, 200)
        self.assertContains(terms_response, "Terms")

    def test_shared_sidebar_includes_error_analyzer_on_authenticated_pages(self):
        pages = [
            reverse("dashboard"),
            reverse("reports"),
            reverse("alerts"),
            reverse("logs"),
            reverse("incidents"),
            reverse("utilities"),
            reverse("profile"),
            reverse("status"),
            reverse("error_log_upload"),
        ]

        for page in pages:
            response = self.client.get(page)
            self.assertEqual(response.status_code, 200, page)
            self.assertContains(response, "Error Analyzer")
            self.assertContains(response, "Profile")
