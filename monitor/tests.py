from io import StringIO
from unittest.mock import Mock, patch

from django.core.management import call_command
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from monitor.models import MonitorLog, Website
from monitor.utils import get_favicon_url, get_site_status


class AuthFlowTests(TestCase):
    def test_login_page_creates_default_admin_user(self):
        self.client.get(reverse("login"))

        admin_user = User.objects.get(username="admin")
        self.assertEqual(admin_user.email, "admin@example.com")
        self.assertTrue(admin_user.check_password("admin123"))
        self.assertTrue(admin_user.is_superuser)

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

    @patch("monitor.management.commands.monitor_sites.send_mail")
    @patch("monitor.utils.requests.get")
    def test_sends_email_only_when_site_transitions_from_up_to_down(self, mock_get, mock_send_mail):
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_UP, response_time=123)
        mock_get.return_value = Mock(
            status_code=500,
            elapsed=Mock(total_seconds=Mock(return_value=0.123)),
        )

        call_command("monitor_sites", stdout=StringIO())

        self.assertEqual(mock_send_mail.call_count, 1)
        args = mock_send_mail.call_args.args
        self.assertIn("is DOWN", args[0])
        self.assertEqual(args[3], [self.user.email])

    @patch("monitor.management.commands.monitor_sites.send_mail")
    @patch("monitor.utils.requests.get")
    def test_does_not_send_duplicate_email_when_site_is_already_down(self, mock_get, mock_send_mail):
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_DOWN, response_time=0)
        mock_get.return_value = Mock(
            status_code=500,
            elapsed=Mock(total_seconds=Mock(return_value=0.123)),
        )

        call_command("monitor_sites", stdout=StringIO())

        mock_send_mail.assert_not_called()


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

    @patch("monitor.views.run_single_check")
    def test_check_now_runs_shared_monitoring_logic_and_redirects(self, mock_run_single_check):
        response = self.client.get(reverse("check_now", args=[self.gmail.id]))

        mock_run_single_check.assert_called_once_with(self.gmail)
        self.assertRedirects(response, reverse("status"))

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
