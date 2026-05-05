from io import StringIO
from unittest.mock import Mock, patch

from django.core.management import call_command
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from monitor.models import MonitorLog, Website


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
    @patch("monitor.management.commands.monitor_sites.requests.get")
    def test_sends_email_only_when_site_transitions_from_up_to_down(self, mock_get, mock_send_mail):
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_UP, response_time=123)
        mock_get.return_value = Mock(status_code=500)

        call_command("monitor_sites", stdout=StringIO())

        self.assertEqual(mock_send_mail.call_count, 1)
        args = mock_send_mail.call_args.args
        self.assertIn("is DOWN", args[0])
        self.assertEqual(args[3], [self.user.email])

    @patch("monitor.management.commands.monitor_sites.send_mail")
    @patch("monitor.management.commands.monitor_sites.requests.get")
    def test_does_not_send_duplicate_email_when_site_is_already_down(self, mock_get, mock_send_mail):
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_DOWN, response_time=0)
        mock_get.return_value = Mock(status_code=500)

        call_command("monitor_sites", stdout=StringIO())

        mock_send_mail.assert_not_called()
