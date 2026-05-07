from datetime import timedelta

from unittest.mock import Mock, patch

import requests
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from monitor.models import Alert, Incident, IncidentEvent, MonitorLog, Website
from monitor.utils import (
    analyze_domain,
    cleanup_monitoring_state,
    get_favicon_url,
    get_site_status,
    normalize_domain_display,
    run_single_check,
    safe_url_decode,
    safe_url_encode,
)


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

    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    @patch("monitor.utils.send_mail")
    @patch("monitor.utils.requests.get")
    def test_sends_email_only_when_site_transitions_from_up_to_down(self, mock_get, mock_send_mail, _mock_ssl):
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_UP, response_time=123)
        mock_get.return_value = Mock(
            status_code=500,
            elapsed=Mock(total_seconds=Mock(return_value=0.123)),
        )

        run_single_check(self.website)

        self.assertEqual(mock_send_mail.call_count, 1)
        args = mock_send_mail.call_args.args
        self.assertIn("is DOWN", args[0])
        self.assertEqual(args[3], [self.user.email])
        self.assertEqual(Alert.objects.filter(website=self.website, alert_type=Alert.TYPE_DOWN).count(), 1)

    @patch("monitor.utils.check_ssl_status", return_value="Valid")
    @patch("monitor.utils.send_mail")
    @patch("monitor.utils.requests.get")
    def test_does_not_send_duplicate_email_when_active_down_alert_exists(self, mock_get, mock_send_mail, _mock_ssl):
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

    def test_normalize_domain_display_removes_scheme_www_and_trailing_slash(self):
        self.assertEqual(normalize_domain_display("https://www.reddit.com/"), "reddit.com")
        self.assertEqual(normalize_domain_display("https://mail.google.com/"), "mail.google.com")
        self.assertEqual(normalize_domain_display("https://abc-not-real-999.com"), "abc-not-real-999.com")

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
    @patch("monitor.utils.send_mail")
    @patch("monitor.utils.requests.get")
    def test_recovery_alert_is_created_when_incident_resolves(self, mock_get, mock_send_mail, _mock_ssl):
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
        self.assertGreaterEqual(mock_send_mail.call_count, 2)

    @patch("monitor.utils.send_mail", side_effect=Exception("SMTP failed"))
    def test_retry_failed_alert_action_updates_status(self, _mock_send_mail):
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

    @patch("monitor.utils.send_mail")
    @patch("monitor.utils.check_ssl_status", return_value="Invalid")
    @patch("monitor.utils.requests.get")
    def test_ssl_alert_and_incident_are_created_once(self, mock_get, _mock_ssl, _mock_send_mail):
        MonitorLog.objects.create(website=self.website, status=MonitorLog.STATUS_UP, response_time=100)
        mock_get.return_value = Mock(
            status_code=200,
            elapsed=Mock(total_seconds=Mock(return_value=0.2)),
        )

        run_single_check(self.website)
        run_single_check(self.website)

        self.assertEqual(Alert.objects.filter(website=self.website, alert_type=Alert.TYPE_SSL).count(), 1)
        self.assertEqual(Incident.objects.filter(website=self.website, incident_type=Incident.TYPE_SSL).count(), 1)

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

    def test_cleanup_resolves_duplicate_active_incidents_per_website_and_type(self):
        first = Incident.objects.create(
            website=self.website,
            title="Complete Outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_DOWN,
            started_at=timezone.now(),
            latest_response_time=0,
        )
        second = Incident.objects.create(
            website=self.website,
            title="Complete Outage",
            incident_type=Incident.TYPE_OUTAGE,
            status=Incident.STATUS_DOWN,
            started_at=timezone.now() + timedelta(minutes=1),
            latest_response_time=0,
        )

        cleanup_monitoring_state(user=self.user)

        unresolved = Incident.objects.filter(
            website=self.website,
            incident_type=Incident.TYPE_OUTAGE,
            is_resolved=False,
        )
        self.assertEqual(unresolved.count(), 1)
        resolved_duplicate = Incident.objects.get(pk=first.pk)
        self.assertTrue(resolved_duplicate.is_resolved or second.is_resolved)

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
        self.assertContains(response, "No monitoring data yet")

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
