from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse


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
