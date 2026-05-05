from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


class LoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(strip=False, widget=forms.PasswordInput)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].widget.attrs.update(
            {
                "class": "auth-input",
                "placeholder": "Enter your username",
                "autocomplete": "username",
                "autofocus": True,
            }
        )
        self.fields["password"].widget.attrs.update(
            {
                "class": "auth-input",
                "placeholder": "Enter your password",
                "autocomplete": "current-password",
                "id": "id_password",
            }
        )


class SignUpForm(UserCreationForm):
    class Meta:
        model = User
        fields = ("username", "password1", "password2")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].help_text = None
        self.fields["password1"].help_text = None
        self.fields["password2"].help_text = None

        self.fields["username"].widget.attrs.update(
            {
                "class": "auth-input",
                "placeholder": "Choose a username",
                "autocomplete": "username",
                "autofocus": True,
            }
        )
        self.fields["password1"].widget.attrs.update(
            {
                "class": "auth-input",
                "placeholder": "Create a strong password",
                "autocomplete": "new-password",
                "id": "id_password1",
            }
        )
        self.fields["password2"].widget.attrs.update(
            {
                "class": "auth-input",
                "placeholder": "Confirm your password",
                "autocomplete": "new-password",
                "id": "id_password2",
            }
        )
