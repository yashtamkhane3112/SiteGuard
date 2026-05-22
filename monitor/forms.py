import logging

from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordChangeForm, PasswordResetForm, SetPasswordForm, UserCreationForm
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.files.images import get_image_dimensions
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from .emailing import build_password_reset_email_options, render_email_template, send_siteguard_email
from .models import UploadedLog, UserProfile

password_reset_logger = logging.getLogger("siteguard.email")


class LoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(strip=False, widget=forms.PasswordInput)
    remember_me = forms.BooleanField(required=False, initial=True)

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
        self.fields["remember_me"].widget.attrs.update(
            {
                "class": "form-check-input",
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


class SiteGuardPasswordResetForm(PasswordResetForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._last_send_succeeded = None
        self.fields["email"].widget.attrs.update(
            {
                "class": "auth-input",
                "placeholder": "you@example.com",
                "autocomplete": "email",
            }
        )

    def clean_email(self):
        email = self.cleaned_data.get("email", "")
        password_reset_logger.info(
            "Password reset form email validated.",
            extra={
                "email_context": {
                    "flow": "password_reset",
                    "stage": "form_validation",
                    "form_class": self.__class__.__name__,
                    "submitted_email": email,
                }
            },
        )
        return email

    def get_users(self, email):
        user_model = get_user_model()
        email_field_name = user_model.get_email_field_name()
        exact_matches = list(
            user_model._default_manager.filter(**{f"{email_field_name}__iexact": email}).order_by("id")
        )
        eligible_users = list(super().get_users(email))

        password_reset_logger.info(
            "Password reset user lookup completed.",
            extra={
                "email_context": {
                    "flow": "password_reset",
                    "stage": "user_lookup",
                    "form_class": self.__class__.__name__,
                    "submitted_email": email,
                    "email_field": email_field_name,
                    "matched_users_count": len(exact_matches),
                    "eligible_users_count": len(eligible_users),
                    "matched_users": [
                        {
                            "id": user.id,
                            "username": user.get_username(),
                            "email": getattr(user, email_field_name, ""),
                            "is_active": user.is_active,
                            "has_usable_password": user.has_usable_password(),
                        }
                        for user in exact_matches
                    ],
                }
            },
        )
        return iter(eligible_users)

    def save(self, *args, **kwargs):
        email_options = build_password_reset_email_options(request=kwargs.get("request"))
        if not kwargs.get("from_email"):
            kwargs["from_email"] = email_options["from_email"]
        if not kwargs.get("html_email_template_name"):
            kwargs["html_email_template_name"] = email_options["html_email_template_name"]
        if not kwargs.get("extra_email_context"):
            kwargs["extra_email_context"] = email_options["extra_email_context"]
        if email_options.get("domain_override") and not kwargs.get("domain_override"):
            kwargs["domain_override"] = email_options["domain_override"]
        if "use_https" in email_options:
            kwargs["use_https"] = email_options["use_https"]
        domain_override = kwargs.get("domain_override")
        request = kwargs.get("request")
        use_https = kwargs.get("use_https", False)
        token_generator = kwargs.get("token_generator", default_token_generator)
        extra_email_context = kwargs.get("extra_email_context")
        subject_template_name = kwargs.get(
            "subject_template_name",
            "registration/password_reset_subject.txt",
        )
        email_template_name = kwargs.get(
            "email_template_name",
            "registration/password_reset_email.html",
        )
        html_email_template_name = kwargs.get("html_email_template_name")
        from_email = kwargs.get("from_email")
        email = self.cleaned_data["email"]

        if not domain_override:
            current_site = get_current_site(request)
            site_name = current_site.name
            domain = current_site.domain
        else:
            site_name = domain = domain_override

        email_field_name = get_user_model().get_email_field_name()
        sent_count = 0
        for user in self.get_users(email):
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = token_generator.make_token(user)
            user_email = getattr(user, email_field_name)
            password_reset_logger.info(
                "Password reset token generated.",
                extra={
                    "email_context": {
                        "flow": "password_reset",
                        "stage": "token_generation",
                        "user_id": user.pk,
                        "username": user.get_username(),
                        "email": user_email,
                        "is_active": user.is_active,
                        "uid": uid,
                        "token_preview": token[:12],
                        "token_length": len(token),
                    }
                },
            )
            context = {
                "email": user_email,
                "domain": domain,
                "site_name": site_name,
                "uid": uid,
                "user": user,
                "token": token,
                "protocol": "https" if use_https else "http",
                **(extra_email_context or {}),
            }
            self.send_mail(
                subject_template_name,
                email_template_name,
                context,
                from_email,
                user_email,
                html_email_template_name=html_email_template_name,
            )
            sent_count += 1

        if sent_count == 0:
            password_reset_logger.warning(
                "Password reset stopped before email send because no eligible users were found.",
                extra={
                    "email_context": {
                        "flow": "password_reset",
                        "stage": "pre_send_stop",
                        "submitted_email": email,
                        "form_class": self.__class__.__name__,
                    }
                },
            )
        return None

    def send_mail(
        self,
        subject_template_name,
        email_template_name,
        context,
        from_email,
        to_email,
        html_email_template_name=None,
    ):
        merged_context = {
            **context,
            "site_name": getattr(settings, "SITE_NAME", "SiteGuard"),
            "support_email": getattr(settings, "SUPPORT_EMAIL", ""),
            "email_subject_prefix": getattr(settings, "EMAIL_SUBJECT_PREFIX", ""),
        }
        subject = render_email_template(subject_template_name, merged_context)
        text_body = render_email_template(email_template_name, merged_context)
        html_body = (
            render_email_template(html_email_template_name, merged_context)
            if html_email_template_name
            else None
        )
        password_reset_logger.info(
            "Password reset email generation completed; entering send_siteguard_email.",
            extra={
                "email_context": {
                    "flow": "password_reset",
                    "stage": "send_mail_entry",
                    "form_class": self.__class__.__name__,
                    "recipient": to_email,
                    "user_id": getattr(context.get("user"), "pk", None),
                    "uid": context.get("uid", ""),
                    "token_preview": str(context.get("token", ""))[:12],
                    "token_length": len(str(context.get("token", ""))),
                    "subject": subject,
                    "html_template": html_email_template_name or "",
                }
            },
        )
        self._last_send_succeeded = send_siteguard_email(
            subject=subject,
            text_body=text_body,
            html_body=html_body,
            recipients=[to_email],
            from_email=from_email,
            log_context={
                "flow": "password_reset",
                "recipient": to_email,
            },
        )


class SiteGuardSetPasswordForm(SetPasswordForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        placeholders = {
            "new_password1": "Create a strong password",
            "new_password2": "Confirm the new password",
        }
        for field_name, field in self.fields.items():
            field.help_text = None
            field.widget.attrs.update(
                {
                    "class": "auth-input",
                    "placeholder": placeholders.get(field_name, ""),
                    "autocomplete": "new-password",
                }
            )


COMMON_TIMEZONES = [
    'UTC',
    'Asia/Calcutta',
    'Asia/Kolkata',
    'America/New_York',
    'America/Chicago',
    'America/Los_Angeles',
    'Europe/London',
    'Europe/Berlin',
    'Asia/Tokyo',
    'Australia/Sydney',
]
TIMEZONE_CHOICES = [(tz, tz) for tz in COMMON_TIMEZONES]


class ProfileUpdateForm(forms.Form):
    username = forms.CharField(max_length=150)
    email = forms.EmailField(required=False)
    avatar = forms.ImageField(required=False)

    allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}
    max_avatar_size = 2 * 1024 * 1024
    max_avatar_dimensions = (2000, 2000)

    def __init__(self, *args, user=None, profile=None, **kwargs):
        self.user = user
        self.profile = profile
        initial = kwargs.setdefault('initial', {})
        if user is not None:
            initial.setdefault('username', user.username)
            initial.setdefault('email', user.email)
        super().__init__(*args, **kwargs)

        self.fields['username'].widget.attrs.update({
            'class': 'form-control custom-input',
            'placeholder': 'Choose a username',
            'autocomplete': 'username',
        })
        self.fields['email'].widget.attrs.update({
            'class': 'form-control custom-input',
            'placeholder': 'you@example.com',
            'autocomplete': 'email',
        })
        self.fields['avatar'].widget.attrs.update({
            'class': 'form-control custom-input',
            'accept': '.jpg,.jpeg,.png,.gif,.webp,image/*',
        })

    def clean_username(self):
        username = (self.cleaned_data.get('username') or '').strip()
        if User.objects.exclude(pk=getattr(self.user, 'pk', None)).filter(username__iexact=username).exists():
            raise forms.ValidationError('That username is already in use.')
        return username

    def clean_email(self):
        email = (self.cleaned_data.get('email') or '').strip().lower()
        if email and User.objects.exclude(pk=getattr(self.user, 'pk', None)).filter(email__iexact=email).exists():
            raise forms.ValidationError('That email address is already in use.')
        return email

    def clean_avatar(self):
        avatar = self.cleaned_data.get('avatar')
        if not avatar:
            return avatar

        filename = (avatar.name or '').lower()
        if not any(filename.endswith(ext) for ext in self.allowed_extensions):
            raise forms.ValidationError('Upload a valid image file.')

        content_type = getattr(avatar, 'content_type', '')
        if content_type and not content_type.startswith('image/'):
            raise forms.ValidationError('Upload a valid image file.')

        if avatar.size > self.max_avatar_size:
            raise forms.ValidationError('Avatar must be 2 MB or smaller.')

        width, height = get_image_dimensions(avatar)
        max_width, max_height = self.max_avatar_dimensions
        if width and height and (width > max_width or height > max_height):
            raise forms.ValidationError(f'Avatar dimensions must not exceed {max_width}x{max_height}px.')

        if hasattr(avatar, 'seek'):
            avatar.seek(0)

        return avatar

    def save(self):
        self.user.username = self.cleaned_data['username']
        self.user.email = self.cleaned_data['email']
        self.user.save(update_fields=['username', 'email'])

        avatar = self.cleaned_data.get('avatar')
        if avatar:
            previous_avatar_name = self.profile.avatar.name if self.profile.avatar else ''
            self.profile.avatar = avatar
            self.profile.save(update_fields=['avatar', 'updated_at'])
            if previous_avatar_name and previous_avatar_name != self.profile.avatar.name:
                self.profile.avatar.storage.delete(previous_avatar_name)

        return self.user, self.profile


class AccountSecurityForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ('email_alerts_enabled', 'two_factor_enabled')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs.update({
                'class': 'custom-toggle-input',
                'aria-label': field.label,
            })


class AccountPreferencesForm(forms.ModelForm):
    timezone = forms.ChoiceField(choices=TIMEZONE_CHOICES)

    class Meta:
        model = UserProfile
        fields = (
            'timezone',
            'email_alerts_enabled',
            'ssl_alerts_enabled',
            'incident_alerts_enabled',
            'marketing_emails_enabled',
            'monitoring_frequency',
            'two_factor_enabled',
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['timezone'].widget.attrs.update({'class': 'form-select custom-input'})
        self.fields['monitoring_frequency'].widget.attrs.update({'class': 'form-select custom-input'})
        for field_name in (
            'email_alerts_enabled',
            'ssl_alerts_enabled',
            'incident_alerts_enabled',
            'marketing_emails_enabled',
            'two_factor_enabled',
        ):
            self.fields[field_name].widget.attrs.update({
                'class': 'custom-toggle-input',
                'aria-label': self.fields[field_name].label,
            })


class AccountPasswordChangeForm(PasswordChangeForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        placeholders = {
            'old_password': 'Current password',
            'new_password1': 'New password',
            'new_password2': 'Confirm new password',
        }
        for field_name, field in self.fields.items():
            field.help_text = None
            field.widget.attrs.update({
                'class': 'form-control custom-input',
                'placeholder': placeholders.get(field_name, ''),
                'autocomplete': 'current-password' if field_name == 'old_password' else 'new-password',
                'spellcheck': 'false',
            })


class DeleteAccountForm(forms.Form):
    password = forms.CharField(strip=False, widget=forms.PasswordInput)
    confirm_delete = forms.BooleanField(
        required=True,
        error_messages={'required': 'Confirm account deletion to continue.'},
    )

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
        self.fields['password'].widget.attrs.update({
            'class': 'form-control custom-input',
            'placeholder': 'Confirm your password',
            'autocomplete': 'current-password',
        })
        self.fields['confirm_delete'].widget.attrs.update({
            'class': 'form-check-input',
            'aria-label': 'Confirm permanent account deletion',
        })
        self.fields['confirm_delete'].label = 'I understand this action cannot be undone.'

    def clean_password(self):
        password = self.cleaned_data.get('password') or ''
        if self.user is None or not self.user.check_password(password):
            raise forms.ValidationError('Password confirmation failed.')
        return password

    def clean_confirm_delete(self):
        confirmed = self.cleaned_data.get('confirm_delete')
        if not confirmed:
            raise forms.ValidationError('Confirm account deletion to continue.')
        return confirmed


class UploadedLogForm(forms.ModelForm):
    allowed_extensions = {'.txt', '.log', '.json'}
    max_file_size = 5 * 1024 * 1024
    blocked_content_types = {
        'application/x-dosexec',
        'application/x-executable',
        'application/x-msdownload',
        'application/x-sh',
    }
    blocked_magic_prefixes = (
        b'MZ',
        b'\x7fELF',
        b'PK\x03\x04',
        b'Rar!\x1a\x07',
        b'\x89PNG\r\n\x1a\n',
        b'\xff\xd8\xff',
        b'%PDF',
    )

    class Meta:
        model = UploadedLog
        fields = ('file',)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['file'].widget.attrs.update({
            'class': 'form-control custom-input',
            'accept': '.txt,.log,.json,text/plain,application/json',
        })
        self.fields['file'].help_text = 'Upload a .txt, .log, or .json file up to 5 MB.'

    def clean_file(self):
        uploaded_file = self.cleaned_data.get('file')
        if not uploaded_file:
            raise forms.ValidationError('Select a log file to upload.')

        file_name = (uploaded_file.name or '').lower()
        if not any(file_name.endswith(ext) for ext in self.allowed_extensions):
            raise forms.ValidationError('Only .txt, .log, and .json diagnostic files are supported.')

        if uploaded_file.size > self.max_file_size:
            raise forms.ValidationError('Log files must be 5 MB or smaller.')

        content_type = (getattr(uploaded_file, 'content_type', '') or '').lower()
        if content_type in self.blocked_content_types:
            raise forms.ValidationError('Executable files are not supported.')

        header = uploaded_file.read(4096)
        if hasattr(uploaded_file, 'seek'):
            uploaded_file.seek(0)

        if b'\x00' in header:
            raise forms.ValidationError('Binary files are not supported. Upload plain text or JSON diagnostics only.')

        if any(header.startswith(prefix) for prefix in self.blocked_magic_prefixes):
            raise forms.ValidationError('Unsupported binary file format. Upload plain text or JSON diagnostics only.')

        return uploaded_file
