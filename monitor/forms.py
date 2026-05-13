from django import forms
from django.contrib.auth.forms import PasswordChangeForm, UserCreationForm
from django.contrib.auth.models import User
from django.core.files.images import get_image_dimensions
from .models import UploadedLog, UserProfile


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
        for field_name in self.fields:
            self.fields[field_name].widget.attrs.update({'class': 'custom-toggle-input'})


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
            self.fields[field_name].widget.attrs.update({'class': 'custom-toggle-input'})


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
    allowed_extensions = {'.txt', '.log'}
    max_file_size = 5 * 1024 * 1024

    class Meta:
        model = UploadedLog
        fields = ('file',)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['file'].widget.attrs.update({
            'class': 'form-control custom-input',
            'accept': '.txt,.log,text/plain',
        })
        self.fields['file'].help_text = 'Upload a .txt or .log file up to 5 MB.'

    def clean_file(self):
        uploaded_file = self.cleaned_data.get('file')
        if not uploaded_file:
            raise forms.ValidationError('Select a log file to upload.')

        file_name = (uploaded_file.name or '').lower()
        if not any(file_name.endswith(ext) for ext in self.allowed_extensions):
            raise forms.ValidationError('Only .txt and .log files are supported.')

        if uploaded_file.size > self.max_file_size:
            raise forms.ValidationError('Log files must be 5 MB or smaller.')

        content_type = getattr(uploaded_file, 'content_type', '')
        if content_type and content_type not in {'text/plain', 'application/octet-stream'}:
            raise forms.ValidationError('Unsupported file type.')

        return uploaded_file
