import logging
import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError, transaction


logger = logging.getLogger("siteguard.runtime")


class Command(BaseCommand):
    help = "Create or update the configured Django superuser from environment variables."

    required_env_vars = (
        "DJANGO_ADMIN_USERNAME",
        "DJANGO_ADMIN_EMAIL",
        "DJANGO_ADMIN_PASSWORD",
    )

    def handle(self, *args, **options):
        config = self._load_config_from_env()
        user_model = get_user_model()

        try:
            with transaction.atomic():
                user, created = self._get_or_create_target_user(user_model, config)
                user.email = config["email"]
                user.is_staff = True
                user.is_superuser = True
                user.is_active = True
                user.set_password(config["password"])
                user.save()
        except IntegrityError as exc:
            logger.error(
                "Admin bootstrap failed because the target account conflicts with an existing user.",
                extra={
                    "admin_bootstrap": {
                        "username": config["username"],
                        "email": config["email"],
                    }
                },
            )
            raise CommandError(
                "Admin bootstrap failed because the configured username or email conflicts with an existing user."
            ) from exc

        action = "created" if created else "updated"
        logger.info(
            "Admin bootstrap %s successfully.",
            action,
            extra={
                "admin_bootstrap": {
                    "status": "success",
                    "action": action,
                    "username": user.get_username(),
                    "email": user.email,
                }
            },
        )
        self.stdout.write(
            self.style.SUCCESS(
                f'Admin bootstrap {action} superuser "{user.get_username()}" successfully.'
            )
        )

    def _load_config_from_env(self):
        values = {}
        missing_vars = []
        for env_name in self.required_env_vars:
            value = (os.environ.get(env_name) or "").strip()
            if not value:
                missing_vars.append(env_name)
            values[env_name] = value

        if missing_vars:
            logger.warning(
                "Admin bootstrap failed because required environment variables are missing.",
                extra={
                    "admin_bootstrap": {
                        "status": "failed",
                        "missing_env_vars": missing_vars,
                    }
                },
            )
            raise CommandError(
                "Missing required environment variables: " + ", ".join(missing_vars)
            )

        return {
            "username": values["DJANGO_ADMIN_USERNAME"],
            "email": values["DJANGO_ADMIN_EMAIL"],
            "password": values["DJANGO_ADMIN_PASSWORD"],
        }

    def _get_or_create_target_user(self, user_model, config):
        username = config["username"]
        email = config["email"]

        existing_by_username = user_model._default_manager.filter(username=username).first()
        if existing_by_username is not None:
            return existing_by_username, False

        email_field = getattr(user_model, "EMAIL_FIELD", "email")
        existing_by_email = (
            user_model._default_manager.filter(**{f"{email_field}__iexact": email}).first()
        )
        if existing_by_email is not None:
            existing_by_email.username = username
            return existing_by_email, False

        return user_model._default_manager.create(
            username=username,
            email=email,
            is_staff=True,
            is_superuser=True,
            is_active=True,
        ), True
