# In api/validators.py

import re
from django.core.exceptions import ValidationError
from .models import SystemSettings

class GxPUsernameValidator:
    def __call__(self, username):
        settings, _ = SystemSettings.objects.get_or_create(pk=1)
        if len(username) < settings.username_min_length:
            raise ValidationError(f"Username must be at least {settings.username_min_length} characters long.")
        if len(username) > settings.username_max_length:
            raise ValidationError(f"Username cannot be more than {settings.username_max_length} characters long.")
        if not settings.username_allow_capitals and re.search(r'[A-Z]', username):
            raise ValidationError("Usernames cannot contain capital letters as per system policy.")
        if not settings.username_allow_numbers and re.search(r'[0-9]', username):
            raise ValidationError("Usernames cannot contain numbers as per system policy.")

class GxPPasswordValidator:
    def __init__(self, user=None):
        self.user = user

    def __call__(self, password):
        settings, _ = SystemSettings.objects.get_or_create(pk=1)

        if len(password) < settings.password_min_length:
            raise ValidationError(f"Password must be at least {settings.password_min_length} characters long.")
        if len(password) > settings.password_max_length:
            raise ValidationError(f"Password cannot be more than {settings.password_max_length} characters long.")

        if settings.enforce_password_complexity and settings.password_complexity_regex:
            if not re.search(settings.password_complexity_regex, password):
                raise ValidationError("Password does not meet the complexity requirements set by the administrator.")

        if self.user and settings.password_prevent_username_sequence:
            username = self.user.username.lower()
            if len(username) >= 4:
                for i in range(len(username) - 3):
                    if username[i:i+4] in password.lower():
                        raise ValidationError("Password cannot contain a sequence of 4 or more characters from the username.")

        if self.user and settings.password_history_count > 0:
            from django.contrib.auth.hashers import check_password
            recent_passwords = self.user.password_history.all()[:settings.password_history_count]
            for record in recent_passwords:
                if check_password(password, record.password_hash):
                    raise ValidationError("This password has been used recently and cannot be reused.")