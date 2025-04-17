from django.core.exceptions import ValidationError
import re

class NumberValidator:
    def validate(self, password, user=None):
        if not re.search(r'\d', password):
            raise ValidationError(
                "The password must contain at least 1 number.",
                code='password_no_number',
            )

    def get_help_text(self):
        return "Your password must contain at least 1 number."

class LetterValidator:
    def validate(self, password, user=None):
        if not re.search(r'[a-zA-Z]', password):
            raise ValidationError(
                "The password must contain at least 1 letter.",
                code='password_no_letter',
            )

    def get_help_text(self):
        return "Your password must contain at least 1 letter."

class SymbolValidator:
    def validate(self, password, user=None):
        if not re.search(r'[()[\]{}|\\`~!@#$%^&*_+=\-;:\"\'<>?,./]', password):
            raise ValidationError(
                "The password must contain at least 1 symbol.",
                code='password_no_symbol',
            )

    def get_help_text(self):
        return "Your password must contain at least 1 symbol."

class NotEqualToExistingPasswordValidator:
    def validate(self, password, user=None):
        if user is not None and user.check_password(password):
            raise ValidationError(
                "Your new password cannot be the same as your current password.",
                code='password_same_as_current',
            )

    def get_help_text(self):
        return "Your new password cannot be the same as your current password."