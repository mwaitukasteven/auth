from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six
from django.utils import timezone
from datetime import timedelta

class AccountActivationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        # Include the timestamp in the hash value
        return (
            six.text_type(user.pk) + 
            six.text_type(timestamp) + 
            six.text_type(user.is_active)
        )
    
    def check_token(self, user, token):
        """
        Check that the token is valid and not expired (5 minutes)
        """
        if not (user and token):
            return False
            
        # Parse the token
        try:
            ts_b36, _ = token.split("-")
        except ValueError:
            return False
            
        try:
            ts = int(ts_b36, 36)
        except ValueError:
            return False
            
        # Check if the token is expired (5 minutes)
        if (timezone.now() - timezone.datetime.fromtimestamp(ts, tz=timezone.utc)) > timedelta(minutes=5):
            return False
            
        return super().check_token(user, token)

account_activation_token = AccountActivationTokenGenerator()