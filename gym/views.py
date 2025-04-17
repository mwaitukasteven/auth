from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.urls import reverse
from django.contrib.auth import get_user_model
from .tokens import account_activation_token
from django.http import HttpResponse
from django.contrib.auth.views import PasswordResetView, PasswordResetConfirmView
from django.urls import reverse_lazy
from django.core.exceptions import ValidationError
from django.conf import settings
from .validators import NumberValidator, LetterValidator, SymbolValidator, NotEqualToExistingPasswordValidator

# ✅ Home View
def home(request):
    return render(request, 'home.html')

# ✅ Email Verification Page
def email_verification(request):
    return render(request, 'email_verification.html')

# ✅ Email Confirmation Page
def email_confirmation(request):
    return render(request, 'email_confirmation.html')

# ✅ Register View (Handles Signup)
def register_view(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password1 = request.POST.get('password1', '').strip()
        password2 = request.POST.get('password2', '').strip()

        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            return render(request, 'register.html')

        try:
            # Apply custom password validators
            NumberValidator().validate(password1)
            LetterValidator().validate(password1)
            SymbolValidator().validate(password1)

        except ValidationError as e:
            messages.error(request, e)
            return render(request, 'register.html')

        User = get_user_model()

        # Check if the username or email already exists
        if User.objects.filter(username=username).exists():
            messages.error(request, "A user with this username already exists.")
            return render(request, 'register.html')
        if User.objects.filter(email=email).exists():
            messages.error(request, "A user with this email already exists.")
            return render(request, 'register.html')

        # Create the user
        user = User.objects.create_user(username=username, email=email, password=password1)
        user.is_active = False  # Deactivate account until it is confirmed
        user.save()

        # Send activation email
        current_site = get_current_site(request)
        mail_subject = 'Activate Your Account'
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = account_activation_token.make_token(user)
        activation_link = f"http://{current_site.domain}/activate/{uid}/{token}/"

        message = render_to_string('email_verification.html', {
            'user': user,
            'activation_link': activation_link,
        })

        send_mail(mail_subject, message, settings.DEFAULT_FROM_EMAIL, [email])

        messages.success(request, "Registration successful! Please check your email to activate your account.")
        return redirect('email_verification')  # Redirect to email verification page

    return render(request, 'register.html')

# ✅ Activate Account via Email
def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        User = get_user_model()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "Your account has been activated! You can now log in.")
        return redirect('login')
    else:
        messages.error(request, "Activation link is invalid or has expired. Please request a new activation link.")
        return redirect('register')

# ✅ Login View
def login_view(request):
    if request.method == "POST":
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()

        print(f"email: {email}, Password: {password}")  # Debugging: Check input values

        user = authenticate(request, username=email, password=password)

        if user is not None:
            if user.is_active:
                print(f"Authenticated User: {user}")  # Debugging: Check if user is authenticated
                login(request, user)
                messages.success(request, 'You logged in successfully')
                return redirect('dashboard')  # Redirect to the dashboard
            else:
                print("Account is not active")  # Debugging: Check if account is inactive
                messages.error(request, "Your account is not active. Please check your email to activate your account.")
                return redirect('login')
        else:
            print("Authentication failed")  # Debugging: Check if authentication failed
            messages.error(request, "Invalid email or password.")
            return redirect('login')

    return render(request, "login.html")

# ✅ Send Activation Email
def send_activation_email(user, to_email, request):
    try:
        current_site = get_current_site(request)
        mail_subject = 'Activate Your Account'
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = account_activation_token.make_token(user)
        activation_url = f"http://{current_site.domain}{reverse('activate', kwargs={'uidb64': uid, 'token': token})}"

        message = render_to_string('email_verification.html', {
            'user': user,
            'activation_url': activation_url,
        })

        send_mail(mail_subject, message, None, [to_email])
        print("Email sent successfully!")
    except Exception as e:
        print(f"Error sending email: {e}")


# ✅ Activate Account via Email
    
# ✅ Login View

@login_required
def change_password_view(request):
    if request.method == 'POST':
        new_password1 = request.POST.get('new_password1')
        new_password2 = request.POST.get('new_password2')
        user = request.user

        if new_password1 != new_password2:
            messages.error(request, "Passwords do not match.")
            return render(request, 'change_password.html')

        try:
            # Apply custom password validators
            NumberValidator().validate(new_password1, user)
            LetterValidator().validate(new_password1, user)
            SymbolValidator().validate(new_password1, user)
            NotEqualToExistingPasswordValidator().validate(new_password1, user)

        except ValidationError as e:
            messages.error(request, e)
            return render(request, 'change_password.html')

        user.set_password(new_password1)
        user.save()
        update_session_auth_hash(request, user)
        messages.success(request, "Password changed successfully.")
        return redirect('profile')

    return render(request, 'change_password.html')

# ✅ Logout View
@login_required
def logout_view(request):
    logout(request)
    messages.success(request, "You have been logged out.")
    return redirect('home')  # Always redirect to homepage

@login_required
def dashboard(request):
    return render(request, 'dashboard.html')

# ✅ Profile Page (Change Password)
@login_required
def profile(request):
    if request.method == "POST":
        new_password = request.POST.get('new_password', '').strip()
        confirm_password = request.POST.get('confirm_password', '').strip()

        if new_password == confirm_password:
            request.user.set_password(new_password)
            request.user.save()
            messages.success(request, "Password changed successfully. Please log in again.")
            return redirect('login')
        else:
            messages.error(request, "Passwords do not match.")
    return render(request, 'profile.html')

# ✅ Test Email View
def test_email_view(request):
    send_mail(
        'Test Email',
        'This is a test email.',
        'mwaitukasteven@gmail.com',  # Replace with your email
        ['mwaitukasteven@gmail.com'],  # Replace with the recipient's email
        fail_silently=False,
    )
    return HttpResponse("Test email sent successfully!")

class CustomPasswordResetView(PasswordResetView):
    template_name = 'password_reset.html'
    email_template_name = 'password_reset_email.html'
    success_url = reverse_lazy('password_reset_done')

    def form_valid(self, form):
        email = form.cleaned_data['email']
        User = get_user_model()
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(self.request, "There is no account associated with this email address.")
            return self.form_invalid(form)  # Return to the form with the error

        return super().form_valid(form)


# ✅ Password Reset Confirm View
class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'password_reset_confirm.html'
    success_url = reverse_lazy('password_reset_complete')

    def post(self, request, *args, **kwargs):
        print("CustomPasswordResetConfirmView.post() called")
        new_password1 = request.POST.get('new_password1')
        new_password2 = request.POST.get('new_password2')

        if new_password1 != new_password2:
            messages.error(request, "Passwords do not match.")
            print("Passwords do not match, rendering to response")
            return self.render_to_response(self.get_context_data())

        try:
            uidb64 = kwargs['uidb64']
            uid = force_str(urlsafe_base64_decode(uidb64))
            User = get_user_model()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist, KeyError) as e:
            messages.error(request, "Invalid user or link.")
            print(f"Error: {e}, rendering to response")
            return self.render_to_response(self.get_context_data())

        try:
            # Apply custom password validators
            NumberValidator().validate(new_password1, user)
            LetterValidator().validate(new_password1, user)
            SymbolValidator().validate(new_password1, user)
            NotEqualToExistingPasswordValidator().validate(new_password1, user)

        except ValidationError as e:
            messages.error(request, e)
            print(f"Validation Error: {e}, rendering to response")
            return self.render_to_response(self.get_context_data())

        user.set_password(new_password1)
        user.save()
        messages.success(request, "Password reset successful!")
        print("Password reset successful, redirecting to password_reset_complete")
        return redirect(self.success_url)