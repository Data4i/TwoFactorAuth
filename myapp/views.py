import base64
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import CustomUser
from .forms import CustomUserCreationForm, OTPVerificationForm
from .utils import send_sms
import pyotp
import qrcode
import io

def signup(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            user.otp_secret = pyotp.random_base32()
            user.save()
            login(request, user)
            return redirect('setup_2fa')
    else:
        form = CustomUserCreationForm()
    return render(request, 'signup.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            # Generate an OTP and send it via SMS
            otp = pyotp.TOTP(user.otp_secret).now()
            try:
                send_sms(user.phone_number, f"Your OTP is {otp}")
                request.session['pre_otp_user'] = user.id
                return redirect('verify_otp')
            except Exception as e:
                return render(request, 'login.html', {'error': f"Failed to send OTP: {str(e)}"})
        else:
            return render(request, 'login.html', {'error': 'Invalid credentials'})
    return render(request, 'login.html')

@login_required
def dashboard(request):
    return render(request, 'dashboard.html')

@login_required
def setup_2fa(request):
    user = request.user
    otp_secret = user.otp_secret
    otp_auth_url = pyotp.totp.TOTP(otp_secret).provisioning_uri(
        user.username, issuer_name="MyDjangoApp"
    )
    # Generate the QR code image
    qr = qrcode.make(otp_auth_url)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    buffer.seek(0)
    # Convert the QR code image to base64
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return render(request, 'setup_2fa.html', {
        'qr_code_base64': qr_code_base64,
        'user': user
    })

def resend_otp(request):
    user_id = request.session.get('pre_otp_user')
    if user_id:
        user = CustomUser.objects.get(id=user_id)
        # Generate a new OTP
        otp = pyotp.TOTP(user.otp_secret).now()
        try:
            send_sms(user.phone_number, f"Your new OTP is {otp}")
            messages.success(request, 'A new OTP has been sent to your phone.')
        except Exception as e:
            messages.error(request, f"Failed to send OTP: {str(e)}")
    return redirect('verify_otp')


def verify_otp(request):
    if request.method == 'POST':
        form = OTPVerificationForm(request.POST)
        if form.is_valid():
            otp = form.cleaned_data['otp']
            user_id = request.session.get('pre_otp_user')
            if user_id:
                user = CustomUser.objects.get(id=user_id)
                totp = pyotp.TOTP(user.otp_secret)
                if totp.verify(otp):
                    login(request, user)
                    del request.session['pre_otp_user']
                    messages.success(request, 'You Have Been Logged In!!')
                    return redirect('dashboard')
                else:
                    return render(request, 'verify_otp.html', {'form': form, 'error': 'Invalid OTP'})
    else:
        form = OTPVerificationForm()
    return render(request, 'verify_otp.html', {'form': form})

@login_required
def logout_user(request):
    logout(request)
    messages.success(request, "You Were Logged Out!!")
    return redirect('login')
