from django.core.mail import EmailMessage
import random
from django.conf import settings
from .models import OTP, User
from django.contrib.sites.shortcuts import get_current_site

def generate_otp():
    otp = ''
    for i in range(6):
        otp += str(random.randint(0, 9))
    return otp

def send_code_to_email(email, request):
    subject = "One Time Password for Email Verification"
    otp = generate_otp()
    current_site = get_current_site(request).domain
    user = User.objects.get(email=email)
    email_body = f'Hello {user.first_name},\n\nYour One Time Password for email verification is {otp}. OTP is valid for 5 minutes. \n\nThank you for signing up on {current_site}.'
    from_email = settings.EMAIL_HOST_USER
    otp_obj = OTP.objects.create(user=user, otp=otp)
    email = EmailMessage(subject=subject, body=email_body, from_email=from_email, to=[user.email])
    email.send()

def send_normal_email(data):
    email = EmailMessage(
        subject=data['subject'],
        body=data['body'],
        from_email=settings.EMAIL_HOST_USER,
        to=data['to']
    )
    email.send()
