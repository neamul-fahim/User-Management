from django.core.mail import send_mail, BadHeaderError
from smtplib import SMTPException
from django.conf import settings
import random
from django.http import HttpRequest


def send_otp_mail(email):
    otp = str(random.randint(100000, 999999))

    subject = 'Account Verification OTP'
    message = f'The OTP is: {otp}'
    from_email = settings.EMAIL_HOST_USER
    recipient = str(email)
    recipient_list = [recipient]

    try:
        send_mail(subject=subject, message=message,
                  from_email=from_email, recipient_list=recipient_list, fail_silently=False)
    except BadHeaderError:
        raise ValueError("Invalid header found.")
    except SMTPException as e:
        raise SMTPException(f"SMTP error occurred: {e}")
    return otp


def send_email(email, message):
    subject = 'Ipsita'
    message = message
    from_email = settings.EMAIL_HOST_USER
    recipient = str(email)
    recipient_list = [recipient]

    send_mail(subject=subject, message=message,
              from_email=from_email, recipient_list=recipient_list, fail_silently=False)


def get_token_from_request(request: HttpRequest) -> str:
    """extract token from request header"""
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if auth_header and 'Bearer ' in auth_header:
        token = auth_header.split('Bearer ')[1]

        return token
    return None
