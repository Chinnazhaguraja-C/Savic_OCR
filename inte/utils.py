from django.core.mail import send_mail
import random
 
def send_otp_email(email, otp):
    subject = 'Your OTP Code'
    message = f'Your OTP code is {otp}. It is valid for 5 minutes.'
    from_email = 'your_email@example.com'  # Replace with your actual email
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list)
 
def generate_otp():
    return random.randint(100000, 999999)