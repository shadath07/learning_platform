from django.core.mail import send_mail
from django.template.loader import render_to_string


def send_purchase_confirmation_email(user, course):
    subject = f"Course Purchase Confirmation: {course.title}"
    message = f"Dear {user.username},\n\nThank you for purchasing the course '{course.title}'. You now have access to its contents."
    from_email = "mohammedshadhath7@gmail.com"  # Use your email address
    recipient_list = [user.email]
    send_mail(subject, message, from_email, recipient_list)