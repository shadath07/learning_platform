from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser, Course, Content

class CustomUserCreationForm(UserCreationForm):
    user_type = forms.ChoiceField(choices=CustomUser.USER_TYPE_CHOICES, widget=forms.RadioSelect)

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'user_type', 'password1', 'password2']

class LoginForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)

class OTPVerificationForm(forms.Form):
    otp = forms.CharField(label='Enter OTP', max_length=6)

class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(label='Enter your email')

class ResetPasswordForm(forms.Form):
    new_password = forms.CharField(label='New Password', widget=forms.PasswordInput)
    confirm_password = forms.CharField(label='Confirm New Password', widget=forms.PasswordInput)

class CourseForm(forms.ModelForm):
    class Meta:
        model = Course
        fields = ['title', 'description', 'teacher', 'price', 'rating']

class ContentForm(forms.ModelForm):
    class Meta:
        model = Content
        fields = ['pdf_file', 'youtube_link']
