import pyotp, smtplib, logging, requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from django.contrib import messages, auth
from django.http import HttpResponseRedirect
from django.contrib.auth import get_user_model, update_session_auth_hash
from django.http import JsonResponse
from django.core.mail import send_mail
from paypal.standard.forms import PayPalPaymentsForm
from django.urls import reverse
from django.shortcuts import render,HttpResponse,redirect, get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string
from .services import send_purchase_confirmation_email
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.views.decorators.csrf import csrf_exempt
from .models import Course, Purchase, Student, Teacher,CustomUser,Content
from django.core.paginator import Paginator
from decimal import Decimal
from .forms import CustomUserCreationForm, LoginForm, OTPVerificationForm, ForgotPasswordForm, ResetPasswordForm,CourseForm,ContentForm

CustomUser = get_user_model()
logger = logging.getLogger(__name__)

# @login_required(login_url='login')
def HomePage(request):
    user_type = None
    if request.user.is_authenticated:
        user_type = request.user.user_type
    return render(request, 'home.html', {'user_type': user_type})

def SignupPage(request):
    form = CustomUserCreationForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        print("Form is valid")
        username = form.cleaned_data['username']
        email = form.cleaned_data['email']
        pass1 = form.cleaned_data['password1']
        pass2 = form.cleaned_data['password2']
        user_type = form.cleaned_data['user_type']
        if pass1 != pass2:
            messages.error(request, "Your password and confirm password are not the same!!")
            return redirect('signup')
        elif not email:
            messages.error(request, "Please provide a valid email address.")
            return redirect('signup')
        else:
            if CustomUser.objects.filter(email=email).exists():
                messages.error(request, "Email has already been registered. Please use a different email.")
                return redirect('signup')
            count = 1
            new_username = username
            while CustomUser.objects.filter(username=new_username).exists():
                new_username = f"{username}{count}"
                count += 1
            my_user = CustomUser(username=new_username, email=email, user_type=user_type)
            my_user.set_password(pass1)
            my_user.save()
            if user_type == 'teacher':
                Teacher.objects.create(user=my_user)
            elif user_type == 'student':
                Student.objects.create(user=my_user)
            messages.success(request, "Account created successfully. You can now log in with your credentials.")
            return redirect('login')
    context = {'form': form}
    return render(request, 'signup.html', context)

def LoginPage(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('pass')
        user = authenticate(request, email=email, password=password)
        if user is not None:
            login(request, user)
            totp = pyotp.TOTP(pyotp.random_base32())
            otp = totp.now()
            subject = '2FA OTP for Login'
            message = f'Your OTP for login is: {otp}'
            from_email = 'kingshad715@gmail.com'
            recipient_list = [user.email]
            send_mail(subject, message, from_email, recipient_list)
            request.session['login_otp'] = otp  
            return render(request, 'loginotp_verification.html') 
        else:
            messages.error(request, "Invalid login credentials. Please try again.")
            return render(request, 'login.html')
    return render(request, 'login.html')

@login_required
def loginotp_verification(request):
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')
        stored_otp = request.session.get('login_otp')
        stored_resend_otp = request.session.get('resend_login_otp')
        if entered_otp == stored_otp or entered_otp == stored_resend_otp:
            request.session.pop('login_otp', None)
            request.session.pop('resend_login_otp', None)
            messages.success(request, "Your credentials have been successfully verified.")
            return redirect('home')  
        else:
            messages.error(request, "Invalid OTP. Please try again.")
    return render(request, 'loginotp_verification.html', {'show_verification_form': True})


def resend_login_otp(request):
    if request.method == 'GET':
        user_email = request.user.email
        if user_email:
            totp = pyotp.TOTP(pyotp.random_base32())
            otp = totp.now()
            subject = 'Resend 2FA OTP for Login'
            message = f'Your new OTP for login is: {otp}'
            from_email = 'kingshad715@gmail.com'  
            recipient_list = [user_email]
            send_mail(subject, message, from_email, recipient_list)
            request.session['resend_login_otp'] = otp
            return JsonResponse({'status': 'success', 'message': 'New OTP has been sent to your email for login verification.'})
        else:
            return JsonResponse({'status': 'error', 'message': 'User email not found.'})
    else:
        return JsonResponse({'status': 'error', 'message': 'No valid operation to resend OTP for login.'})

def verify_login_otp(request, otp):
    stored_otp = request.session.get('login_otp')
    stored_resend_otp = request.session.get('resend_login_otp')   
    print(f"Stored Resend OTP: {stored_resend_otp}")
    print(f"Entered OTP: {otp}")
    if (stored_otp and otp == stored_otp) or (stored_resend_otp and otp == stored_resend_otp):
        user = request.user
        if user is not None:
            login(request, user)
            request.session.pop('login_otp', None)
            request.session.pop('resend_login_otp', None)
            messages.success(request, "Your credentials have been successfully verified.")
            return redirect('home')     
    messages.error(request, "Invalid OTP. Please try again.")
    return redirect('loginotp_verification')  

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            messages.error(request, 'User with this email does not exist.')
            return redirect('forgot_password')
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        current_site = get_current_site(request)
        reset_url = reverse('reset_password', kwargs={'uidb64': uid, 'token': token})
        subject = 'Reset your password'
        message = render_to_string('reset_password_email.html', {
            'user': user,
            'reset_url': reset_url,
        })
        send_mail(subject, message, 'kingshad715@gmail.com', [user.email])
        messages.success(request, 'A password reset link has been sent to your email.')
        return redirect(reset_url)
    return render(request, 'forgot_password.html')

def reset_password(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = CustomUser.objects.get(pk=uid)
    except (CustomUser.DoesNotExist, ValueError, OverflowError):
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            if new_password == confirm_password:
                user.set_password(new_password)
                user.save()
                update_session_auth_hash(request, user)
                success_message = 'Your password has been successfully reset. You can now log in.'
                return render(request, 'reset_password.html', {'success_message': success_message})
            else:
                messages.error(request, 'Passwords do not match.')
        return render(request, 'reset_password.html', {'uidb64': uidb64, 'token': token})
    else:
        messages.error(request, 'Invalid reset link.')
        return redirect('login')


def LogoutPage(request):
    logout(request)
    return redirect('login')

def CourseList(request):
    courses = Course.objects.all()
    paginator = Paginator(courses, 6)  
    page_number = request.GET.get('page')
    page_courses = paginator.get_page(page_number)
    return render(request, 'course_list.html', {'page_courses': page_courses})


def CourseDetail(request, course_id):
    course = get_object_or_404(Course, id=course_id) 
    course_price_float = float(course.price)
    discounted_price = course_price_float * 0.7
    paypal_dict = {
        "business": settings.PAYPAL_RECEIVER_EMAIL,
        "amount": str(discounted_price),  
        "item_name": course.title,
        "invoice": f"course-{course_id}",
        "notify_url": request.build_absolute_uri(reverse('paypal-ipn')),
        "return_url": request.build_absolute_uri(reverse('payment_success')),
        "cancel_return": request.build_absolute_uri(reverse('payment_cancel')),
    }
    paypal_form = PayPalPaymentsForm(initial=paypal_dict)
    context = {
        'course': course,
        'discounted_price': discounted_price,
        'paypal_form': paypal_form,
    }
    return render(request, 'course_detail.html', context)

@login_required(login_url='login')
def PurchaseCourse(request, course_id):
    course = get_object_or_404(Course, id=course_id)
    discounted_price = course.price * Decimal('0.7')
    paypal_dict = {
        "business": settings.PAYPAL_RECEIVER_EMAIL,
        "amount": str(discounted_price),
        "item_name": course.title,
        "invoice": f"course-{course_id}",
        "notify_url": request.build_absolute_uri(reverse('paypal-ipn')),
        "return_url": f"{request.build_absolute_uri(reverse('payment_success'))}?status=success&course_id={course_id}",
        "cancel_return": f"{request.build_absolute_uri(reverse('payment_success'))}?status=cancel&course_id={course_id}",
    }
    paypal_form = PayPalPaymentsForm(initial=paypal_dict)
    context = {
        'course': course,
        'discounted_price': discounted_price,
        'paypal_form': paypal_form,
    }
    return render(request, 'purchase.html', context)

@login_required(login_url='login')
def payment_success(request):
    payment_status = request.GET.get('status')
    course_id = request.GET.get('course_id')   
    if payment_status == 'success' and course_id:
        course = get_object_or_404(Course, id=course_id)
        student = request.user.student
        content = course.content_set.first() 
        purchase = Purchase(student=student, course=course, content=content, teacher=course.teacher)
        purchase.save()
        send_purchase_confirmation_email(request.user, course)
        return redirect('purchased_courses')    
    elif payment_status == 'cancel':
        return redirect('payment_cancel')   
    return redirect('payment_error')  

@login_required(login_url='login')
def payment_error(request):
    return render(request, 'payment_error.html')

@login_required(login_url='login')
def payment_cancel(request):
    return render(request, 'payment_cancel.html')

@csrf_exempt
def paypal_ipn(request):
    if request.method == 'POST':
        verification_data = {'cmd': '_notify-validate'}
        verification_data.update(request.POST)
        response = requests.post(settings.PAYPAL_IPN_URL, data=verification_data)           
        if response.text == 'VERIFIED':
            payment_status = request.POST.get('payment_status')
            if payment_status == 'Completed':
                course_id = int(request.POST.get('invoice').split('-')[1])
                course = Course.objects.get(id=course_id)
                user = request.user
                student = user.student
                content = course.content
                try:
                    purchase = Purchase(student=student, course=course, content=content, teacher=course.teacher)
                    purchase.save()
                    send_purchase_confirmation_email(user, course)
                except Exception as e:
                    print(f"Exception during purchase processing: {e}")
                    return HttpResponse(status=500)
                return HttpResponse("OK")
            else:
                return HttpResponse(status=200)
        else:
            return HttpResponse(status=400)
    return HttpResponse(status=405)


@login_required(login_url='login')
def purchased_courses(request):
    user = request.user
    student = user.student
    purchases = Purchase.objects.filter(student=student)
    context = {
        'purchases': purchases,
    }
    return render(request, 'purchased_courses.html', context)


@login_required
def available_courses(request):
    user = request.user
    if user.user_type == 'teacher':
        return render(request, 'available_courses.html', {'user': user})
    else:
        return render(request, 'error.html', {'message': 'Access Denied'})


@login_required
def course_students(request, course_id):
    course = Course.objects.get(id=course_id)
    purchases = Purchase.objects.filter(course=course)   
    return render(request, 'course_students.html', {'course': course, 'purchases': purchases})


@login_required
def create_course(request):
    if request.method == 'POST':
        form = CourseForm(request.POST)
        if form.is_valid():
            course = form.save(commit=False)
            course.teacher = request.user.teacher
            course.save()
            return redirect('available_courses')  
    else:
        form = CourseForm() 
    return render(request, 'create_course.html', {'form': form})


@login_required
def update_course(request, course_id):
    course = Course.objects.get(id=course_id)
    if request.method == 'POST':
        form = CourseForm(request.POST, instance=course)
        if form.is_valid():
            form.save()
            return redirect('available_courses') 
    else:
        form = CourseForm(instance=course)
    return render(request, 'update_course.html', {'course': course, 'form': form})


@login_required
def delete_course(request, course_id):
    course = Course.objects.get(id=course_id)
    if request.method == 'POST':
        course.delete()
        return redirect('available_courses')
    return render(request, 'delete_course.html', {'course': course})

@login_required
def add_content(request, course_id):
    course = get_object_or_404(Course, id=course_id)
    existing_content = Content.objects.filter(course=course)
    if request.method == 'POST':
        form = ContentForm(request.POST, request.FILES)
        if form.is_valid():
            if existing_content.exists():
                messages.warning(request, 'Content for this course already exists. You can edit it below.')
            else:
                content = form.save(commit=False)
                content.course = course
                content.teacher = request.user.teacher
                content.save()
                return redirect('available_courses')  
    else:
        form = ContentForm()
    return render(request, 'add_content.html', {'course': course, 'form': form, 'existing_content': existing_content})


@login_required
def edit_content(request, course_id, content_id):
    content = get_object_or_404(Content, id=content_id, course_id=course_id)
    if request.method == 'POST':
        form = ContentForm(request.POST, request.FILES, instance=content)
        if form.is_valid():
            form.save()
            return redirect('available_courses')  
    else:
        form = ContentForm(instance=content)
    return render(request, 'edit_content.html', {'content': content, 'form': form})


@login_required
def delete_content(request, course_id, content_id):
    content = get_object_or_404(Content, id=content_id)
    if request.method == 'POST':
        content.delete()
        return redirect('edit_course', course_id=course_id)
    return render(request, 'delete_content.html', {'content': content})