import pyotp, requests
from django.core.mail import send_mail
from django.contrib.auth import authenticate, login
from rest_framework.views import APIView
from decimal import Decimal
from django.conf import settings
from paypal.standard.forms import PayPalPaymentsForm
from courses.services import send_purchase_confirmation_email
from django.urls import reverse
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework import status
from rest_framework.generics import ListAPIView
from rest_framework.generics import RetrieveAPIView
from django.urls import reverse
from django.contrib.auth.tokens import default_token_generator
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from rest_framework.response import Response
from rest_framework import viewsets
from rest_framework.pagination import PageNumberPagination
from .serializers import *
from courses.models import *
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.permissions import IsAuthenticated,IsAuthenticatedOrReadOnly
from rest_framework_simplejwt.authentication import  JWTAuthentication


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticatedOrReadOnly])
def homepage_api(request):
    user_type = None
    if request.user.is_authenticated:
        user_type = request.user.user_type
        user_instance = request.user
        serializer = CustomUserSerializer(user_instance)
        return Response(serializer.data)
    return Response({'user_type': user_type})


@api_view(['GET','POST'])
def signuppage_api(request):
    if request.method == 'POST':
        serializer = CustomUserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user_type = serializer.validated_data.get('user_type')
            if user_type == 'teacher':
                Teacher.objects.create(user=user)
            elif user_type == 'student':
                Student.objects.create(user=user)
            return Response({"success": "Account created successfully. You can now log in with your credentials."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET','POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def loginpage_api(request):
    if request.method == 'POST':
        serializer = CustomUserLoginSerializer(data = request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            password = serializer.validated_data.get('password')
            user = authenticate(request, email=email, password=password)
            if user is not None:
                login(request, user)
                totp = pyotp.TOTP(pyotp.random_base32())
                print(totp)
                otp = totp.now()
                print(otp)
                subject = '2FA OTP for Login'
                message = f'Your OTP for login is: {otp}'
                from_email = 'kingshad715@gmail.com'
                recipient_list = [user.email]
                send_mail(subject, message, from_email, recipient_list)
                request.session['login_otp'] = otp
                
                # refresh = RefreshToken.for_user(user)
                # access_token = str(refresh.access_token)
                # refresh_token = str(refresh)
                
                return Response({'Success': 'Authentication successful. Please check your email for the OTP.'}, status=status.HTTP_200_OK)
            return Response({'error': 'Invalid login credentials. Please try again.'},status=status.HTTP_401_UNAUTHORIZED)
        return Response({'error': 'Invalid data. Please provide valid email and password.'},status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def loginotp_verification_api(request):
    if request.method == 'POST':
        entered_otp = request.data.get('otp')
        stored_otp = request.session.get('login_otp')
        stored_resend_otp = request.session.get('resend_login_otp')
        if entered_otp == stored_otp or entered_otp == stored_resend_otp:
            request.session.pop('login_otp', None)
            request.session.pop('resend_login_otp', None)
            return Response({"Success":"Your credentials have been successfully verified."}, status=status.HTTP_200_OK)
        return Response({"error":"Invalid OTP. Please try again."},status=status.HTTP_400_BAD_REQUEST)
    return Response({"Message":"Welcome to the OTP verification endpoint."}, status = status.HTTP_200_OK)


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def resend_login_otp_api(request):
    if request.method == 'GET':
        user_email = request.user.email
        if user_email:
            totp = pyotp.TOTP(pyotp.random_base32())
            otp = totp.now()
            print(otp)
            subject = 'Resend 2FA OTP for Login'
            message = f'Your new OTP for login is:{otp}'
            from_email = 'kingshad715@gmail.com'
            recipient_list = [user_email]
            send_mail(subject,message,from_email,recipient_list)            
            request.session['resend_login_otp'] = otp
            return Response({'status':'success','message':'New OTP has been sent to your email for login verification.'},status = status.HTTP_200_OK)
        return Response({'status':'error','message':'User email not found.'}, status=status.HTTP_400_BAD_REQUEST)
    return Response({'status':'error','message':'No valid operation to resend OTP for login.'},status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def verify_login_otp_api(request):
    otp = request.data.get('otp')
    stored_otp = request.session.get('login_otp')
    stored_resend_otp = request.session.get('resend_login_otp')
    if (stored_otp and otp == stored_otp) or (stored_resend_otp and otp == stored_resend_otp):
        user = request.user
        if user is not None:
            request.session.pop('login_otp', None)
            request.session.pop('resend_login_otp', None)
            return Response({'status':'success', 'message':'Your credentials have been successfully verified.'},status=status.HTTP_200_OK)
    return Response({'status':'error'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def forgot_password_api(request):
    if request.method == 'POST':
        email = request.data.get('email')
        if email:
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                return Response({"error":"User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            current_site = get_current_site(request)
            reset_url = reverse('reset_password', kwargs = {'uidb64':uid, 'token':token})
            subject = 'Reset your password'
            message = f'Reset your password by clicking on the link:{current_site}{reset_url}'
            from_email = 'kingshad715@gmail.com'
            recipient_list = [user.email]
            send_mail(subject, message, from_email, recipient_list)
            return Response({'status':'A password reset link has been sent to your email.'},status=status.HTTP_200_OK)
        return Response({'error':'Please provide an email.'},  status=status.HTTP_400_BAD_REQUEST)
    return Response({'error': 'Invalid request method.'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def reset_password_api(request):
    serializer = ResetPasswordSerializer(data=request.data)
    if serializer.is_valid():
        new_password =serializer.validated_data.get('new_password')
        confirm_password = serializer.validated_data.get('confirm_password')
        if new_password == confirm_password :
            user =request.user
            user.set_password(new_password)
            user.save()
            return Response({'status':'Your password has been successfully reset.'}, status =status.HTTP_200_OK)
        return Response({'error':'Passwords do not match.'},status=status.HTTP_400_BAD_REQUEST)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def logoutpage_api(request):
    return Response({'status':'You have been logged out.'},status=status.HTTP_200_OK)


class CourseListAPI(ListAPIView):
    queryset = Course.objects.all()
    serializer_class = CourseSerializer
    pagination_class = PageNumberPagination


class CourseDetailAPI(RetrieveAPIView):
    queryset = Course.objects.all()
    serializer_class = CourseSerializer
    

@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def purchase_course_api(request, course_id):
    course = get_object_or_404(Course, id=course_id)
    discounted_price = course.price * Decimal('0.7')
    paypal_dict = {
        "business": settings.PAYPAL_RECEIVER_EMAIL,
        "amount": str(discounted_price),
        "item_name": course.title,
        "invoice": f"course-{course_id}",
        "notify_url": request.build_absolute_uri(reverse('paypalipn-api')),
        "return_url": f"{request.build_absolute_uri(reverse('paymentsuccess-api'))}?status=success&course_id={course_id}",
        "cancel_return": f"{request.build_absolute_uri(reverse('paymenterror-api'))}?status=cancel&course_id={course_id}",
    }
    # Serialize the course data and convert the PayPal form to a string
    context = {
        'course': CourseSerializer(course).data,
        'discounted_price': discounted_price,
        'paypal_form': str(PayPalPaymentsForm(initial=paypal_dict)),
    }
    return Response(context)



@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def payment_success_api(request):
    payment_status = request.data.get('status')
    course_id = request.data.get('course_id')
    if payment_status == 'success' and course_id:
        course = get_object_or_404(Course, id=course_id)
        student = request.user.student
        content = course.content_set.first()
        purchase = Purchase(student=student, course = course,content=content, teacher=course.teacher)
        purchase.save()
        send_purchase_confirmation_email(request.user,course)
        purchase_serializer = PurchaseSerializer(purchase)
        return Response({'mesaage':'Payment was successful','purchase':purchase_serializer.data}, status = status.HTTP_200_OK)
    elif payment_status == 'cancel':
        return Response({'message':'Payment was cancelled'},status=status.HTTP_404_NOT_FOUND)
    return Response({'message':'Payment error'},status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def paypal_ipn_api(request):
    if request.method == 'POST':
        verification_data = {'cmd': '_notify-validate'}
        verification_data.update(request.data)
        response = requests.post(settings.PAYPAL_IPN_URL, data=verification_data)
        if response.text == 'VERIFIED':
            payment_status = request.data.get('payment_status')
            if payment_status == 'Completed':
                course_id = int(request.data.get('invoice').split('-')[1])
                try:
                    course = Course.objects.get(id=course_id)
                    user = request.user
                    student = user.student
                    content = course.content
                    purchase = Purchase(student=student, course=course, content=content, teacher=course.teacher)
                    purchase.save()
                    send_purchase_confirmation_email(user, course)
                    purchase_serializer = PurchaseSerializer(purchase)  # Serialize the purchase data
                    return Response({'message': 'Purchase successful', 'purchase': purchase_serializer.data})
                except Exception as e:
                    print(f"Exception during purchase processing: {e}")
                    return Response({'message': 'Internal Server Error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({'message': 'Payment not completed'})
        return Response({'message': 'Verification failed'}, status=status.HTTP_400_BAD_REQUEST)
    return Response({'error':'Invalid request method.'},status=status.HTTP_405_METHOD_NOT_ALLOWED)

@api_view((['GET']))
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def payment_error_api(request):
    return Response({'message':'Payment error'})

@api_view((['GET']))
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def payment_cancel_api(request):
    return Response({'message':'Payment was cancelled'})


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def purchased_courses_api(request):
    user = request.user
    student = user.student
    purchase = Purchase.objects.filter(student=student)
    serializer = PurchaseSerializer(purchase, many = True)
    return Response({'purchase':serializer.data}, status=status.HTTP_200_OK)


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def available_courses_api(request):
    user = request.user
    if user.user_type == 'teacher':
        courses = Course.objects.all()
        serializer = CourseSerializer(courses, many = True)
        return Response(serializer.data)
    return Response({'Status':'Access Denied'})


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def course_students_api(request, course_id):
    if request.method == 'GET':
        course = Course.objects.get(id=course_id)
        purchases = Purchase.objects.filter(course=course)
        serializer = PurchaseSerializer(purchases, many=True)
        return Response(serializer.data,status=status.HTTP_200_OK)
    return Response({'status':'Invalid Request Method'},status=status.HTTP_405_METHOD_NOT_ALLOWED)


@api_view(['GET','POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def create_course_api(request):
    if request.method == 'POST':
        serializer = CourseFormSerializer(data = request.data)
        if serializer.is_valid():
            serializer.save(teacher=request.user.teacher)
            return Response({'status':'Course has been created successfully'},status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    return Response({'status':'Invalid Request Method'},status=status.HTTP_405_METHOD_NOT_ALLOWED)


@api_view(['GET','PUT'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def update_course_api(request, course_id):
    try:
        course = get_object_or_404(Course,id=course_id)
    except Course.DoesNotExist:
        return Response({'status':'Course Not Found'},status=status.HTTP_404_NOT_FOUND)  
    if request.method == 'PUT':
        serializer = CourseFormSerializer(course,data=request.data, partial=True) 
        if serializer.is_valid():
            serializer.save()
            return Response({'status':'Data updated Successfully'},status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    return Response({'status':'Invalid Request Method'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)       
            

@api_view(['GET','DELETE'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def delete_course_api(request,course_id):
    try:
        course = get_object_or_404(Course,id=course_id)
    except Course.DoesNotExist:
        return Response({'status':'Course Not Found'},status=status.HTTP_404_NOT_FOUND)
    if request.method =='DELETE':
        course.delete()
        return Response({'status':'Course has been Deleted successfully'})
    return Response({'status':'Invalid request method'},status=status.HTTP_405_METHOD_NOT_ALLOWED)


@api_view(['GET','POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def add_content_api(request,course_id):
    try:
        course =get_object_or_404(Course,id=course_id)
        existing_content = Content.objects.filter(course = course)
    except Course.DoesNotExist:
        return Response({'status':'Course Not Found'},status=status.HTTP_404_NOT_FOUND)
    if request.method  == 'POST':
        serializer = ContentFormSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(course=course,teacher=request.user.teacher)
            return Response({'status':'content added successfully'},status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
    elif request.method == 'GET':
        content = Content.objects.filter(course=course)
        serializer = ContentSerializer(content, many=True)
        return Response({'content': serializer.data}, status=status.HTTP_200_OK)
    return Response({'status':'Invalid Request Method'},status=status.HTTP_405_METHOD_NOT_ALLOWED)


@api_view(['GET','PUT'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def edit_content_api(request,course_id,content_id):
    try:
        course = Course.objects.get(id=course_id)
        content_items = Content.objects.get(course=course,id=content_id)
    except (Course.DoesNotExist,Content.DoesNotExist):
        return Response({'status':'Course or Content Not Found'},status=status.HTTP_404_NOT_FOUND)
    if request.method == 'PUT':
        serializer = ContentFormSerializer(content_items,data = request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'status':'content has been updated'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    return Response({'status':'Invalid Request Method'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


@api_view(['GET','DELETE'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def delete_content_api(request,course_id,content_id):
    content = get_object_or_404(Content,id=content_id)
    if content.course_id != course_id:
        return Response({'status':'Invalid Request'},status=status.HTTP_400_BAD_REQUEST)
    if request.method == 'DELETE':
        content.delete()
        return Response({'status':'Content has been deleted successfully'}, status=status.HTTP_200_OK)
    return Response({'status':'Invalid Request Method'},status = status.HTTP_405_METHOD_NOT_ALLOWED)