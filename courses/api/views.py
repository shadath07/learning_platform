import pyotp, requests, logging
from django.core.mail import send_mail
from django.contrib.auth import authenticate, login
from rest_framework.views import APIView
from decimal import Decimal
from django.conf import settings
from django.contrib.auth import get_user_model
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
from rest_framework.permissions import IsAuthenticated,IsAuthenticatedOrReadOnly,AllowAny
from rest_framework_simplejwt.authentication import  JWTAuthentication


CustomUser = get_user_model()
logger = logging.getLogger(__name__)

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
@authentication_classes([JWTAuthentication])
@permission_classes([AllowAny])
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
@permission_classes([AllowAny])
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
                request.session['login_email'] = email
                return Response({'Success': 'Authentication successful. Please check your email for the OTP.'}, status=status.HTTP_200_OK)
            return Response({'error': 'Invalid login credentials. Please try again.'},status=status.HTTP_401_UNAUTHORIZED)
        return Response({'error': 'Invalid data. Please provide valid email and password.'},status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([AllowAny])
def loginotp_verification_api(request):
    if request.method == 'POST':
        entered_otp = request.data.get('otp')
        stored_otp = request.session.get('login_otp')
        stored_resend_otp = request.session.get('resend_login_otp')
        email = request.session.get('login_email')
        if entered_otp == stored_otp or entered_otp == stored_resend_otp:
            if email:
                CustomUser = get_user_model()
                try:
                    user = CustomUser.objects.get(email=email)
                except CustomUser.DoesNotExist:
                    user = None
                if user:
                    refresh = RefreshToken.for_user(user)
                    access_token = str(refresh.access_token)
                    refresh_token = str(refresh)
                    return Response({"Success": "Your credentials have been successfully verified.", "access_token": access_token, "refresh_token": refresh_token}, status=status.HTTP_200_OK)
                return Response({"error": "User not found with the provided email."}, status=status.HTTP_400_BAD_REQUEST)
            return Response({"error": "Email not found. Please try logging in again."}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error": "Invalid OTP. Please try again."}, status=status.HTTP_400_BAD_REQUEST)
    return Response({"status": "error", "message": "Invalid Request Method"}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

@api_view(['GET','POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([AllowAny])
def resend_login_otp_api(request):
    if request.method == 'POST':
        user_email = request.data.get('email')
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

# @api_view(['POST'])
# @authentication_classes([JWTAuthentication])
# @permission_classes([IsAuthenticated])
# def verify_login_otp_api(request):
#     otp = request.data.get('otp')
#     stored_otp = request.session.get('login_otp')
#     stored_resend_otp = request.session.get('resend_login_otp')
#     if (stored_otp and otp == stored_otp) or (stored_resend_otp and otp == stored_resend_otp):
#         user = request.user
#         if user is not None:
#             login(request, user)
#             request.session.pop('login_otp', None)
#             request.session.pop('resend_login_otp', None)
#             return Response({'status':'success', 'message':'Your credentials have been successfully verified.'},status=status.HTTP_200_OK)
#     return Response({'status':'error'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([AllowAny])
def forgot_password_api(request):
    if request.method == 'POST':
        email = request.data.get('email')
        if email:
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                return Response({"error":"User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)
            token = default_token_generator.make_token(user) 
            uid = urlsafe_base64_encode(force_bytes(user.pk))  #it is the unique user ID
            current_site = get_current_site(request)  #here it is to construct reset URL for the user 
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

@permission_classes([AllowAny])
class CourseListAPI(ListAPIView):
    queryset = Course.objects.all()
    serializer_class = CourseSerializer
    pagination_class = PageNumberPagination

@permission_classes([AllowAny])
class CourseDetailAPI(RetrieveAPIView):
    queryset = Course.objects.all()
    serializer_class = CourseSerializer
    

@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([AllowAny])
def purchase_course_api(request, course_id):
    course = get_object_or_404(Course, id=course_id)
    discounted_price = course.price * Decimal('0.7')
    paypal_dict = {
        "business": settings.PAYPAL_RECEIVER_EMAIL,
        "amount": str(discounted_price),
        "item_name": course.title,
        "invoice": f"course-{course_id}", # here it is the unique identifier for the invoice
        "notify_url": request.build_absolute_uri(reverse('paypalipn-api')),
        "return_url": f"{request.build_absolute_uri(reverse('paymentsuccess-api'))}?status=success&course_id={course_id}",
        "cancel_return": f"{request.build_absolute_uri(reverse('paymenterror-api'))}?status=cancel&course_id={course_id}",
    }
    context = {# serializing the course data and converting the PayPal form to a string
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
        content_items = Content.objects.filter(course=course)
        if content_items.exists():
            for content in content_items:
                purchase = Purchase(student=student, course=course,content=content, teacher=course.teacher)
                purchase.save()
                send_purchase_confirmation_email(request.user,course)
                purchase_serializer = PurchaseSerializer(purchase)
                return Response({'status':'Payment was successful','purchase':purchase_serializer.data}, status = status.HTTP_200_OK)
        return Response({'status': 'No content found for the course'}, status=status.HTTP_404_NOT_FOUND)
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
                    content_items = Content.objects.filter(course=course)
                    if content_items.exists():
                        for content in content_items:
                            purchase = Purchase(student=student, course=course, content=content, teacher=course.teacher)
                            purchase.save()
                            send_purchase_confirmation_email(user, course)
                            purchase_serializer = PurchaseSerializer(purchase)  # serialize the purchase data
                            return Response({'message': 'Purchase successful', 'purchase': purchase_serializer.data})
                    return Response({'message': 'No content found for the course'}, status=status.HTTP_404_NOT_FOUND)
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
    if user.user_type == 'student':
        student=user.student
        purchases = Purchase.objects.filter(student=student)
        purchase_data = []
        for purchase in purchases:
            courses= Course.objects.filter(purchase=purchase)
            for course in courses:
                content_data = []
                contents = Content.objects.filter(course=course)
                for content in contents:
                    content_info = {
                        'pdf_file': content.pdf_file.url if content.pdf_file else None,
                        'youtube_link': content.youtube_link,
                    }
                    content_data.append(content_info)
                course_info = {
                    'title': course.title,
                    'contents': content_data,
                }
            purchase_info = {
                'purchase': purchase.id,
                'course': course_info,
            }
            purchase_data.append(purchase_info)
            return Response(purchase_data, status=status.HTTP_200_OK)
    return Response({'status': 'Access Denied'}, status=status.HTTP_403_FORBIDDEN)

@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def available_courses_api(request):
    user = request.user
    teacher = user.teacher
    if user.user_type == 'teacher':
        courses = Course.objects.filter(teacher=teacher)
        serializer = CourseSerializer(courses, many=True)
        return Response(serializer.data)
    return Response({'status':'Access Denied'}, status= status.HTTP_403_FORBIDDEN)


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def purchased_course_students_api(request, course_id):
    user = request.user
    if request.method == 'GET':
        if user.user_type == 'teacher':
            try:
                course = Course.objects.get(id=course_id)
                purchases = Purchase.objects.filter(course=course)
                serializer = PurchaseSerializer(purchases, many=True)
                return Response(serializer.data,status=status.HTTP_200_OK)
            except Course.DoesNotExist:
                return Response({'status': 'Course not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'status': 'Access Denied'}, status=status.HTTP_403_FORBIDDEN)
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
    if request.method == 'GET':
        serializer = CourseSerializer(course)
        return Response(serializer.data)
    elif request.method == 'PUT':
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
        # existing_content = Content.objects.filter(course = course)
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
def view_edit_content_api(request,course_id,content_id=None):
    try:
        course = Course.objects.get(id=course_id)
        if content_id is not None:
            content_item = Content.objects.get(course=course, id=content_id)
        else:
            content_items = Content.objects.filter(course=course)
    except (Course.DoesNotExist,Content.DoesNotExist):
        return Response({'status':'Course or Content Not Found'},status=status.HTTP_404_NOT_FOUND)
    if request.method == 'GET':
        if content_id is not None:
            serializer = ContentSerializer(content_item)
        else:
            serializer = ContentSerializer(content_items, many=True)
        return Response(serializer.data)
    elif request.method == 'PUT':
        serializer = ContentFormSerializer(content_item,data = request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'status':'content has been updated'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    return Response({'status':'Invalid Request Method'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


@api_view(['DELETE'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def delete_content_api(request,course_id,content_id=None):
    if request.method == 'DELETE':
        if content_id is not None:
            content = get_object_or_404(Content,id=content_id,course_id=course_id)
            content.delete()
            return Response({'status':'Content has been deleted successfully'}, status=status.HTTP_200_OK)
        else:
            contents = Content.objects.filter(course_id=course_id)
            contents.delete()
            return Response({'status':'All contents for the course have been deleted successfully'}, status=status.HTTP_200_OK)
    return Response({'status': 'Invalid Request Method'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)






# @api_view(['GET'])
# @authentication_classes([JWTAuthentication])
# @permission_classes([IsAuthenticated])
# def purchasedcourse_teachers_student_api(request,teacher_id):
#     if request.method == 'GET':
#         purchase = Purchase.objects.filter(teacher=teacher_id)
#         serializer = PurchaseSerializer(purchase, many = True)
#         return Response(serializer.data)


# @api_view(['GET','DELETE'])
# @authentication_classes([JWTAuthentication])
# @permission_classes([IsAuthenticated])
# def teacher_courses_delete_api(request,teacher_id):
#     if request.method == 'DELETE':
#         try:
#             course = Course.objects.filter(teacher=teacher_id)
#             course.delete()
#             return Response({'status':'Courses Deleted successfully'}, status=status.HTTP_200_OK)
#         except Course.DoesNotExist:
#             return Response({'status':'Courses Not Found'}, status=status.HTTP_404_NOT_FOUND)
#     return Response({'status':'Invalid Request Method'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

