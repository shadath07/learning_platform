from django.urls import path
from . import views

urlpatterns = [
    path('', views.HomePage, name='home'),
    path('login/', views.LoginPage, name='login'),
    path('signup/', views.SignupPage, name='signup'),
    path('logout/', views.LogoutPage, name='logout'),
    path('courses/', views.CourseList, name='course_list'),
    path('course/<int:course_id>/', views.CourseDetail, name='course_detail'),
    path('course/<int:course_id>/purchase/', views.PurchaseCourse, name='purchase_course'),
    path('resend-login-otp/', views.resend_login_otp, name='resend_login_otp'),
    path('loginotp_verification/', views.loginotp_verification, name='loginotp_verification'),
    path('verify-login-otp/', views.verify_login_otp, name='verify_login_otp'),
    
    path('payment_success/', views.payment_success, name='payment_success'),
    path('payment_cancel/', views.payment_cancel, name='payment_cancel'),
    path('payment_error/', views.payment_error, name='payment_error'),
    path('paypal-ipn/', views.paypal_ipn, name='paypal-ipn'),
    
    path('purchased-courses/', views.purchased_courses, name='purchased_courses'),
    path('available-courses/', views.available_courses, name='available_courses'),
    # "Forgot Password"
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('reset-password/<uidb64>/<token>/', views.reset_password, name='reset_password'),
    
    
    path('create_course/', views.create_course, name='create_course'),
    path('update_course/<int:course_id>/', views.update_course, name='update_course'),
    path('delete_course/<int:course_id>/', views.delete_course, name='delete_course'),
    path('add_content/<int:course_id>/', views.add_content, name='add_content'),
    path('edit_content/<int:course_id>/<int:content_id>/', views.edit_content, name='edit_content'),
    path('delete_content/<int:course_id>/<int:content_id>/', views.delete_content, name='delete_content'),
    path('course/<int:course_id>/students/', views.course_students, name='course_students'),
]