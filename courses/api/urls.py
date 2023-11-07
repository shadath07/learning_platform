from django.urls import path,include
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView
from . import views

urlpatterns=[
    path('homepage-api/',views.homepage_api,name='homepage-api'),
    
    # Authentication Login 
    path('auth/', include('rest_framework.urls', namespace='rest_framework')),
    
    path('signuppage-api/',views.signuppage_api,name='signuppage-api'),
    path('loginpage-api/',views.loginpage_api,name = 'loginpage-api'),
    path('logoutpage-api/',views.logoutpage_api,name='logoutpage-api'),
    path('loginotpverification-api/',views.loginotp_verification_api,name="loginotpverification-api"),
    path('resendloginotp-api/',views.resend_login_otp_api,name='resendloginotp-api'),
    # path('verifyloginotp-api/',views.verify_login_otp_api, name="verifyloginotp-name"),
    path('forgotpassword-api/',views.forgot_password_api, name="forgotpassword-api"),
    path('resetpassword-api/',views.reset_password_api,name='resetpassword-api'),
    
    path('courselist-api/',views.CourseListAPI.as_view(), name='courselist-api'),
    path('coursedetail-api/<int:pk>/',views.CourseDetailAPI.as_view(),name='coursedetail-api'),
    
    path('purchasecourse-api/<int:course_id>/',views.purchase_course_api,name='purchasecourse-api'),
    path('paymentsuccess-api/',views.payment_success_api, name='paymentsuccess-api'),
    path('paymentcancel-api/',views.payment_cancel_api, name='paymentcancel-api'),
    path('paymenterror-api/',views.payment_error_api, name='paymenterror-api'),
    path('paypalipn-api/',views.paypal_ipn_api,name='paypalipn-api'),
    
    path('purchasedcourses-api/',views.purchased_courses_api, name='purchasedcourses-api'),
    path('availablecourses-api/',views.available_courses_api, name='availablecourses-api'),
    path('purchasedcoursestudents-api/<int:course_id>/',views.purchased_course_students_api, name='purchasedcoursestudents-api'),
    
    # path('purchasedcourse_teachersstudent-api/<int:teacher_id>/',views.purchasedcourse_teachers_student_api, name='purchasedcourse_teachersstudent-api'),
    # path('teachercoursesdelete-api/<int:teacher_id>/',views.teacher_courses_delete_api, name='teachercoursesdelete-api'),
    
    path('createcourse-api/',views.create_course_api, name='createcourse-api'),
    path('updatecourse-api/<int:course_id>/',views.update_course_api,name ='updatecourse-api'),
    path('deletecourse-api/<int:course_id>/',views.delete_course_api,name='deletecourse-api'),
    
    path('addcontent-api/<int:course_id>/',views.add_content_api,name='addcontent-api'),
    path('editcontent-api/<int:course_id>/<int:content_id>/',views.view_edit_content_api,name='editcontent-api'),
    # used to get all the contents associated with the course.
    path('editcontent-api/<int:course_id>/',views.view_edit_content_api,name='editcontent-api'),
    path('deletecontent-api/<int:course_id>/<int:content_id>/',views.delete_content_api,name='deletecontent-api'),
    # used to delete all the comntents associated with the course.
    path('deletecontent-api/<int:course_id>/',views.delete_content_api,name='deletecontent-api'),
    # JSON web token verification urls
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh-token/', TokenRefreshView.as_view(), name='refresh-token'),
    path('verify-token/', TokenVerifyView.as_view(), name='verify-token'),
]