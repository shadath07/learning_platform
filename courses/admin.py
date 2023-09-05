from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, Teacher, Student, Course, Content, Purchase

class TeacherAdmin(admin.ModelAdmin):
    list_display = ('user',)

class StudentAdmin(admin.ModelAdmin):
    list_display = ('user',)

class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'user_type')

class CourseAdmin(admin.ModelAdmin):
    list_display = ('title', 'teacher', 'price', 'rating')

class ContentAdmin(admin.ModelAdmin):
    list_display = ('course', 'teacher')

class PurchaseAdmin(admin.ModelAdmin):
    list_display = ('student', 'course', 'purchase_date')

# Register your custom admin classes
admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Teacher, TeacherAdmin)
admin.site.register(Student, StudentAdmin)
admin.site.register(Course, CourseAdmin)
admin.site.register(Content, ContentAdmin)
admin.site.register(Purchase, PurchaseAdmin)

admin.site.site_header = 'Learning Platform Admin'
admin.site.site_title = 'Learning Platform Admin'
admin.site.index_title = 'Welcome to Learning Platform Admin'
