from django.db import models
from .managers import CustomUserManager
from django.contrib.auth.models import AbstractUser

class CustomUser(AbstractUser):
    USER_TYPE_CHOICES = [
        ('teacher', 'Teacher'),
        ('student', 'Student'),
    ]
    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES)
    objects = CustomUserManager()
    def __str__(self):
        return self.username

class Teacher(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    def __str__(self):
        return self.user.username


class Student(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    courses_enrolled = models.ManyToManyField('Course', related_name='students_enrolled')
    def __str__(self):
        return self.user.username


class Course(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    teacher = models.ForeignKey(Teacher, on_delete=models.CASCADE)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    rating = models.DecimalField(max_digits=3, decimal_places=2, null=True, blank=True)  
    has_contents = models.BooleanField(default=False)
    thumbnail = models.ImageField(upload_to='course_thumbnails/', null=False, blank=False)
    def __str__(self):
        return f'{self.title} by {self.teacher}'

class Content(models.Model):
    course = models.ForeignKey(Course, on_delete=models.CASCADE)
    pdf_file = models.FileField(upload_to='pdfs/', blank=True, null=True)
    youtube_link = models.URLField(blank=True, null=True)
    teacher = models.ForeignKey(Teacher, on_delete=models.CASCADE, related_name='contents_created_by')
    def __str__(self):
        return f"Content for {self.course.title}"

class Purchase(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE)
    course = models.ForeignKey('Course', on_delete=models.CASCADE)
    purchase_date = models.DateTimeField(auto_now_add=True)
    content = models.ForeignKey(Content, on_delete=models.CASCADE, related_name='purchase', default=None)
    teacher = models.ForeignKey(Teacher, on_delete=models.CASCADE, related_name='purchases_teacher')

    def __str__(self):
        return f"{self.student.user.username} - {self.course.title}"