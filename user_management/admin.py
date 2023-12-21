from django.contrib import admin
from . models import CustomUser, RegistrationProfile, JobProfile, OtpVerification

# Register your models here.
admin.site.register(CustomUser)
admin.site.register(RegistrationProfile)
admin.site.register(JobProfile)
admin.site.register(OtpVerification)
