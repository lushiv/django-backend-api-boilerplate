
from django.conf.urls import url
from django.contrib import admin
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions
from django.urls import path
from . import views

schema_view = get_schema_view(
   openapi.Info(
      title="My API",
      default_version='v1',
      description="Test description",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@snippets.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('swagger(?P<format>\.json|\.yaml)', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    url(r'^admin/', admin.site.urls),
    
    #1:- Customer Login and Register
    url(r'^api/login/', view=views.login, name="login"),
    url(r'^api/signup/', view=views.signup, name="signup"),
    url(r'^api/logout/', view=views.logout, name="logout"),

    #2:- Change password
    url(r'^api/change_password/', view=views.changepassword,name="changepassword"),

    #3:- Forget password
    url(r'^api/forget-password-request', view=views.forget_password_request, name="forget_password_request"),
    url(r'^api/reset-password', view=views.reset_password, name="reset_password"),

    #4:- 2Fa
    url(r'^api/enable_2fa/', view=views.enable_2fa, name="enable_2fa"),
    url(r'^api/verify_otp/', view=views.verify_otp, name="verify_otp"),
    url(r'^api/disable_2fa/', view=views.disable_2fa, name="disable_2fa"),

    #5:- Multifactor login
    url(r'^api/multifactor_login/', view=views.multifactor_login, name="multifactor_login"),

    #6: Contact us
    url(r'^api/contact-us', view=views.contact_us, name="contact_us"),

    # verify profile services
    url(r'^api/email-verify', view=views.email_verify, name="email_verify"),
    url(r'^api/token_validation', view=views.token_validation, name="token_validation"),
    url(r'^api/resend_email', view=views.resend_email, name="resend_email")
]