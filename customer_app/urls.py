
from django.conf.urls import url
from django.contrib import admin

from . import views

urlpatterns = [
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

    # email services
    url(r'^api/email-verify', view=views.email_verify, name="email_verify"),
    url(r'^api/token_validation', view=views.token_validation, name="token_validation"),
    url(r'^api/resend_email', view=views.resend_email, name="resend_email")
]