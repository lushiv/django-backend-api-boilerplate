
class Common:
    bad_request = 'Internal Server Error'
    missing_input_params = 'Input Params Missing'
    invalid_credentials = 'Invalid Credentials'
    redis_error = 'Error with redis operation'
    login_sucess = 'Login Sucess'
    password_changed='Password Changed Sucessfully'
    password_rest_sucessfully = 'Password Reset Sucessfully'
    password_mismatch = 'Password Mismatch'
    duplicate_login = 'Email address Exist'
    invalid_email='You have not yet signed up or email is incorrect. Please check your email'
    internal_server_error = 'Internal Server Error'
    two_fa_sucess = '2fa Activated Sucessfully'
    two_fa_not_activated = '2fa Not Activated'
    two_fa_invalid = 'Invalid 2fa Authentication'   
    duplicate_2fa = 'Duplicate 2fa request'
    invalid_user = 'Unauthorized user / session expired'
    otp_reenalbe = "Otp reenable"
    enter_otp =  "Please Enter Valid Otp"
    role_not_defined = "User Role not found"
    invalid_form_data = "Invalid data"
    unable_to_validate_email = "Unable to Send Verification Link"
    invalid_token = 'Verification Link Dead'
    token_expired = 'Token Expired'
    unable_to_verify_email = 'Unable To verify User Email address'
    verify_email = 'Please Verify Your Email Address'
    admin_not_active = "You are currently inactive. Contact someone."
    pasword_not_matching = "Password Mismatch"
    need_to_activate = "Your username is created but needs approval from other admin"
    admin_activated = "The admin is activated"
    admin_deactivated = "The admin is deactivated"
    invalid_jwt = 'Invalid User'
    forgot_password_email = 'Email has been Sent to provided Email for password recovery !!'
    forgot_password_fail_email = "unable to send forget password email"
    contact_us_sucess = "Thank You for contacting customer care, Someone from our team Will get Back To you within 24 hours !! "
    operation_failed = "Operation Failed"
    operation_success = "Operation Sucess"
    user_not_found = "User Not Found"
    email_sent_successfully = "Email Has Been Resent Successfully !!"


class Tables:
    user_master = 'user_master'
    role = 'role'
    otp_detail = 'otp_detail'
    token_verification = 'token_verification'
    admin = 'admin'
    active_status = 'admin_active',
    contact_us = 'contact_us'


class RoleId:
    customer = 1
    admin = 2
    manager = 3

class TokenValidationRefString:
    forgot_password = 'forgot_password'
    account_verification = 'account_verification'