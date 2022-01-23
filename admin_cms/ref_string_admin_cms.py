class AdminCms:
    invalid_credentials = 'Invalid Admin Detail'
    duplicate_login = 'Email has already been registered'
    password_mismatch = 'Password Doesnt Match '
    database_issue = 'OOps something went wrong !!'
    unable_to_verify_email = 'unable_to_verify_email'
    login_sucess = 'login_success'
    invalid_token = 'invalid_token'
    


class Tables:
    admin = 'admin'
    token_verification = 'token_verification'
    role = 'role'
    otp_detail = 'otp_detail'
    user_master = 'user_master'
    address_list = 'address_list'
    address_master = 'address_master'
    contact_us = 'contact_us'
    kyc = 'app_kycmanagement'
    suport_ticket = 'app_supportticket'
    ticket_message = 'app_ticketmessage',
    investment_plans = 'investment_plans'
    


class Common:
    bad_request = 'Internal Server Error'
    missing_input_params = 'Input Params Missing'
    invalid_credentials = 'Invalid Credentials'
    redis_error = 'Error with redis operation'
    login_sucess = 'Login Success'
    password_changed='Password Changed Successfully'
    duplicate_login = 'Email address Exist'
    invalid_email='You have not yet signed up or email is incorrect. Please check your email'
    internal_server_error = 'Internal Server Error'
    two_fa_sucess = '2fa Activated Successfully'
    two_fa_not_activated = '2fa Not Activated'
    two_fa_invalid = 'Invalid 2fa Authentication'   
    duplicate_2fa = 'Duplicate 2fa request'
    invalid_user = 'Unauthorized user / session expired'
    otp_reenalbe = "Otp reenable"
    role_not_defined = "User Role not found"
    invalid_form_data = "Invalid data"
    kyc_already_done = "Contact administrator for further KYC change"
    kyc_storage_error = "Error in storing Kyc Data"
    kyc_file_storage_error = "Error in Saving  Kyc File"
    unable_to_validate_email = "Unable to Send Verification Link"
    invalid_token = 'Invalid Verification Token'
    token_expired = 'Token Expired'
    unable_to_verify_email = 'Unable To verify User Email address'
    verify_email = 'Please Verify Your Email Address'
    admin_not_active = "You are currently inactive. Contact someone."
    pasword_not_matching = "Password Mismatch"
    need_to_activate = "Your username is created but needs approval from other admin"
    admin_activated = "The admin is activated"
    admin_deactivated = "The admin is deactivated"
    user_not_found = "User Not Found"
    operation_sucess = "Operation Sucess !!"
    operation_failed = "Operation Failed !!"
    invalid_user_status = "Invalid User Status"
    user_status_updated_sucess = "User Status Updated Successfully"
    user_status_updated_fail = "Failed to upadte user status"
    user_not_found = "User Not found"
    admin_deleted = "Admin Deleted Successfully"
    user_deleted = "User Deleted Successfully"
    unable_to_create_admin= "Unable to Create Admin User",
    investment_plan_not_found = "Investment plan was not exist",
    investment_plan_deleted = "Investment Plan Deleted Successfully",
    investment_plan_exist = "Investment Plan already exist"




class UserStatusList:
    no_restrictions = 'no_restrictions'
    user_blocked = 'user_blocked'
    crypto_payment_blocked = 'crypto_payment_blocked'
    user_status_label = {
        "crypto_payment_blocked" : "Block Crypto Payment",
        "user_blocked" : "Block User From Platform",
        "no_restrictions" :"Free User From all Bans"
    }

class ProjectionFields:
    get_investment_plan_list = 'uuid, id, plan_name, minimum_investment, maximum_investment, profit, Instant_withdrawal,capital_security,status, '
    get_investment_plan_details = 'uuid, id, plan_name, minimum_investment, maximum_investment, profit, Instant_withdrawal,capital_security,status'
