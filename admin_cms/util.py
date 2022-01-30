from customer_app import views
import sys

from common_util import common_util,  custom_exceptions, models, redis_helper, logger, redis_helper, encryption
from common_util import email_verification, jwt_operation

from . import ref_string_admin_cms as ref_strings, models as admin_model


obj_admin = common_util.CommonUtil(log='admin_logs')
obj_admin.create_logger()


def create_new_admin(new_user_email, password, password_confirm, first_name, last_name, role):
    try:
        obj_admin.create_logger()

        # check if email exisit
        email_exist = models.find_sql(
            logger=obj_admin.logger,
            table_name=ref_strings.Tables.admin,
            filters={
                'email': new_user_email,
                'deleted': 0
            }
        )
        if email_exist:
            raise custom_exceptions.UserException(ref_strings.AdminCms.duplicate_login)

        if not password == password_confirm:
            raise custom_exceptions.UserException(ref_strings.AdminCms.password_mismatch)

        user_id = common_util.get_uuid()

        insert_data = {
            'uuid': user_id,
            'email': new_user_email,
            'password': encryption.get_hash(password),
            'first_name': first_name,
            'last_name': last_name,
            'role': int(role)
        }

        db_status = models.insert_sql(
            obj_admin.logger,
            ref_strings.Tables.admin,
            insert_data
        )
        if not db_status:
            raise custom_exceptions.UserException(ref_strings.AdminCms.database_issue)

        admin_verification_link = common_util.config.get('email_service','admin_email_confirmation_link')
        email_verification.create_email_verification(obj_admin.logger, user_id, new_user_email, first_name, admin_verification_link)
        return {
            'message': 'Admin User created Successfully '
        }

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_admin.logger.error_logger(error)
        raise


def admin_email_verification(token):
    try:
        obj_admin.create_logger()
        token_status = models.find_sql(
            logger = obj_admin.logger,
            table_name= ref_strings.Tables.token_verification, 
            filters={
                'token' : token, 
                'used' : 0, 
                'deleted' : 0
            }
        )
        if not token_status: 
            raise custom_exceptions.UserException(ref_strings.AdminCms.invalid_token)

        delete_token_status = models.update_sql(
                logger=obj_admin.logger, 
                table_name=ref_strings.Tables.token_verification, 
                update_data={
                    'used' : 1,
                    'deleted' : 1
                }, 
                condition={
                    'token' : token
                }
            )

        if (token_status[0].get('expiry_time') < common_util.get_unix_time()):
            raise custom_exceptions.UserException(ref_strings.Common.token_expired)
        
        user_id = token_status[0].get('user_id')

        #make user email verifeid in user master
        verified_status = models.update_sql(
            logger= obj_admin.logger,
            table_name=ref_strings.Tables.admin,
            update_data={
                "verified" : True
            },
            condition={
                "uuid" : user_id
            }
        )
        if not verified_status:
            raise custom_exceptions.UserException(ref_strings.AdminCms.unable_to_verify_email)
        
        user_detail = models.find_sql(
            logger = obj_admin.logger,
            table_name= ref_strings.Tables.admin, 
            filters={
                'uuid' : user_id
            }
        )
        if not user_detail: 
            raise custom_exceptions.UserException(ref_strings.Common.invalid_user)
        user_email = user_detail[0].get('email')
        role = models.find_sql(obj_admin.logger, ref_strings.Tables.role, {'id' : user_detail[0].get('role')})
        if not role:
            raise custom_exceptions.UserException(ref_strings.Common.role_not_defined)
       
        user_role =  role[0].get('role')
        encoded_jwt = jwt_operation.make_jwt_operation(
            logger = obj_admin.logger,
            email = user_email, 
            user_role= user_role, 
            user_id = user_id
        )
        
        multi_factor_auth_status = models.find_sql(
            logger= obj_admin.logger, 
            table_name= ref_strings.Tables.otp_detail, 
            filters= {
                'email': user_email, 
                'otp_status': True
                }
        )
        
        multi_factor_auth_status = True if (multi_factor_auth_status or len(multi_factor_auth_status)) > 0 else False

        return_data = {
            'token' : encoded_jwt,
            'userInfo' : {
            'email' : user_email,
            'multi_factor_auth_enable' : multi_factor_auth_status,
            'user_id' : user_id,
            'role' : user_role
            },
            'message' : ref_strings.Common.login_sucess
        }
        return return_data
        

    except custom_exceptions.UserException:
        raise 
    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_admin.logger.error_logger('admin email_verification %s' %error)
        raise


def admin_login(email, password):
    try:

        data = {
            'email':email,
            'password': encryption.get_hash(password),
            'deleted': 0
        }

        db_check = models.find_sql(
            obj_admin.logger, 
            ref_strings.Tables.admin, 
            data
        )

        if not db_check:
            raise custom_exceptions.UserException(ref_strings.AdminCms.invalid_credentials)

        db_check = db_check[0]
        user_id = db_check.get('uuid')


        role = models.find_sql(obj_admin.logger, ref_strings.Tables.role, {'id' : db_check.get('role')})
        if not role:
            raise custom_exceptions.UserException(ref_strings.Common.role_not_defined)
       
        user_role =  role[0].get('role')
        
        encoded_jwt = jwt_operation.make_jwt_operation(
            logger = obj_admin.logger,
            email = email,
            user_role = user_role, 
            user_id = user_id
        )

        multi_factor_auth_status = models.find_sql(
            logger= obj_admin.logger, 
            table_name= ref_strings.Tables.otp_detail, 
            filters= {
                'email': email, 
                'otp_status': True
                }
        )
        
        multi_factor_auth_status = True if multi_factor_auth_status or len(multi_factor_auth_status) > 0 else False

        return_data = {
            'token' : encoded_jwt,
            'userInfo' : {
            'email' : email,
            'multi_factor_auth_enable' : multi_factor_auth_status,
            'user_id' : user_id,
            'role' : user_role
            },
            'message' : ref_strings.Common.login_sucess
        }
        return return_data


    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_admin.logger.error_logger('admin login %s' %error)
        raise


def changepw(uuid, oldpassword, newpassword, confirm_password):
    try:
        if not newpassword == confirm_password:
            raise custom_exceptions.UserException(ref_strings.Common.pasword_not_matching)

        data = {
            'uuid': uuid,
            'password': encryption.get_hash(oldpassword),
            'deleted' : 0
        }

        db_check = models.find_sql(obj_admin.logger, ref_strings.Tables.admin, data)
        if not db_check:
            raise custom_exceptions.UserException(ref_strings.Common.invalid_credentials)
        
        updated_data = {
            'password': encryption.get_hash(newpassword)
        }

        db_status = models.update_sql(
            logger = obj_admin.logger, 
            table_name = ref_strings.Tables.admin, 
            update_data = updated_data, 
            condition = data
            )
        if not db_status:
            raise custom_exceptions.UserException(ref_strings.Common.internal_server_error)

        returnData={
            'message':ref_strings.Common.password_changed
        }
        return returnData

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_admin.logger.error_logger('changepw %s' %error)
        raise


def list_all_customer(filters, order_dict, pagination):
    try :
        cust_data, total_count = admin_model.list_all_customer(
            logger= obj_admin.logger, 
            filters= filters, 
            order_dict= order_dict, 
            pagination = pagination
        )

        return {
            'data' : cust_data,
            'count' : len(cust_data),
            'total_count' : total_count
        }

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_admin.logger.error_logger('list all customer %s' %error)
        raise


def get_customer_detail(uuid):
    try :
        kyc_detail = {}
        user_info = {}
        wallet_address_data = {}
        watch_address_data = {}
        investment_plan_info = {}

        cust_data = admin_model.get_customer_detail(   # join with kyc detail so if not kyc uploaded goto else
            logger=obj_admin.logger,
            uuid=uuid
        )

        get_plan_list = admin_model.get_investment_my_plan_details(logger=obj_admin.logger,
        uuid=uuid)
        if len(cust_data) > 0:
            cust_data = cust_data[0]
            kyc_detail = {
                'kyc_status': cust_data.get('status'),
                'first_name' : cust_data.get('first_name'),
                'last_name' : cust_data.get('last_name'),
                'resident' : cust_data.get('resident'),
                'verification_type' : cust_data.get('verification_type'),
                'id_number' : cust_data.get('id_number'),
                'reject_reason' : cust_data.get('reject_reason'),
                'kyc_created_at' : cust_data.get('kyc_created_at'),
            }
            customer_status = cust_data.get('user_status') if (not cust_data.get('user_status') == None) else ref_strings.UserStatusList.no_restrictions
            customer_status_label = ref_strings.UserStatusList.user_status_label.get(customer_status)
            user_info = {
                'email' : cust_data.get('email'),
                'verified' : cust_data.get('verified'),
                'user_created_at': cust_data.get('user_created_at'),
                'uuid' : uuid,
                'user_status': customer_status,
                'user_status_label' : customer_status_label
            }

            investment_plan_info = {
            'plan_id' : get_plan_list[0].get('plan_id'),
            'plan_name' : get_plan_list[0].get('plan_name')
        }

        else:
            cust_data = models.find_sql(
                logger=obj_admin.logger, 
                table_name=ref_strings.Tables.user_master, 
                filters={
                    'uuid' : uuid,
                    'deleted' : 0
                }
            )
            if not cust_data:
                raise custom_exceptions.UserException(ref_strings.Common.user_not_found)

            # user restriction status
            cust_data = cust_data[0]
            customer_status = cust_data.get('user_status') if (not cust_data.get('user_status') == None) else ref_strings.UserStatusList.no_restrictions
            customer_status_label = ref_strings.UserStatusList.user_status_label.get(customer_status)

            user_info = {
                'email' : cust_data.get('email'),
                'verified' : cust_data.get('verified'),
                'user_created_at': cust_data.get('timestamp'),
                'uuid' : uuid,
                'user_status': customer_status,
                'user_status_label' : customer_status_label,
            }

            investment_plan_info = {
                'plan_id' : get_plan_list[0].get('plan_id'),
                'plan_name' : get_plan_list[0].get('plan_name')
            }


        # user 2fa status
        multi_factor_auth_status = models.find_sql(
            logger=obj_admin.logger,
            table_name=ref_strings.Tables.otp_detail,
            filters={'email': cust_data.get('email'), 'otp_status': True}
        )
        multi_factor_auth_status = True if multi_factor_auth_status or len(multi_factor_auth_status) > 0 else False
        user_info['multi_factor_auth_status'] = multi_factor_auth_status

        wallet_address_data = models.find_sql(
            logger=obj_admin.logger,
            table_name=ref_strings.Tables.address_list, 
            filters={
                'address_type': 'wallet',
                'email': cust_data.get('email'),
                'status': 1
            }
        )

        watch_address_data = models.find_sql(
            logger=obj_admin.logger,
            table_name=ref_strings.Tables.address_list, 
            filters={
                'address_type': 'watch_only',
                'email': cust_data.get('email'),
                'status': 1
            }
        )

        mnemonics = models.find_sql(
            logger=obj_admin.logger,
            table_name=ref_strings.Tables.address_master,
            filters={
                'email': cust_data.get('email'),
            }
        )
        if mnemonics:
            mnemonics = mnemonics[0].get('mnemonic')
        return_data = {
            'kyc_detail': kyc_detail,
            'user_info': user_info,
            'watch_address_data': watch_address_data,
            'wallet_address_data': wallet_address_data,
            'walletKey': mnemonics,
            'investment_plan_info' : investment_plan_info
        }

        return return_data

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_admin.logger.error_logger('list all customer %s' %error)
        raise



def customer_status_list():
    try:

        status_list = ref_strings.UserStatusList.user_status_label
        return {
            'customer_status_list' : status_list
        }

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_admin.logger.error_logger('customer_action_list %s' %error)
        raise



def customer_status_change(uuid, status): 
    try:
        status_list = ref_strings.UserStatusList.user_status_label
        if not status in status_list:
            raise custom_exceptions.UserException(ref_strings.Common.invalid_user_status)


        user_exist =  models.find_sql(
            logger=obj_admin.logger,
            table_name=ref_strings.Tables.user_master, 
            filters={
                'uuid' : uuid,
                'deleted' : 0
            }
        )

        if not user_exist:
            raise custom_exceptions.UserException(ref_strings.Common.user_not_found)

        status_update = models.update_sql(
            logger=obj_admin.logger,
            table_name=ref_strings.Tables.user_master,
            update_data={
                'status' : status
            },
            condition={
                'uuid' : uuid,
                'deleted' : 0                
            }
        )
        if not status_update:
            raise custom_exceptions.UserException(ref_strings.Common.user_status_updated_fail)
        return {
            'message' : ref_strings.Common.user_status_updated_sucess
        }

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_admin.logger.error_logger('customer_status_list %s' %error)
        raise


def list_all_admin(filters, order_dict, pagination):
    try :
        cust_data, total_count = admin_model.list_all_admins(
            logger= obj_admin.logger, 
            filters= filters, 
            order_dict= order_dict, 
            pagination = pagination
        )

        return {
            'data' : cust_data,
            'count' : len(cust_data),
            'total_count' : total_count
        }

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_admin.logger.error_logger('list all customer %s' %error)
        raise



def get_contact_us_detail(filters, order_dict, pagination):
    try:

        contact_us_list, total_count = admin_model.get_contact_us_list(
            logger= obj_admin.logger,
            filters= filters, 
            order_dict=order_dict, 
            pagination=pagination
        )
        if not contact_us_list:
            return_data = []
            return {'data' : return_data}


        contact_us_return_list = []
        for each_contact_us_data in contact_us_list:
            contact_us_data = {
                'name' : each_contact_us_data.get('name'),
                'email' : each_contact_us_data.get('email'),
                'subject' : each_contact_us_data.get('subject'),
                'message' : each_contact_us_data.get('message'),
                'resolved' : each_contact_us_data.get('resolved'),
                'id' : each_contact_us_data.get('uuid')
            }
            contact_us_return_list.append(contact_us_data)
        
        return_data = {
            'data' : contact_us_return_list,
            'count' : len(contact_us_return_list),
            'total_count' : total_count,
            'message' : ref_strings.Common.operation_sucess
        }

        return return_data
    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_admin.logger.error_logger('get_contact_us_detail%s' %error)
        raise


def contact_us_status_change(uuid, status, delete=False):
    try:
        if delete:
            update_condition = {
                'deleted': 1
            }
        else:
            update_condition = {
                'resolved': int(status),
            }
        db_status = models.update_sql(
            logger=obj_admin.logger,
            table_name=ref_strings.Tables.contact_us,
            update_data=update_condition,
            condition={
                'uuid': uuid
            }
        )
        if not db_status:
            raise custom_exceptions.UserException(ref_strings.Common.internal_server_error)

        return {"message": "Operation Success"}

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_admin.logger.error_logger('get_contact_us_detail%s' %error)
        raise


def delete_admin(uuid):
    try: 

        check_user_exist =  models.find_sql(
            logger=obj_admin.logger,
            table_name=ref_strings.Tables.admin, 
            filters={
                'uuid' : uuid,
                'deleted' : 0
            }
        )

        if not check_user_exist:
            raise custom_exceptions.UserException(ref_strings.Common.user_not_found)

        db_status = models.update_sql(
            logger=obj_admin.logger,
            table_name=ref_strings.Tables.admin,
            update_data={
                'deleted' : 1
            },
            condition={
                'uuid' : uuid,
                'deleted' : 0
            }
        )
        if not db_status:
            raise custom_exceptions.UserException(ref_strings.Common.internal_server_error)

        return  {"message" : ref_strings.Common.admin_deleted}


    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_admin.logger.error_logger('delete_admin%s' %error)
        raise


def delete_customer(uuid):
    try: 
        check_user_exist =  models.find_sql(
            logger=obj_admin.logger,
            table_name=ref_strings.Tables.user_master,
            filters={
                'uuid' : uuid,
                'deleted' : 0
            }
        )

        if not check_user_exist:
            raise custom_exceptions.UserException(ref_strings.Common.user_not_found)

        db_status = models.update_sql(
            logger=obj_admin.logger,
            table_name=ref_strings.Tables.user_master,
            update_data={
                'deleted' : 1
            },
            condition={
                'uuid' : uuid,
                'deleted' : 0
            }
        )
        if not db_status:
            raise custom_exceptions.UserException(ref_strings.Common.internal_server_error)

        return  {"message" : ref_strings.Common.user_deleted}


    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_admin.logger.error_logger('delete_customer%s' %error)
        raise




    try :
        get_user_id =  models.find_sql(
            logger=obj_admin.logger,
            table_name=ref_strings.Tables.kyc,
            filters={
                'id' : kyc_id
            }
        )
        if not get_user_id:
            raise custom_exceptions.UserException(ref_strings.Common.user_not_found)

        user_info = get_user_id[0]
        user_uuid = user_info.get('user_id')

        user_detail = models.find_sql(
            logger=obj_admin.logger,
            table_name=ref_strings.Tables.user_master,
            filters={
                'uuid' : user_uuid,
                'deleted' : 0
            },
            columns= ['email', 'username', 'created_at']
        )
        if not get_user_id:
            raise custom_exceptions.UserException(ref_strings.Common.user_not_found)

        user_detail = user_detail[0]

        return user_detail

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_admin.logger.error_logger('kyc by id%s' %error)
        raise


def get_user_id_by_email(email):
    try:
        user_data = models.find_sql(
            logger=obj_admin.logger,
            table_name=ref_strings.Tables.user_master,
            filters={
                'email' : email,
                'deleted' : 0
            },
            columns= ['uuid', 'email', 'username', 'created_at']
        )
        if not user_data:
            raise custom_exceptions.UserException(ref_strings.Common.user_not_found)
        return user_data[0]
    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_admin.logger.error_logger('delete_customer%s' %error)
        raise