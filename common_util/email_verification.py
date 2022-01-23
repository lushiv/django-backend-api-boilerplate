from common_util import common_util, ref_strings, custom_exceptions, models, redis_helper, logger, redis_helper, encryption
from . import ref_strings

obj_common = common_util.CommonUtil(log = 'common_logs')


def create_email_verification(logger, user_id, email, name, link=False):
    try:

        data_exist = models.find_sql(
            logger,
            table_name=ref_strings.Tables.token_verification, 
            filters={
                'user_id' : user_id, 
                'used' : 0, 
                'deleted' : 0
            }
        )
        if data_exist:
            db_data =  models.update_sql(
                logger,
                table_name=ref_strings.Tables.token_verification,
                update_data={
                    'deleted' : 1,
                    'used': 1
                },
                condition= {
                    'user_id' : user_id, 
                    'token' : data_exist[0].get('token')
                }
            )
            if not db_data: 
                raise custom_exceptions.UserException(ref_strings.Common.unable_to_validate_email)


        db_data = {
            'uuid' : common_util.get_uuid(),
            'user_id' : user_id,
            'token' : common_util.get_uuid(),
            'otp' : common_util.generate_otp(int(common_util.config.get('common_settings','otp_len'))) ,
            'expiry_time' : common_util.get_unix_time() + int(common_util.config.get('common_settings','token_expiry_time_hr'))* 60 * 60,
            'created_on' : common_util.get_unix_time()
        }
        db_status = models.insert_sql(
            logger,
            table_name=ref_strings.Tables.token_verification,
            insert_data= db_data
        )
        if not db_status:
            raise custom_exceptions.UserException(ref_strings.Common.unable_to_validate_email)
        
        link = common_util.config.get('email_service','email_confirmation_link') if not link else link 
        link +=  db_data.get('token') 

        send_signup_email(email, name , link)
        return  {}

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger(error)
        raise
        


def send_signup_email(email, name, link):
    try: 
        import requests

        url = common_util.config.get('email_service','email_link')
        payload = {
            "sender": {
                "email": common_util.config.get('email_service','sender_email')
            },
            "to": [
                {
                    "name": name,
                    "email": email
                }
            ],
            "templateId": 2,
            "params" : {
                "email" : email,
                "Link" : link
            },
            "replyTo": {
                "email": common_util.config.get('email_service','replyEmail'),
                "name": "BTC wallet Admin"
            }
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "api-key": common_util.config.get('email_service', 'access_key')
        }

        response = requests.request("POST", url, json=payload, headers=headers)

        print(response.text)


    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        obj_common.logger.error_logger(error)
        raise
        
