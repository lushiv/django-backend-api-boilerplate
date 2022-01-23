import sys,os,datetime
import json
from common_util import  custom_exceptions, models, redis_helper, logger, redis_helper, encryption
from . import ref_strings, common_util
import jwt


obj_common = common_util.CommonUtil(log = 'common_logs')


def make_jwt_operation(logger, email, user_role, user_id):
    try: 
        jwt_payload = {
            'email' : email,
            'role' : user_role,
            'user_id' : user_id
        }
        headers = {
            'timestamp': str(datetime.datetime.now())
        }

        encoded_jwt = jwt.encode(
            jwt_payload,
            obj_common.jwt_secret,
            algorithm= obj_common.jwt_algorithm,
            headers= headers
        )

        encoded_jwt = encoded_jwt.decode("utf-8")

        redis_status = redis_helper.setex(
            logger,
            key= encoded_jwt,
            value = json.dumps(jwt_payload),
            time_out= common_util.get_config().get('jwt', 'timeout')
        )
        if not redis_status:
            raise custom_exceptions.UserException(ref_strings.Common.bad_request)

        return encoded_jwt

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        logger.error_logger('make_jwt_operation %s ' %error)
        raise

