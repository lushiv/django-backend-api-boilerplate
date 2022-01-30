import sys,os
import uuid

from django.db import models

from . import util
from common_util import custom_exceptions, ref_strings, models as custom_model, common_util
from django.views.decorators.csrf import csrf_exempt
import json


def get_multifactor_login_details(logger, email, admin_request=False):
    try:
        db_data = None
        query = 'NA'

        db = custom_model.db_connection(logger)
        cursor = db.cursor(dictionary=True)

        if not admin_request:
            query = "SELECT u.email,u.uuid,u.username, r.role  FROM user_master u inner join role r on u.role_id = r.id where u.email = '%s'" %email
        else:
            query = "SELECT a.email,a.uuid, r.role  FROM admin a inner join role r on a.role = r.id where a.email = '%s'" %email

        cursor.execute(query)

        db_data = cursor.fetchall()

        logger.msg_logger('>>>>>>>> MSQL get_multifactor_login_details Success : %s' %(query))

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        logger.error_logger('get_multifactor_login_details : %s || %s'%(error, query))
        raise e
    finally:
        if db: db.close()
        return db_data


def execute_raw_query(logger, query, data_tuple = None):
    ''' only beign used to get data'''
    try:
        db_data = None

        db = custom_model.db_connection(logger)
        cursor = db.cursor(dictionary=True)

        if data_tuple:
            cursor.execute(query, data_tuple)
        else :
            cursor.execute(query)

        db_data = cursor.fetchall()

        logger.msg_logger('>>>>>>>> MSQL raw query  Success : %s || %s' %(query, data_tuple))

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        logger.error_logger('get raw query : %s || %s || %s '%(error, query, data_tuple))
        raise e
    finally:
        if db:
            cursor.close()
            db.close()
        return db_data