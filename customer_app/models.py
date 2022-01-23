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
 

#@sql raw quryy for get all investment plans list
def get_investment_plan_list(logger, order_dict, pagination):
    try:
        # print(order_dict,pagination)
        db_data = None
        db_count = None

        wherecase = ()

        db = custom_model.db_connection(logger)

        cursor = db.cursor(dictionary=True)

        projection_file = ref_strings.ProjectionFields.get_investment_plan_list
        list_query = 'SELECT   '
        count_query = ' select count(*) as count '

        list_query += projection_file

        date_query  = ''' DATE_FORMAT(FROM_UNIXTIME(UNIX_TIMESTAMP(created_at)), '%Y-%m-%d') AS created_on  '''
        list_query += date_query
        base_query = ' FROM {} WHERE deleted = 0  AND status=0 '.format(ref_strings.Tables.investment_plans) #tood deleted option

        filter_query = ''

        base_query += filter_query

        order_query = ' ORDER BY '

        order_query += ' {} {} '.format( order_dict.get('order'), order_dict.get('sort_by'))

        base_query += order_query
        list_query += base_query

        current_page = int(pagination.get('current_page'))
        per_page = int(pagination.get('per_page'))
        start_row = ( current_page -1 ) * per_page

        page_query = ' Limit {} , {} '.format(start_row, per_page)
        list_query += page_query

        count_query += base_query

    
        db_data = cursor.execute(list_query, wherecase)
        db_data = cursor.fetchall()

        db_data_count = cursor.execute(count_query, wherecase)
        db_count = cursor.fetchall()
        db_count = db_count[0].get('count')
        
        logger.msg_logger('>>>>>>>> MSQL  Success : %s ' %(list_query))

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        logger.error_logger('get_investment_plan_list : %s || %s'%(error, list_query))
        raise e
    finally:
        if db:
            cursor.close()
            db.close()
        return db_data, db_count




#@sql raw quryy for get my plan details
def get_investment_my_plan_details(logger,user_id):
    try:
        db_data = None
        db = custom_model.db_connection(logger)
        cursor = db.cursor(dictionary=True)


        query = " SELECT  ip.uuid, ip.plan_name, ip.minimum_investment, ip.maximum_investment, ip.profit, ip.Instant_withdrawal,ip.capital_security,ip.status,u.plan_id FROM user_master u Left join investment_plans ip on u.plan_id = ip.id where u.uuid = '%s'" %user_id
        cursor.execute(query)

        db_data = cursor.fetchall()
        logger.msg_logger('>>>>>>>> MSQL  Success : %s ' %(query))

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        logger.error_logger('get_investment_my_plan_details : %s || %s'%(error, query))
        raise e
    finally:
        if db:
            cursor.close()
            db.close()
        return db_data

#@get account details from address_list tbl and transaction_master
def get_account_details(logger,email):
    try:
        db_data = None
        db = custom_model.db_connection(logger)
        cursor = db.cursor(dictionary=True)
        query = '''SELECT 
                (SELECT 
                        SUM(balance)
                    FROM
                        django_backend.transaction_master
                    WHERE
                        email = '%s'
                            AND status = 'Received') AS total_deposit_balance,
                (SELECT 
                        SUM(balance)
                    FROM
                        django_backend.transaction_master
                    WHERE
                        email = '%s'
                            AND status = 'Sent') AS total_withdraw_balance;
                ''' %(email,email)
        cursor.execute(query)
        db_data = cursor.fetchall()
        logger.msg_logger('>>>>>>>> MSQL  Success : %s ' %(query))

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        logger.error_logger('get_account_details : %s || %s'%(error, query))
        raise e
    finally:
        if db:
            cursor.close()
            db.close()
        return db_data


def get_referral_details(logger,referral_token):
    try:
        db_data = None
        db = custom_model.db_connection(logger)
        cursor = db.cursor(dictionary=True)

        query = " SELECT * FROM user_master where uuid LIKE '%s'" % ("%" + referral_token + "%")
        cursor.execute(query)

        db_data = cursor.fetchall()
        logger.msg_logger('>>>>>>>> MSQL  Success : %s ' %(query))

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        logger.error_logger('get_referral_details : %s || %s'%(error, query))
        raise e
    finally:
        if db:
            cursor.close()
            db.close()
        return db_data