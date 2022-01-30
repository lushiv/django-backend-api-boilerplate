import sys,os
from . import util as admin_util , ref_string_admin_cms as admin_ref_string, models as admin_model
from common_util import custom_exceptions, ref_strings, models as common_model, common_util
from django.views.decorators.csrf import csrf_exempt
import json


def list_all_customer(logger, filters, order_dict, pagination ):
    try:
        db_data = None
        wherecase = ()

        db = common_model.db_connection(logger)

        cursor = db.cursor(dictionary=True)

        projection_file =  'uuid, email, username, role_id, kyc_status, verified, '
        list_query = 'SELECT   '
        count_query = ' select count(*) as count '

        list_query += projection_file

        date_query  = ''' DATE_FORMAT(FROM_UNIXTIME(UNIX_TIMESTAMP(timestamp)), '%Y-%m-%d') AS created_on  '''
        list_query += date_query
        base_query = ' FROM {} WHERE deleted = 0  '.format(admin_ref_string.Tables.user_master)

        filter_query = ''
        if (filters.get('email')):
            filter_query += ' AND email like  %s '
            # wherecase.append()
            wherecase = (*wherecase, "%"+filters.get('email')+"%")

            base_query += filter_query


        order_query = ' ORDER BY '

        order_query += ' {} {} '.format( order_dict.get('order_item'), order_dict.get('sort_item'))

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




        logger.msg_logger('>>>>>>>> MSQL  Success : %s :: %s ' %(base_query, wherecase))

        
    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        logger.error_logger('validate_address : %s || %s'%(error, query))
        raise e
    finally:
        if db:
            cursor.close()
            db.close()
        return db_data, db_count



def list_all_admins(logger, filters, order_dict, pagination ):
    try:
        db_data = None
        wherecase = ()

        db = common_model.db_connection(logger)

        cursor = db.cursor(dictionary=True)

        projection_file =  'uuid, id, email, first_name, last_name, role, status, verified,  '
        list_query = 'SELECT   '
        count_query = ' select count(*) as count '

        list_query += projection_file

        date_query  = ''' DATE_FORMAT(FROM_UNIXTIME(UNIX_TIMESTAMP(created_at)), '%Y-%m-%d') AS created_on  '''
        list_query += date_query
        base_query = ' FROM {} WHERE deleted = 0 '.format(admin_ref_string.Tables.admin) #tood deleted option

        filter_query = ''
        if (filters.get('email')):
            filter_query += ' AND email like  %s '
            # wherecase.append()
            wherecase = (*wherecase, "%"+filters.get('email')+"%")

            base_query += filter_query


        order_query = ' ORDER BY '

        order_query += ' {} {} '.format( order_dict.get('order_item'), order_dict.get('sort_item'))

        base_query += order_query
        list_query += base_query


        # pagination
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




        logger.msg_logger('>>>>>>>> MSQL  Success : %s :: %s ' %(base_query, wherecase))

        
    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        logger.error_logger('list_all_admins : %s || %s'%(error, query))
        raise e
    finally:
        if db:
            cursor.close()
            db.close()
        return db_data, db_count



def get_customer_detail(logger, uuid):
    try:
        wherecase = ()
        query =   """SELECT 
    kyc.status,
    kyc.first_name,
    kyc.last_name,
    kyc.resident,
    kyc.verification_type,
    kyc.id_number,
    kyc.reject_reason,
    kyc.timestamp AS kyc_created_at,
    user.email,
    user.verified,
    user.created_at AS user_created_at,
    user.status AS user_status
FROM
    app_kycmanagement AS kyc
        LEFT JOIN
    user_master user ON kyc.user_id = user.uuid
WHERE
    user.uuid = %s AND user.deleted = 0
        AND kyc.rejected = 0;"""
        db = common_model.db_connection(logger)
        cursor = db.cursor(dictionary=True)
        wherecase =( *wherecase, uuid)
        
        db_data = cursor.execute(query, wherecase)
        db_data = cursor.fetchall()
        logger.msg_logger('>>>>>>>> MSQL  Success : %s :: %s ' %(query, uuid))

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        logger.error_logger('get_customer_detail : %s || %s'%(error, query))
        raise e
    finally:
        if db:
            cursor.close()
            db.close()
        return db_data