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


def get_contact_us_list(logger, filters, order_dict, pagination):
    try:
        db_data = None
        db_count = None

        wherecase = ()

        db = common_model.db_connection(logger)

        cursor = db.cursor(dictionary=True)

        projection_file = 'uuid, id, email, name, subject, message, resolved, '
        list_query = 'SELECT   '
        count_query = ' select count(*) as count '

        list_query += projection_file

        date_query  = ''' DATE_FORMAT(FROM_UNIXTIME(UNIX_TIMESTAMP(created_at)), '%Y-%m-%d') AS created_on  '''
        list_query += date_query
        base_query = ' FROM {} WHERE deleted = 0  '.format(admin_ref_string.Tables.contact_us) #tood deleted option

        filter_query = ''

        #filter data :: email && resolved 
        if (filters.get('email')):
            filter_query += ' AND email like  %s '
            # wherecase.append()
            wherecase = (*wherecase, "%"+filters.get('email')+"%")

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
        logger.error_logger('get_customer_detail : %s || %s'%(error, query))
        raise e
    finally:
        if db:
            cursor.close()
            db.close()
        return db_data, db_count



def get_deleted_address(logger, filters, order_dict, pagination ):
    try:
        db_data = None
        wherecase = ()

        db = common_model.db_connection(logger)

        cursor = db.cursor(dictionary=True)

        projection_file =  'email, currency_name, address, label, address_type, balance, '
        list_query = 'SELECT   '
        count_query = ' select count(*) as count '

        list_query += projection_file

        date_query  = ''' DATE_FORMAT(FROM_UNIXTIME(UNIX_TIMESTAMP(timestamp)), '%Y-%m-%d') AS created_on  '''
        list_query += date_query
        base_query = ' FROM {} where True  '.format(admin_ref_string.Tables.address_list)

        filter_query = ''
        if (filters.get('address')):
            filter_query += ' AND address =  %s '
            # wherecase.append()
            wherecase = (*wherecase, filters.get('address'))
            base_query += filter_query

        if (filters.get('email')):
            filter_query += ' AND email like  %s '
            # wherecase.append()
            wherecase = (*wherecase, "%"+filters.get('email')+"%")
            base_query += filter_query


        order_query = ' ORDER BY timestamp '

        order_query += ' {}  '.format( order_dict.get('sort_item'))

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
        logger.error_logger('get all address : %s || %s'%(error, query))
        raise e
    finally:
        if db:
            cursor.close()
            db.close()
        return db_data, db_count


#@sql raw quryy for get all investment plans list
def get_investment_plan_list(logger, filters, order_dict, pagination):
    try:
        #print(filters,order_dict,pagination)
        db_data = None
        db_count = None

        wherecase = ()

        db = common_model.db_connection(logger)

        cursor = db.cursor(dictionary=True)

        projection_file = admin_ref_string.ProjectionFields.get_investment_plan_list
        list_query = 'SELECT   '
        count_query = ' select count(*) as count '

        list_query += projection_file

        date_query  = ''' DATE_FORMAT(FROM_UNIXTIME(UNIX_TIMESTAMP(created_at)), '%Y-%m-%d') AS created_on  '''
        list_query += date_query
        base_query = ' FROM {} WHERE deleted = 0  '.format(admin_ref_string.Tables.investment_plans) #tood deleted option

        filter_query = ''

        #filter data :: plan_name
        if (filters.get('plan_name')):
            filter_query += ' AND plan_name like  %s '
            # wherecase.append()
            wherecase = (*wherecase, "%"+filters.get('plan_name')+"%")

        elif (filters.get('minimum_investment')):
            filter_query += ' AND minimum_investment like  %s '
            # wherecase.append()
            wherecase = (*wherecase, "%"+filters.get('minimum_investment')+"%")

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

#@sql raw quryy for get all investment plans list
def get_investment_plan_details(logger, uuid):
    try:
  
        wherecase = ()
        projection_file = admin_ref_string.ProjectionFields.get_investment_plan_details
        details_query = 'SELECT '

        details_query += projection_file

        base_query = ' FROM {} WHERE uuid = %s AND deleted = 0    '.format(admin_ref_string.Tables.investment_plans)

        details_query += base_query

        db = common_model.db_connection(logger)
        cursor = db.cursor(dictionary=True)
        wherecase =( *wherecase, uuid)
        db_data = cursor.execute(details_query, wherecase)
        db_data = cursor.fetchall()
        print('!!!!!!!', db_data)
        logger.msg_logger('>>>>>>>> MSQL  Success : %s :: %s ' %(details_query, uuid))

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        logger.error_logger('get_investment_plan_details : %s || %s'%(error, details_query))
        raise e
    finally:
        if db:
            cursor.close()
            db.close()
        return db_data


#@sql raw quryy for get my plan details
def get_investment_my_plan_details(logger,uuid):
    try:
        db_data = None
        db = common_model.db_connection(logger)
        cursor = db.cursor(dictionary=True)


        query = " SELECT  ip.uuid, ip.plan_name, ip.minimum_investment, ip.maximum_investment, ip.profit, ip.Instant_withdrawal,ip.capital_security,ip.status,u.plan_id FROM user_master u Left join investment_plans ip on u.plan_id = ip.id where u.uuid = '%s'" %uuid
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