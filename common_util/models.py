import sys,os
import mysql.connector
from . import  common_util, logger

import json


def convert_to_dict(columns_, results):
    allResults = []
    columns = [columns[0] for col in columns_]
    if type(results) is list:
        for value in results:
            allResults.append(dict(zip(columns, value)))
        return allResults
    elif type(results) is tuple:
        allResults.append(dict(zip(columns, results)))
        return allResults


def make_dict_factory(cursor):
    column_names = [d[0].lower() for d in cursor.description]

    def create_row(*args):
        return dict(zip(column_names, args))

    return create_row


def query_from_data(insert_data):  #formulate query for insert data
    condition = ''
    for key,value in insert_data.items():
        if type(value) == str:
            condition += "'{}'".format(value)+','
        else:
            condition += '{}'.format(value)+','

    return condition[:-1]

 

def query_from_filter(filters, type_='AND', search=False):
    params = ''

    if search:
        for key, value in filters.items():
            params += "lower({0}) LIKE '%{1}%' {2} ".format(key, value.lower(), type)
    else:
        for key, value in filters.items():
            if type(value) == str:
                params += "%s = '%s' %s " % (key, value, type_)
            else:
                params += '''{} = {} {} '''.format(key, value, type_)


    return params[:-(len(type_)+2)]


def db_connection(logger):
    try:

        config = common_util.get_config()
        db_name = config.get('db_mysql','db_name')
        user_name = config.get('db_mysql', 'user_name')
        password = config.get('db_mysql', 'password')
        host = config.get('db_mysql', 'host')
        return mysql.connector.connect(
            host=host,
            database=db_name, 
            user=user_name, 
            password=password
        )
    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        logger.error_logger('db connection error %s'  %error)
        print (error)
        raise e


def find_sql(logger, table_name, filters={}, columns='', sort=False, limit=False):
    try:
        data = None
        query = 'NA'
        db = db_connection(logger)
        cursor = db.cursor(dictionary=True)
        
        if columns:
            columns = ','.join(columns)
        else:
            columns = '*'

        if filters:
            params = query_from_filter(filters)
            query = 'SELECT %s FROM %s WHERE %s' %(columns, table_name, params)
        else:
            query = 'SELECT %s FROM %s' %(columns, table_name)

        if sort:
            query += ' ORDER BY '+ sort[0]+ " "+ sort[1]

        if limit:
             query += ' LIMIT {} , {} '.format(limit[0], limit[1])
        cursor.execute(query)
        data = cursor.fetchall()
        logger.msg_logger('>>>>>>>> MSQL Find Success : %s' %(query))

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        logger.error_logger('find_sql : %s || %s'%(error, query))
        raise e
    finally:
        if db: db.close()
        return data


def insert_sql(logger, table_name, insert_data):
    try:
        data = None
        ret_status = False
        db = db_connection(logger)
        cursor = db.cursor()
        query = 'insert into %s (%s) Values (%s)' %(table_name, ','.join([key for key in insert_data]), query_from_data(insert_data))
        cursor.execute(query)
        db.commit()
        logger.msg_logger('>>>>>>>> SQL Insert Success : %s ' % (query))
        ret_status = True

    except Exception as e :
        error = common_util.get_error_traceback(sys, e)
        print (error)
        logger.error_logger('insert_psql : %s || %s ' % (error, query))
        raise e
    finally:
        if db: db.close()
        return ret_status


def update_sql(logger, table_name, update_data, condition):
    try:
        ret_status = False
        db = db_connection(logger)
        cursor = db.cursor()
        query = 'update  %s set %s where %s' %(table_name, query_from_filter(update_data, type_= ',') , query_from_filter(condition, type_= 'AND'))
        cursor.execute(query)
        db.commit()
        logger.msg_logger('>>>>>>>> SQL update_sql Success : %s ' % (query))
        ret_status = True

    except Exception as e :
        error = common_util.get_error_traceback(sys, e)
        print (error)
        logger.error_logger('update_sql : %s || %s ' % (error, query))
        raise e
    finally:
        if db: db.close()
        return ret_status



def selectIFexist(logger, table_name, column):
    try:
        data = None
        db = db_connection(logger)
        cursor = db.cursor()
        query='SELECT COUNT(*) FROM %s WHERE email="%s"' %(table_name, column)
        cursor.execute(query)
        data = cursor.fetchone()
        logger.msg_logger('>>>>>>>> MSQL selectIFexist Success : %s' %(query))
        data = data[0]
    except Exception as e :
        error = common_util.get_error_traceback(sys, e)
        print (error)
        logger.error_logger('selectifexist : %s || %s ' % (error, query))
        raise e
    finally:
        if db: db.close()
        return data


def updateMany(logger, data_list=None, table_name=None):
    """
    Updates a mysql table with the data provided. If the key is not unique, the
    data will be inserted into the table.

    The dictionaries must have all the same keys due to how the query is built.

    Param:
        data_list (List):
            A list of dictionaries where the keys are the mysql table
            column names, and the values are the update values
        mysql_table (String):
            The mysql table to be updated.
    """

    try:
        ret_status = False
        db = db_connection(logger)
        cursor = db.cursor()
        query = ""
        values = []

        for data_dict in data_list:

            if not query:
                columns = ', '.join('`{0}`'.format(k) for k in data_dict)
                duplicates = ', '.join('{0}=VALUES({0})'.format(k) for k in data_dict)
                place_holders = ', '.join('%s'.format(k) for k in data_dict)
                query = "INSERT INTO {0} ({1}) VALUES ({2})".format(table_name, columns, place_holders)
                query = "{0} ON DUPLICATE KEY UPDATE {1}".format(query, duplicates)

            v = list(data_dict.values())
            values.append(v)

            cursor.executemany(query, values)
        ret_status = True
    
    except Exception as e :
        error = common_util.get_error_traceback(sys, e)
        print (error)
        logger.error_logger('selectifexist : %s || %s || %s ' % (error, query, values))
        raise e
    finally:
        if db: 
            db.commit()
            cursor.close()
            db.close()
        return ret_status
