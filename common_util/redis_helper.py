import os, sys
import redis
from . import  common_util, custom_exceptions, ref_strings
import json

def redis_connection():
    """
    Redis Connection
    """

    try:
        config = common_util.get_config()

        pool = redis.ConnectionPool(
            host=config.get('redis', 'host'),
            port=int(config.get('redis', 'port')),
            db=int(config.get('redis', 'db'))
        )

        redis_conn = redis.Redis(connection_pool=pool)

        # Check if the connection is up
        if redis_conn.ping():
            return redis_conn
        else:
            raise Exception('Redis Server is Down')

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        print (error)
        raise


def setex(logger, key, value, time_out):
    try:
        red_con = redis_connection()
        red_con.setex(key, time_out, json.dumps(value))
        return True        
    except Exception as e :
        error = common_util.get_error_traceback(sys, e)
        logger.error_logger('redis setx error %s ' %error)
        raise e

def get_key(logger, key):
    try:
        redis_conn = redis_connection()
        data = redis_conn.get(key)
        if not data:
           return False
        return data.decode('utf-8')

    except custom_exceptions.UserException:
        raise

    except Exception as e:
        error = common_util.get_error_traceback(sys, e)
        logger.error_logger('redis get_key error: %s ' %error)
        raise e

def set_key(key, value):
    try:
        red_con = redis_connection()
        red_con.set(key, value)
        return True        
    except Exception as e :
        error = common_util.get_error_traceback(sys, e)
        print (error)
        return False

def del_key(key):
    try:
        red_con = redis_connection()
        red_con.delete(key)
        return True        
    except Exception as e :
        error = common_util.get_error_traceback(sys, e)
        print (error)
        return False