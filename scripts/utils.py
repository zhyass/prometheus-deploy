import json
import traceback
import httplib
import os
import subprocess
import time
import logging.handlers
# call the function before calling other functions of the current file
def init_logger(logger_name, log_dir):
    global logger
    if not os.path.isdir(log_dir):
        os.system("mkdir -p %s; chmod 755 %s" % (log_dir, log_dir))
    radon_deploy_log = "%s/%s.log" % (log_dir, logger_name)
    Rthandler = logging.handlers.RotatingFileHandler(radon_deploy_log, maxBytes=20 * 1024 * 1024 , backupCount=5)
    formatter = logging.Formatter('%(asctime)s -%(thread)d- [%(levelname)s] %(message)s (%(filename)s:%(lineno)d)')
    Rthandler.setFormatter(formatter)

    logger = logging.getLogger('radon')
    logger.addHandler(Rthandler)
    logger.setLevel(logging.INFO)
    return logger

def get_json_params(params=None):
    json_params = {}
    if params:
        json_params = json.loads(params[0])
    return json_params

def exec_cmd(cmd):
    """
    :param cmd: the command you want to call
    :return: ret_code, output
    """
    try:
        ret = subprocess.check_output(cmd, shell=True)
        return 0, ret
    except subprocess.CalledProcessError as e:
        return e.returncode, e.output

def check_local_service(service,str_port):
    try:
        port = int(str_port)
    except ValueError:
        #Handle the exception
        logger.error('Please enter an integer %s' % str_port)
        return False
    cmd = 'nc -z -v -w10 127.0.0.1 %d' % port
    ret_code, _ = exec_cmd(cmd)
    if ret_code != 0:
        logger.error('no process listen at %d' % port)
        return False

    cmd = 'pidof %s' % service
    ret_code, output = exec_cmd(cmd)
    if ret_code != 0 or len(output) == 0:
        #port occupied by other process,need kill the process 
        command='''kill -9 $(netstat -nlp | grep %d | awk '{print $7}' | awk -F"/" '{ print $1 }')''' % port
        exec_cmd(command)
        logger.error('cannot find %s process' % service)
        return False
    return True

def read_file(filename, mode='r'):
    try:
        if not os.path.exists(filename):
            return None
        with open(filename, mode) as f:
            content = f.read()
    except Exception, e:
        logger.error("read file [%s] failed, [%s]" % (filename, e))
        return None
    return content

def wait_conf_file_ready(conf_file, retry=5, check=False):
    is_not_null = False
    is_exists = False
    while retry > 0:
        if os.path.exists(conf_file):
            is_exists = True
            if check:
                if read_file(conf_file, "r").strip():
                    is_not_null = True
                    break
            else:
                break
        retry -= 1
        time.sleep(1)
        continue
    else:
        if is_exists:
            if not is_not_null:
                logger.error("%s exists but it is empty" % conf_file)
                return -1
        else:
            logger.error("%s is not exist" % conf_file)
            return -1
    logger.info("%s is ready" % conf_file)
    return 0

def http_request(host, port, method, url, body=None, headers=None):
    '''
    url example: /v1/radon/backend
    '''
    logger.info("http_request: host [%s], port [%d], method [%s], url [%s], body [%s], headers [%s]"
                % (host, port, method, url, body, json.dumps(headers)))
    if method not in ['GET', 'PUT', 'POST', 'DELETE']:
        logger.error("get wrong http method [%s]" % method)
        return -1, ""

    try:
        conn = httplib.HTTPConnection("%s:%d" % (host, port))
        if not conn:
            logger.error("create http connection failed")
            return -1, ""

        conn.request(method, url, body, headers)
        res = conn.getresponse()
        if res.status != 200:
            logger.error("http request failed, status [%d], reason [%s], data [%s]"
                         % (res.status, res.reason, res.read()))
            conn.close()
            return -1, ""

        data = res.read()
        logger.info("http request succeeded, status [%d], reason [%s], data [%s]"
                     % (res.status, res.reason, data))
        conn.close()
        return 0, data
    except:
        err_msg = traceback.format_exc()
        logger.error(err_msg)
        conn.close()
        logger.error("http_request failed")
        return -1, ""

def write_json_file(filepath, record):
    try:
        msg = json.dumps(record, indent=1)
        with open(filepath, 'w+') as file_object:
            file_object.write("%s" % msg)
        return 0
    except Exception, e:
        logger.error("write json failed: %s" % e)
        return -1