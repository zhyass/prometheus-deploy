#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import yaml
import sys
import os
import subprocess
import time
import traceback
import logging.handlers
import sqlite3
import requests

SUPPORTED_ACTIONS = {
    "displayjobs": "display the prometheus monitor job list",
    "addjob": "add job to the prometheus monitor job list",
    "deljob": "delete job from the prometheus monitor job list",
    "reset": "reset the grafana server's admin password to default(admin)",
    "modifyuser": "modify the admin's password",
    "dashboards": "display dashboard for download",
    "healthcheck": "check the service status",
    "healthaction": "take action if service check health failed",
    "start": "start prometheus and grafana-server",
    "stop": "stop prometheus and grafana-server",
    "restart": "restart prometheus and grafana-server"
}

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

def add_job(job_cnf):
    logger.info("add_job")

    if not job_cnf:
        logger.error("add_job without config")
        return -1

    job_name = job_cnf.get("job_name", "").strip()
    ip = job_cnf.get("ip", "").strip()
    port = job_cnf.get("port", "")
    if not job_name:
        logger.error("add_job get job_name [%s] failed" % job_name)
        return -1
    if not ip:
        logger.error("add_job get ip [%s] failed" % ip)
        return -1
    if not port:
        logger.error("add_job get port [%d] failed" % port)
        return -1

    fd = open('/opt/prometheus/prometheus.yml', 'a')
    l = []
    l.append("  - job_name: '" + job_name + "'\n")
    l.append("    static_configs:\n")
    l.append("    - targets: ['" + ip + ":" + str(port) + "']\n")
    fd.writelines(l)
    fd.close()

    ret_code, _ = exec_cmd('service prometheus restart')
    if ret_code != 0:
        logger.error('add_job restart service prometheus failed')
        return -1

    logger.info("add_job succeeded")
    return 0

def del_job(job_cnf):
    logger.info("del_job")
    
    if not job_cnf:
        logger.error("del_job without config")
        return -1

    job_name = job_cnf.get("job_name","").strip()
    if not job_name:
        logger.error("del_job get job_name [%s] failed" % job_name)
        return -1

    iflag = 0
    s = "- job_name: '" + job_name + "'"
    with open('/opt/prometheus/prometheus.yml', 'r') as f:
        lines = f.readlines()
    f.close()
    with open('/opt/prometheus/prometheus.yml', 'w') as g:
        for line in lines:
            if iflag == 0:
                if s in line:
                    iflag = 1
                    continue
                g.write(line)
            elif iflag == 1:
                if '- job_name: ' in line:
                    iflag = 2
                    g.write(line)
            else :
                g.write(line)
    g.close()

    ret_code, _ = exec_cmd('service prometheus restart')
    if ret_code != 0:
        logger.error('del_job restart service prometheus failed')
        return -1

    logger.info("del_job succeeded")
    return 0

def modify_user(user_cnf):
    logger.info("modify_user")

    if not user_cnf:
        logger.error("modify_user without config")
        return -1

    oldpasswd = user_cnf.get("oldpasswd", "").strip()
    newpasswd = user_cnf.get("newpasswd", "").strip()
    confirmnew = user_cnf.get("confirmnew", "").strip()
    if not oldpasswd:
        logger.error("modify_user get oldpasswd [%s] failed" % oldpasswd)
        return -1
    if not newpasswd:
        logger.error("modify_user get newpasswd [%s] failed" % newpasswd)
        return -1
    if not confirmnew:
        logger.error("modify_user get confirmnew [%s] failed" % confirmnew)
        return -1
    if newpasswd != confirmnew:
        logger.error("modify_user please makesure the password is same!")
        return -1

    try:
        url = 'http://localhost:3000/api/user/password'
        body = {
            "oldPassword": oldpasswd,
            "newPassword": newpasswd,
            "confirmNew": confirmnew
        }
        res = requests.put(url, json=body, headers={"Content-Type": "application/json"}, auth=('admin', oldpasswd))
        if res.status_code != 200:
            logger.error("modify_user failed, status [%d], reason [%s], data [%s]"
                         % (res.status_code, res.reason, res.text))
            return -1

        logger.info("modify_user succeeded, status [%d], reason [%s], data [%s]"
                     % (res.status_code, res.reason, res.text))
        return 0
    except:
        err_msg = traceback.format_exc()
        logger.error(err_msg)
        logger.error("modify_user failed")
        return -1

def reset_admin():
    logger.info("reset_admin")

    conn = sqlite3.connect("/var/lib/grafana/grafana.db")
    conn.execute("update user set password = '59acf18b94d7eb0694c61e60ce44c110c7a683ac6a8f09580d626f90f4a242000746579358d77dd9e570e83fa24faa88a8a6', salt = 'F3FAxVm33R' where login = 'admin'")
    conn.commit()
    conn.close()

    logger.info("reset_admin succeeded")
    return 0

def disp_list():
    logger.info("disp_list")

    fd = open('/opt/prometheus/prometheus.yml', 'r')
    dict_tmp = yaml.load(fd)
    fd.close()

    l = []
    for i in dict_tmp['scrape_configs']:
        job_name = i['job_name']
        for j in i['static_configs']:
            for k in j['targets']:
                lst = k.split(":")
                if len(lst) != 2:
                    logger.error("disp_list failed, unsyntax err for 'prometheus.yml'")
                    return -1
                l.append([job_name, lst[0], lst[1]])

    ret_cnf = {
        "labels": ["job_name", "ip", "port"],
        "data": l
    }
    print json.dumps(ret_cnf)

    logger.info("disp_list succeeded")
    return 0

def disp_dashboard():
    logger.info("disp_dashboard")

    l = []
    ftppath = '/srv/ftp'
    fileList = os.listdir(ftppath)
    for fileName in fileList:
        if 'json' in fileName:
            l.append([fileName])
    ret_cnf = {
        "labels": ["fileName"],
        "data": l
    }
    print json.dumps(ret_cnf)
    
    logger.info("disp_dashboard succeeded")
    return 0

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

def check_local_service(service,port):
    cmd = 'nc -z -v -w10 127.0.0.1 %d' % port
    ret_code, _ = exec_cmd(cmd)
    if ret_code != 0:
        logger.error('no process listen at %d' % port)
        return False

    cmd = 'pidof %s' % service
    ret_code, output = exec_cmd(cmd)
    if ret_code != 0 or len(output) == 0:
        #port occupied by other process,need kill the process 
        command='''kill -9 $(netstat -nlp | grep : %d | awk '{print $7}' | awk -F"/" '{ print $1 }')''' % port
        exec_cmd(command)
        logger.error('cannot find %s process' % service)
        return False
    return True

def health_check():
    logger.info("health_check")
    bflag = False
    if not check_local_service("prometheus", 9090):
        logger.error('check prometheus process failed')
        bflag = True

    if not check_local_service("grafana-server", 3000):
        logger.error('check grafana-server process failed')
        if bflag:
            return -3, "prometheus and grafana-server are not running"
        return -2, "grafana-server is not running"

    if bflag:
        return -1, "prometheus is not running"

    logger.info("health_check succeeded")
    return 0,""

def health_action():
    logger.info("health_action")
    ret = health_check()

    cmd = ''
    if ret == -1:
        cmd = 'service prometheus start'
    elif ret == -2:
        cmd = 'service grafana-server start'
    elif ret == -3:
        cmd = 'service grafana-server start; service prometheus start'
    else:
        cmd = 'service grafana-server restart; service prometheus restart'
    ret_code, output = exec_cmd(cmd)
    if ret_code != 0:
        logger.error('health_action start the service failed, reason %s' % output)
        return -1

    logger.info("health_action succeeded")
    return 0

def stop_server():
    logger.info("stop_server")

    if not check_local_service("prometheus", 9090):
        logger.warning("stop_server skips the step to stop prometheus")
    else:
        ret_code, _ = exec_cmd('service prometheus stop')
        if ret_code != 0:
            logger.error('stop_server stop the service prometheus failed, reason %s' % output)
            return -1

    if not check_local_service("grafana-server", 3000):
        logger.warning("stop_server skips the step to stop grafana-server")
    else:
        ret_code, _ = exec_cmd('service grafana-server stop')
        if ret_code != 0:
            logger.error('stop_server stop the service grafana-server failed, reason %s' % output)
            return -1

    logger.info("stop_server succeeded")
    return 0

def start_server():
    logger.info("start_server")

    if check_local_service("prometheus", 9090):
        logger.warning("start_server skips the step to start prometheus")
    else:
        ret_code, _ = exec_cmd('service prometheus start')
        if ret_code != 0:
            logger.error('start_server start the service prometheus failed, reason %s' % output)
            return -1

    if check_local_service("grafana-server", 3000):
        logger.warning("start_server skips the step to start grafana-server")
    else:
        ret_code, _ = exec_cmd('service grafana-server start')
        if ret_code != 0:
            logger.error('start_server start the service grafana-server failed, reason %s' % output)
            return -1

    logger.info("start_server succeeded")
    return 0

def restart_server():
    logger.info("restart_server")
    stop_server()
    if 0 != start_server():
        logger.error("restart_server failed")
        return -1
    logger.info("restart_server succeeded")
    return 0

def print_usage():
    print "usage:\n"
    #new_actions = sorted(SUPPORTED_ACTIONS.items(), lambda x, y: cmp(x[0], y[0]))
    #for key, val in new_actions:
    for key, val in SUPPORTED_ACTIONS.iteritems():
        print "    %-20s    %s" % (key, val)
    print "\n"

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print_usage()
        exit(-1)

    action = sys.argv[1]
    if action not in SUPPORTED_ACTIONS.keys():
        print_usage()
        exit(-1)

    logger = init_logger(action, "/data/log")
    logger.info(sys.argv)

    ret = 0
    try:
        if action == "displayjobs":
            ret = disp_list()
        elif action == "addjob":
            job_cnf = get_json_params(sys.argv[2:])
            ret = add_job(job_cnf)
        elif action == "reset":
            ret = reset_admin()
        elif action == "modifyuser":
            user_cnf = get_json_params(sys.argv[2:])
            ret = modify_user(user_cnf)
        elif action == "dashboards":
            ret = disp_dashboard()
        elif action == "deljob":
            job_cnf = get_json_params(sys.argv[2:])
            ret = del_job(job_cnf)
        elif action == "healthcheck":
            ret, _ = health_check()
        elif action == "healthaction":
            ret = health_action()
        elif action == "start":
            ret = start_server()
        elif action == "stop":
            ret = stop_server()
        elif action == "restart":
            ret = restart_server()
        exit(ret)
    except Exception, e:
        logger.error("%s" % traceback.format_exc())
        exit(-1)