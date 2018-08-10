#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import yaml
import sys
import os
import traceback
import logging.handlers
import sqlite3
import requests

SUPPORTED_ACTIONS = {
    "displayjobs": "display the prometheus monitor job list",
    "addjob": "add job to the prometheus monitor job list",
    "reset": "reset the grafana server's admin password to default(admin)",
    "modifyuser": "modify the admin's password",
    "dashboards": "display dashboard for download"
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
    logger.info("add_job_prometheus_job_list")

    if not job_cnf:
        logger.error("add_job without config")
        return -1

    job_name = job_cnf.get("job_name", "").strip()
    targets = job_cnf.get("targets", "").strip()
    if not job_name:
        logger.error("add_job get job_name [%s] failed" % job_name)
        return -1
    if not targets:
        logger.error("add_job get targets [%s] failed" % targets)
        return -1

    fd = open('/opt/prometheus/prometheus.yml', 'a')
    l = []
    l.append("  - job_name: '" + job_name + "'\n")
    l.append("    static_configs:\n")
    l.append("    - targets: ['" + targets + "']\n")
    fd.writelines(l)
    fd.close()

    logger.info("add_job succeeded")
    return 0

def modify_user(user_cnf):
    logger.info("modify_grafana_user_password")

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
        logger.error("please makesure the password is same!")
        return -1

    try:
        url = 'http://localhost:3000/api/user/password'
        body = {
            "oldPassword": oldpasswd,
            "newPassword": newpasswd,
            "confirmNew": confirmnew
        }
        res = requests.put(url, json=body, headers={"Content-Type": "application/json"}, auth=('admin', 'admin'))
        if res.status_code != 200:
            logger.error("http request failed, status [%d], reason [%s], data [%s]"
                         % (res.status_code, res.reason, res.text))
            return -1

        logger.info("http request succeeded, status [%d], reason [%s], data [%s]"
                     % (res.status_code, res.reason, res.text))
        return 0
    except:
        err_msg = traceback.format_exc()
        logger.error(err_msg)
        logger.error("http_request failed")
        return -1

def reset_admin():
    logger.info("reset_grafana_admin_password")

    conn = sqlite3.connect("/var/lib/grafana/grafana.db")
    conn.execute("update user set password = '59acf18b94d7eb0694c61e60ce44c110c7a683ac6a8f09580d626f90f4a242000746579358d77dd9e570e83fa24faa88a8a6', salt = 'F3FAxVm33R' where login = 'admin'")
    conn.commit()
    conn.close()

    logger.info("reset_admin succeeded")
    return 0

def disp_list():
    logger.info("display_prometheus_job_list")

    fd = open('/opt/prometheus/prometheus.yml', 'r')
    dict_tmp = yaml.load(fd)
    fd.close()

    l = []
    for i in dict_tmp['scrape_configs']:
        job_name = i['job_name']
        for j in i['static_configs']:
            for k in j['targets']:
                l.append([job_name,k])

    ret_cnf = {
        "labels": ["job_name", "targets"],
        "data": l
    }
    print json.dumps(ret_cnf)

    logger.info("display_prometheus_job_list succeeded")
    return 0

def disp_dashboard():
    logger.info("display_dashboard_for_download")

    l = []
    ftppath = '/srv/ftp'
    fileList = os.listdir(ftppath)
    for fileName in fileList:
        if 'json' in fileName:
            l.append(fileName)
    ret_cnf = {
        "labels": ["fileName"],
        "data": l
    }
    print json.dumps(ret_cnf)
    
    logger.info("display_dashboard_for_download succeeded")
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
        exit(ret)
    except Exception, e:
        logger.error("%s" % traceback.format_exc())
        exit(-1)
