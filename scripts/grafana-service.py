#!/usr/bin/env python
# -*- coding: utf-8 -*-
import base64
import collections
import json
import yaml
import sys
import os
import time
import traceback
import logging.handlers
import ruamel.yaml
import sqlite3
from configobj import ConfigObj
from ruamel.yaml.scalarstring import SingleQuotedScalarString
from filelock import FileLock
from utils import (
    init_logger,
    get_json_params,
    exec_cmd,
    check_local_service,
    read_file,
    wait_conf_file_ready,
    http_request,
    write_json_file,
    read_json_file
)

SUPPORTED_ACTIONS = {
    "displayjobs": "display the prometheus monitor job list",
    "addjob": "add job to the prometheus monitor job list",
    "deljob": "delete job from the prometheus monitor job list",
    "reset": "reset the grafana server's admin password",
    "dashboards": "display dashboard for download",
    "healthcheck": "check the service status",
    "healthaction": "take action if service check health failed",
    "start": "start prometheus and grafana-server",
    "stop": "stop prometheus and grafana-server",
    "restart": "restart prometheus and grafana-server",
    "updateparam": "update parameters",
    "startalertmanager": "start alertmanager",
    "stopalertmanager": "stop alertmanager"
}
PROMETHEUS_GLOBAL = ['scrape_interval', 'scrape_timeout', 'evaluation_interval']
PROMETHEUS_VARS = ['scrape_interval', 'scrape_timeout', 'metrics_path', 'scheme']
MONITOR_VERSION_FILE = "/etc/monitor/version"
MONITOR_CNF = "/etc/monitor/monitor.conf"
IP_FILE = "/etc/monitor/ip"
GRAFANA_CNF = "/opt/grafana/conf/grafana.ini"
PROMETHEUS_CNF = "/opt/prometheus/conf/prometheus.yml"
PROMETHEUS_SCRIPT = "/opt/prometheus/scripts/run_prometheus.sh"
DATASOURCE_FILE = "/opt/grafana/datasources/data_source.json"
LOCK_TIMEOUT = 300
GRAFANA_PWD = "/etc/monitor/grafana.pwd"


def load_params():
    ret = wait_conf_file_ready(MONITOR_CNF)
    if ret != 0:
        return None
    
    params = {}
    f = open(MONITOR_CNF, 'r')
    for line in open(MONITOR_CNF):
        line = f.readline()
        param = line.split("=")
        logger.info("param_split:%s",param)
        if len(param) != 2:
            continue
        
        key = param[0].strip()
        val = param[1].strip()

        if key[0] == '#':
            continue

        if key and val:
            params[key] = val

    rets = wait_conf_file_ready(IP_FILE)
    if rets != 0:
        return None
    ip = read_file(IP_FILE)
    if not ip:
        logger.error("load_params get ip failed")
        return None
    params["local_ip"] = ip
    
    logger.info("load params:%s",params)
    return params


def add_job(job_cnf,flock_path):
    logger.info("add_job")

    if not job_cnf:
        logger.error("add_job without config")
        return -1
    job_name = job_cnf.get("job_name", "").strip()
    ip = job_cnf.get("ip", "").strip()
    port = job_cnf.get("port", "")
    labelname = job_cnf.get("labelname", "").strip()
    labelvalue = job_cnf.get("labelvalue", "").strip()

    with FileLock(flock_path, LOCK_TIMEOUT, stealing=True) as locked:
        if not locked.is_locked:
            logger.error("add_job get lock failed")
            return -1
        with open(PROMETHEUS_CNF, "r") as docs:
            try:
                alldata = ruamel.yaml.round_trip_load(docs, preserve_quotes=True)
            except ruamel.yaml.YAMLError as exc:
                logger.error('add_job open prometheus.yml failed %s' % exc)
                return -1
        static_configs = {}
        labels = {}
        if labelname != "" and labelvalue != "":
            labels[labelname] = SingleQuotedScalarString(labelvalue)
            static_configs['labels'] = labels
        target = SingleQuotedScalarString(ip + ":" + str(port))
        static_configs['targets'] = [target]

        find = False
        if alldata['scrape_configs'] is not None:
            for i in alldata['scrape_configs']:
                if job_name == i['job_name']:
                    for j in i['static_configs']:
                        if j.has_key('labels') and labels != {} and j['labels'] == labels:
                            find = True
                            j['targets'].append(target)
                            j['targets'] = list(set(j['targets']))
                            break
                    if not find:
                        i['static_configs'].append(static_configs)
                        find = True
                    break
        else:
            alldata['scrape_configs'] = []
        if not find:
            scrape_configs = {}
            scrape_configs['static_configs'] = [static_configs]
            scrape_configs['job_name'] = SingleQuotedScalarString(job_name)
            for name in PROMETHEUS_VARS:
                param = job_cnf.get(name, "").strip()
                if param != "":
                    scrape_configs[name] = SingleQuotedScalarString(param)
            if job_cnf.get("honor_labels").lower() == 'true':
                scrape_configs['honor_labels'] = True
            alldata['scrape_configs'].append(scrape_configs)

        with open(PROMETHEUS_CNF, 'w+') as outfile:
            try:
                ruamel.yaml.round_trip_dump(alldata, outfile, default_flow_style=False, allow_unicode=True, indent=4, block_seq_indent=2)
            except ruamel.yaml.YAMLError as exc:
                logger.error('add_job write prometheus.yml failed %s' % exc)
                return -1

    url = '/-/reload'
    res, _ = http_request(params["local_ip"], int(params["prometheus_port"]), "POST", url, None, headers={})
    if res != 0:
        logger.error('add_job reload prometheus.yml failed')
        return -1
    logger.info("add_job succeeded")
    return 0


def del_job(job_cnf):
    logger.info("del_job")
    
    if not job_cnf:
        logger.error("del_job without config")
        return -1

    job_name = job_cnf.get("job_name","").strip()
    ip = job_cnf.get("ip", "").strip()
    port = job_cnf.get("port", "")
    target = ip + ":" + str(port)

    with FileLock(flock_path, LOCK_TIMEOUT, stealing=True) as locked:
        if not locked.is_locked:
            logger.error("add_job get lock failed")
            return -1
        with open(PROMETHEUS_CNF, "r") as docs:
            try:
                alldata = ruamel.yaml.round_trip_load(docs, preserve_quotes=True)
            except ruamel.yaml.YAMLError as exc:
                logger.error('add_job open prometheus.yml failed %s' % exc)
                return -1
        
        find = False
        for i in alldata['scrape_configs']:
            if job_name == i['job_name']:
                for j in i['static_configs']:
                    for k in j['targets']:
                        if k == target:
                            find = True
                            if len(j['targets']) == 1:
                                if len(i['static_configs']) == 1:
                                    alldata['scrape_configs'].remove(i)
                                else:
                                    i['static_configs'].remove(j)
                            else:
                                j['targets'].remove(k)
                            break
                    if find:
                        break
                break
        
        if not find:
            logger.error('del_job failed, cannot find job_name:%s, target:%s', job_name, target)
            return -1

        if len(alldata['scrape_configs']) == 0:
            alldata['scrape_configs'] = None
        with open(PROMETHEUS_CNF, 'w+') as outfile:
            try:
                ruamel.yaml.round_trip_dump(alldata, outfile, default_flow_style=False, allow_unicode=True, indent=4, block_seq_indent=2)
            except ruamel.yaml.YAMLError as exc:
                logger.error('del_job write prometheus.yml failed %s' % exc)
                return -1

    url = '/-/reload'
    res, _ = http_request(params["local_ip"], int(params["prometheus_port"]), "POST", url, None, headers={})
    if res != 0:
        logger.error('del_job reload prometheus.yml failed')
        return -1

    logger.info("del_job succeeded")
    return 0


def reset_admin(params, passwd):
    logger.info("reset_admin.")

    if not passwd:
        logger.error("modify_user without config")
        return -1
    newpasswd = passwd.get("newpasswd", "").strip()
    if not newpasswd:
        logger.error("modify_user get newpasswd [%s] failed" % newpasswd)
        return -1

    cmd = "/opt/grafana/bin/grafana-cli %s reset-admin-password --homepath '/opt/grafana' --config '%s' %s" % (params["admin_user"], GRAFANA_CNF, newpasswd)
    ret_code, _ = exec_cmd(cmd)
    if ret_code != 0:
        logger.error('reset_admin failed')
        return -1

    pwd = "%s" % newpasswd
    auth = base64.b64encode(params["admin_user"]+ ':'+ pwd) 
    headers = {"Content-Type": "application/json",
            "Authorization": "Basic " + auth}
    res = write_json_file(GRAFANA_PWD, headers)
    if res != 0:
        logger.info("reset_admin failed")
        return -1

    logger.info("reset_admin succeeded.")
    return 0


def disp_list(params):
    logger.info("disp_list")

    url = '/api/v1/targets'
    headers = {"Content-Type": "application/json"}
    res, data = http_request(params["local_ip"], int(params["prometheus_port"]), "GET", url, None, headers)
    if res != 0:
        logger.error("disp_list fail")
        return -1

    body = json.loads(data)

    l = []
    for i in body['data']['activeTargets']:
        job_name = i['labels']['job']
        scrapeUrl = i['scrapeUrl']
        instance = i['labels']['instance']
        health = i['health']
        group = ""
        if i['labels'].has_key('group'):
            group = i['labels']['group']
        l.append([job_name, scrapeUrl, instance, health, group])

    ret_cnf = {
        "labels": ["job_name", "scrapeUrl", "instance", "health", "group"],
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


def health_check(params):
    logger.info("health_check")
    bflag = False
    if not check_local_service("prometheus", params["prometheus_port"]):
        logger.error('check prometheus process failed')
        bflag = True

    if not check_local_service("grafana-server", params["grafana_port"]):
        logger.error('check grafana-server process failed')
        if bflag:
            return -3, "prometheus and grafana-server are not running"
        return -2, "grafana-server is not running"

    if bflag:
        return -1, "prometheus is not running"

    logger.info("health_check succeeded")
    return 0,""


def health_action(params):
    logger.info("health_action")
    ret = health_check(params)

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


def stop_server(params):
    logger.info("stop_server")

    if not check_local_service("prometheus", params["prometheus_port"]):
        logger.warning("stop_server skips the step to stop prometheus")
    else:
        ret_code, output = exec_cmd('service prometheus stop')
        if ret_code != 0:
            logger.error('stop_server stop the service prometheus failed, reason %s' % output)
            return -1

    if not check_local_service("grafana-server", params["grafana_port"]):
        logger.warning("stop_server skips the step to stop grafana-server")
    else:
        ret_code, output = exec_cmd('service grafana-server stop')
        if ret_code != 0:
            logger.error('stop_server stop the service grafana-server failed, reason %s' % output)
            return -1

    logger.info("stop_server succeeded")
    return 0


def start_server(params, flock_path):
    logger.info("start_server")

    if check_local_service("prometheus", params["prometheus_port"]):
        logger.warning("start_server skips the step to start prometheus")
    else:
        generate_script(params, flock_path)
        ret_code, output = exec_cmd('service prometheus start')
        if ret_code != 0:
            logger.error('start_server start the service prometheus failed, reason %s' % output)
            return -1

    if check_local_service("grafana-server", params["grafana_port"]):
        logger.warning("start_server skips the step to start grafana-server")
    else:
        generate_cnf(params, flock_path)
        ret_code, output = exec_cmd('service grafana-server start')
        if ret_code != 0:
            logger.error('start_server start the service grafana-server failed, reason %s' % output)
            return -1
    time.sleep(3)
    res = import_datasources(params)
    if res != 0:
        logger.error('start_server fail')
        return -1
    logger.info("start_server succeeded")
    return 0


def restart_server(params, flock_path):
    logger.info("restart_server")
    stop_server(params)
    if 0 != start_server(params, flock_path):
        logger.error("restart_server failed")
        return -1
    logger.info("restart_server succeeded")
    return 0


def update_params(params, flock_path):
    logger.info("update_params")

    if not check_local_service("grafana-server", params["grafana_port"]):
        logger.info("update_params grafana-server need update")
        result = generate_cnf(params, flock_path)
        if result != 0:
            logger.error('update_params failed')
            return -1
        ret_code, _ = exec_cmd('service grafana-server restart')
        if ret_code != 0:
            logger.error('update_params restart service grafana-server failed')
            return -1
        time.sleep(3)
        
    change = 0
    with FileLock(flock_path, LOCK_TIMEOUT, stealing=True) as locked:
        if not locked.is_locked:
            logger.error("update_params get lock failed")
            return -1
        with open(PROMETHEUS_CNF, "r") as docs:
            try:
                alldata = ruamel.yaml.round_trip_load(docs, preserve_quotes=True)
            except ruamel.yaml.YAMLError as exc:
                logger.error('update_params open prometheus.yml failed %s' % exc)
                return -1
    
        for name in PROMETHEUS_GLOBAL:
            if is_prometheus_global_var_diff(params, alldata['global'], name):
                change = 1
        external_labels = {}
        if params.has_key('external_labelname') and params.has_key('external_labelvalue'):
            external_labels[params['external_labelname']] = SingleQuotedScalarString(params['external_labelvalue'])
        else:
            external_labels = None
        if alldata['global']['external_labels'] != external_labels:
            alldata['global']['external_labels'] = external_labels
            change = 1
        if change == 1:
            logger.info("update_params need update prometheus.yml")
            with open(PROMETHEUS_CNF, 'w+') as outfile:
                try:
                    ruamel.yaml.round_trip_dump(alldata, outfile, default_flow_style=False, allow_unicode=True, indent=4, block_seq_indent=2)
                except ruamel.yaml.YAMLError as exc:
                    logger.error('update_params write prometheus.yml failed %s' % exc)
                    return -1

    if not os.path.exists(PROMETHEUS_SCRIPT):
        change = 3
    else:
        last_line = open(PROMETHEUS_SCRIPT).readlines()[-1]
        if last_line != '    --storage.tsdb.retention="%s"' % params["tsdb_retention"]:
            change = 2
        if not check_local_service("prometheus", params["prometheus_port"]):
            change = 3
    
    if change == 0:
        logger.info("update_params prometheus neednot update")
        return 0
    if change == 1:
        url = '/-/reload'
        res_node, _ = http_request(params["local_ip"], int(params["prometheus_port"]), "POST", url, None, headers={})
        if res_node != 0:
            logger.error('update_params reload prometheus.yml failed')
            return -1
        logger.info("update_params reload prometheus config succeeded")
        return 0
    if change == 3:
        logger.info("update_params need update datasources")
        res = update_datasources(params)
        if res != 0:
            logger.error('update_params update_datasources failed')
            return -1

    logger.info("update_params need update run_prometheus.sh")
    generate_script(params, flock_path)
    ret_code, _ = exec_cmd('service prometheus restart')
    if ret_code != 0:
        logger.error('update_params restart service prometheus failed')
        return -1
    logger.info("update_params succeeded")
    return 0


def is_prometheus_global_var_diff(params, vars, name):
    if vars[name] == params[name]:
        return False
    else:
        vars[name] = params[name]
        return True

def generate_cnf(params, flock_path):
    logger.info("generate_cnf")
    with FileLock(flock_path, LOCK_TIMEOUT, stealing=True) as locked:
        if not locked.is_locked:
            logger.error("generate_cnf get lock failed")
            return -1
        if not os.path.exists(GRAFANA_CNF):
            logger.error("generate_cnf get grafana.ini failed")
            return -1
        config = ConfigObj(GRAFANA_CNF)
        config['server']['http_port']=params["grafana_port"]
        if config['server']['domain']=="":
            pwd = "%s" % params["admin_password"]
            auth = base64.b64encode(params["admin_user"]+ ':'+ pwd) 
            headers = {"Content-Type": "application/json",
                    "Authorization": "Basic " + auth}
            res = write_json_file(GRAFANA_PWD, headers)
            if res != 0:
                logger.info("generate_cnf failed")
                return -1
            config['server']['domain']=params["local_ip"]
            config['security']['admin_user']=params["admin_user"]
            config['security']['admin_password']=params["admin_password"]
        config.write()
    logger.info("generate_cnf succeeded")
    return 0


def generate_script(params, flock_path):
    logger.info("generate_script")
    with FileLock(flock_path, LOCK_TIMEOUT, stealing=True) as locked:
        if not locked.is_locked:
            logger.error("generate_script get lock failed")
            return -1
        run_text = '''#!/bin/bash
set -e

cd /opt/prometheus || exit 1
exec > >(tee -i -a "/data/prometheus/log/prometheus.log")
exec 2>&1

exec bin/prometheus \\
    --config.file="%s" \\
    --web.listen-address=":%s" \\
    --web.external-url="http://%s:%s/" \\
    --web.enable-admin-api \\
    --web.enable-lifecycle \\
    --log.level="info" \\
    --storage.tsdb.path="/data/prometheus/data" \\
    --storage.tsdb.retention="%s"''' % (PROMETHEUS_CNF, params["prometheus_port"], params["local_ip"], params["prometheus_port"], params["tsdb_retention"])

        f = open(PROMETHEUS_SCRIPT, 'w')
        f.write(run_text)
        f.close()
        exec_cmd('chmod +x %s' % PROMETHEUS_SCRIPT)
    logger.info("generate_script succeeded")
    return 0


def import_datasources(params):
    logger.info("import_datasources")

    url1 = '/api/datasources/id/Prometheus'
    headers = read_json_file(GRAFANA_PWD)
    if not headers:
        logger.error("import_datasources failed")
        return -1
    res1, _ = http_request(params["local_ip"], int(params["grafana_port"]), "GET", url1, None, headers)
    if res1 == 0:
        logger.info("neednot import_datasources")
        return 0

    url = '/api/datasources'
    body = {
        "name":"Prometheus",
        "type":"prometheus",
        "access":"proxy",
        "url":"http://%s:%s/" % (params["local_ip"], params["prometheus_port"]),
        "basicAuth": False
    }
    res2, _ = http_request(params["local_ip"], int(params["grafana_port"]), "POST", url, json.dumps(body), headers)
    if res2 != 0:
        logger.error("import_datasources fail")
        return -1

    logger.info("import_datasources succeeded")
    return 0


def update_datasources(params):
    logger.info("update_datasources")

    url1 = '/api/datasources/Prometheus'
    headers = read_json_file(GRAFANA_PWD)
    if not headers:
        logger.error("update_datasources failed")
        return -1
    res1, strs = http_request(params["local_ip"], int(params["grafana_port"]), "GET", url1, None, headers)

    if res1 == 0:
        body = json.loads(strs)
        body['url'] = "http://%s:%s/" % (params["local_ip"], params["prometheus_port"])
        url = '/api/datasources/%d' % body['id']
        method = "PUT"
    else:
        url = '/api/datasources'
        body = {
            "name":"Prometheus",
            "type":"prometheus",
            "access":"proxy",
            "url":"http://%s:%s/" % (params["local_ip"], params["prometheus_port"]),
            "basicAuth": False
        }
        method = "POST"
    res2, _ = http_request(params["local_ip"], int(params["grafana_port"]), method, url, json.dumps(body), headers)
    if res2 != 0:
        logger.error("update_datasources fail")
        return -1

    logger.info("update_datasources succeeded")
    return 0

def start_alertmanager():
    logger.info("start_alertmanager")

    if check_local_service("alertmanager", 9093):
        logger.warning("start_alertmanager skipped")
    else:
        ret_code, output = exec_cmd('service alertmanager start')
        if ret_code != 0:
            logger.error('start_alertmanager failed, reason %s' % output)
            return -1
    logger.info("start_alertmanager succeeded")
    return 0

def stop_alertmanager():
    logger.info("stop_alertmanager")

    if check_local_service("alertmanager", 9093):
        ret_code, output = exec_cmd('service alertmanager stop')
        if ret_code != 0:
            logger.error('stop_alertmanager failed, reason %s' % output)
            return -1
    logger.info("stop_alertmanager succeeded")
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

    version = read_file(MONITOR_VERSION_FILE)
    if not version:
        logger.error("read_version failed")
        exit(-1)
    flock_path = "/tmp/%s" %version
    params = load_params()

    ret = 0
    try:
        if action == "displayjobs":
            ret = disp_list(params)
        elif action == "addjob":
            job_cnf = get_json_params(sys.argv[2:])
            ret = add_job(job_cnf,flock_path)
        elif action == "reset":
            passwd = get_json_params(sys.argv[2:])
            ret = reset_admin(params, passwd)
        elif action == "dashboards":
            ret = disp_dashboard()
        elif action == "deljob":
            job_cnf = get_json_params(sys.argv[2:])
            ret = del_job(job_cnf)
        elif action == "healthcheck":
            ret, _ = health_check(params)
        elif action == "healthaction":
            ret = health_action(params)
        elif action == "start":
            ret = start_server(params, flock_path)
        elif action == "stop":
            ret = stop_server(params)
        elif action == "restart":
            ret = restart_server(params, flock_path)
        elif action == "updateparam":
            ret = update_params(params, flock_path)
        elif action == "startalertmanager":
            ret = start_alertmanager()
        elif action == "stopalertmanager":
            ret = stop_alertmanager()
        exit(ret)
    except Exception, e:
        logger.error("%s" % traceback.format_exc())
        exit(-1)