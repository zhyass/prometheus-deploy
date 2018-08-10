#!/bin/bash
# check if server port is ready
g_port_status=$(netstat -tulpen | grep 3000)
p_port_status=$(netstat -tulpen | grep 9090)
#echo $g_port_status
if [ "$g_port_status" != "" ]
then
    g_portReady=true
else
    g_portReady=false
fi
#echo $p_port_status
if [ "$p_port_status" != "" ]
then
    p_portReady=true
else
    p_portReady=false
fi

#echo $portReady
# check if grafana process is running
g_process_status=$(ps -ef | grep -v grep | grep 'grafana')
#echo $g_process_status
if [ "$g_process_status" != "" ]
then
    g_pidReady=true
else
    g_pidReady=false
fi
# check if prometheus process is running
p_process_status=$(ps -ef | grep -v grep | grep 'prometheus')
#echo $p_process_status
if [ "$p_process_status" != "" ]
then
    p_pidReady=true
else
    p_pidReady=false
fi
#echo $pidReady

#0 OK;1 prometheus err;2 grafana err;3 both err
if [ $g_portReady == "true" ]&&[ $g_pidReady == "true" ]&&[ $p_portReady == "true" ]&&[ $p_pidReady == "true" ]
then
    exit 0
elif [ $g_portReady == "true" ]&&[ $g_pidReady == "true" ]
then
    exit 1
elif [ $p_portReady == "true" ]&&[ $p_pidReady == "true" ]
then
    exit 2
else
    exit 3
fi
