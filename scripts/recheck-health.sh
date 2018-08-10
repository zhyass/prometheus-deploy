#! /bin/bash
/opt/prometheus/scripts/serverStatus.sh
#echo $?
serverStatus=$?
if [ $serverStatus == "1" ]
then
  #echo "grafana is running"
  service prometheus start
elif [ $serverStatus == "2" ]
then
  #echo "prometheus is running"
  service grafana-server start
else
  #echo "server is down"
  service prometheus restart
  service grafana-server restart
fi
