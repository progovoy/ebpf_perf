#!/bin/bash

CUR_DIR="$( cd "$(dirname "$0")" ; pwd -P )"

echo "Running: docker rm prometheus
docker run --name prometheus -d --network host -v \
${CUR_DIR}/../config/prometheus.yml:/etc/prometheus/prometheus.yml \
prom/prometheus" 
docker rm -f prometheus
docker run --name prometheus -d --network host -v \
${CUR_DIR}/../config/prometheus.yml:/etc/prometheus/prometheus.yml \
prom/prometheus

echo "Running: docker rm grafana
mkdir /tmp/storage
chmod -R 0777 /tmp/storage
docker run --network host -d --name grafana -v \
${CUR_DIR}/../config/grafana.ini:/etc/grafana/grafana.ini -v \
/tmp/storage:/var/lib/grafana grafana/grafana"
docker rm -f grafana
sudo mkdir /tmp/storage
sudo chmod -R 0777 /tmp/storage
docker run --network host -d --name grafana -v \
${CUR_DIR}/../config/grafana.ini:/etc/grafana/grafana.ini -v \
/tmp/storage:/var/lib/grafana grafana/grafana
