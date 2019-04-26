#!/bin/bash

apt-get update
apt-get install -y python3.7 python3-venv python3-pip bpfcc-tools linux-headers-$(uname -r) python3-bpfcc docker.io

pip3 install pipenv docker-compose
cd /project
pipenv --python 3.7
pipenv install

cp  -r /usr/lib/python3/dist-packages/bcc/ $(pipenv --venv)/lib/python3.7/

docker pull prom/prometheus
docker pull grafana/grafana

mkdir -p storage/grafana
touch storage/grafana/grafana.db
chmod -R 0777 storage
