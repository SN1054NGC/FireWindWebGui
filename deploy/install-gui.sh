#!/bin/bash
# Установка GUI-панели поверх AntiZapret (Ubuntu 22.04/24.04, Debian 11/12)
set -e
export DEBIAN_FRONTEND=noninteractive
D=$(cd "$(dirname "$0")" && pwd)
R=$(cd "$D/.." && pwd)

apt-get install -y -qq python3-venv python3-pip qrencode nginx >/dev/null

install -d /opt/vds-panel
cp -f "$R/gui/app.py" "$R/gui/vpn.py" "$R/gui/schema.sql" "$R/gui/requirements.txt" /opt/vds-panel/
cd /opt/vds-panel
[ -d venv ] || python3 -m venv venv
./venv/bin/pip install -q -r requirements.txt

if [ ! -f /etc/vds-panel.env ]; then
  cp -f "$R/.env.example" /etc/vds-panel.env
  sed -i "s|^VDS_SECRET=.*|VDS_SECRET=$(openssl rand -hex 32)|" /etc/vds-panel.env
  sed -i "s|^VDS_GUEST_PASS=.*|VDS_GUEST_PASS=$(openssl rand -base64 12 | tr -dc 'A-Za-z0-9' | cut -c1-12)|" /etc/vds-panel.env
  chmod 600 /etc/vds-panel.env
fi

cp -f "$D/vds-panel.service" /etc/systemd/system/vds-panel.service
systemctl daemon-reload
systemctl enable --now vds-panel >/dev/null 2>&1 || systemctl restart vds-panel
sleep 2
systemctl is-active vds-panel
echo "Готово. Панель: http://127.0.0.1:8010  (первый вход admin / admin)"