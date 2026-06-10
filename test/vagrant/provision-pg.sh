#!/bin/bash
# Provision PostgreSQL + Kerberos client + native ldapsearch + ldap2pg.
set -eux

export DEBIAN_FRONTEND=noninteractive
export LANG=C.UTF-8 LC_ALL=C.UTF-8

LDAP_IP=192.168.56.10

sed -i '/127\.0\.1\.1/d' /etc/hosts
grep -q 'ldap.bridoulou.fr' /etc/hosts || echo "$LDAP_IP ldap.bridoulou.fr ldap" >> /etc/hosts

echo "krb5-config krb5-config/default_realm string BRIDOULOU.FR" | debconf-set-selections

apt-get update
apt-get install -y postgresql krb5-user ldap-utils libsasl2-modules-gssapi-mit

cat > /etc/krb5.conf <<'EOF'
[libdefaults]
	default_realm = BRIDOULOU.FR
	dns_lookup_realm = false
	dns_lookup_kdc = false
	rdns = false
	dns_canonicalize_hostname = false

[realms]
	BRIDOULOU.FR = {
		kdc = ldap.bridoulou.fr
		admin_server = ldap.bridoulou.fr
	}

[domain_realm]
	.bridoulou.fr = BRIDOULOU.FR
	bridoulou.fr = BRIDOULOU.FR
EOF

mkdir -p /etc/ldap
cat > /etc/ldap/ldap.conf <<'EOF'
BASE dc=bridoulou,dc=fr
URI ldap://ldap.bridoulou.fr
REFERRALS off
NETWORK_TIMEOUT 5
TIMEOUT 10
EOF

# Trust auth locally, like the docker-compose dev environment.
PGVER=$(ls /etc/postgresql | head -1)
HBA="/etc/postgresql/${PGVER}/main/pg_hba.conf"
[ -f "${HBA}.orig" ] || cp "$HBA" "${HBA}.orig"
cat > "$HBA" <<'EOF'
local   all   all                 trust
host    all   all   127.0.0.1/32  trust
host    all   all   ::1/128       trust
EOF
systemctl restart postgresql

# Load the same postgres fixtures as docker-compose (previous state to sync).
sed -i 's/\r$//' /tmp/fixtures/*.sh /tmp/run-test.sh /tmp/ldap2pg.yml /tmp/ldap2pg-edge.yml
export PGHOST=/var/run/postgresql
bash /tmp/fixtures/reset.sh
bash /tmp/fixtures/nominal.sh

install -m 755 /tmp/ldap2pg.bin /usr/local/bin/ldap2pg
mkdir -p /opt/ldap2pg-test
install -m 644 /tmp/ldap2pg.yml /opt/ldap2pg-test/ldap2pg.yml
install -m 644 /tmp/ldap2pg-edge.yml /opt/ldap2pg-test/ldap2pg-edge.yml
install -m 755 /tmp/run-test.sh /usr/local/bin/run-gssapi-test

ldap2pg --version

echo "PostgreSQL + ldap2pg provisioned. Run: run-gssapi-test"
