#!/bin/bash
# Diagnostic: probe what the Samba server requires and how the gokrb5-native
# ldap2pg binary behaves. Run on the pg VM.
export LANG=C.UTF-8 LC_ALL=C.UTF-8
export PGHOST=/var/run/postgresql PGUSER=ldap2pg PGDATABASE=nominal NO_COLOR=1
export LDAPSASL_MECH=GSSAPI

echo '1Ntegral' | kinit administrator@BRIDOULOU.FR
klist

echo; echo "### A. native ldapsearch ldap:// default (sign/seal) ###"
ldapsearch -Y GSSAPI -H ldap://ldap.bridoulou.fr -b cn=users,dc=bridoulou,dc=fr -LLL '(cn=readers)' cn 2>&1 | head -8

echo; echo "### B. native ldapsearch ldap:// -O maxssf=0 (no layer) ###"
ldapsearch -Y GSSAPI -O maxssf=0 -H ldap://ldap.bridoulou.fr -b cn=users,dc=bridoulou,dc=fr -LLL '(cn=readers)' cn 2>&1 | head -8

echo; echo "### C. native ldapsearch ldap:// -O minssf=1,maxssf=1 (integrity only) ###"
ldapsearch -Y GSSAPI -O minssf=1,maxssf=1 -H ldap://ldap.bridoulou.fr -b cn=users,dc=bridoulou,dc=fr -LLL '(cn=readers)' cn 2>&1 | head -8

echo; echo "### D. native ldapsearch ldaps:// default ###"
LDAPTLS_REQCERT=allow ldapsearch -Y GSSAPI -H ldaps://ldap.bridoulou.fr -b cn=users,dc=bridoulou,dc=fr -LLL '(cn=readers)' cn 2>&1 | head -8

echo; echo "### E. native ldapsearch ldaps:// -O maxssf=0 ###"
LDAPTLS_REQCERT=allow ldapsearch -Y GSSAPI -O maxssf=0 -H ldaps://ldap.bridoulou.fr -b cn=users,dc=bridoulou,dc=fr -LLL '(cn=readers)' cn 2>&1 | head -8

echo; echo "### F. gokrb5-native ldap2pg over ldap:// (dry run) ###"
cd /opt/ldap2pg-test
LDAPURI=ldap://ldap.bridoulou.fr /tmp/ldap2pg.new -c ldap2pg.yml --verbose 2>&1 | grep -iv 'level=DEBUG msg="Loading LDAP' | head -40

echo; echo "### G. gokrb5-native ldap2pg over ldaps:// (dry run) ###"
LDAPURI=ldaps://ldap.bridoulou.fr LDAPTLS_REQCERT=allow /tmp/ldap2pg.new -c ldap2pg.yml --verbose 2>&1 | tail -25
