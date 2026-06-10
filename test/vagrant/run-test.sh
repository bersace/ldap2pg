#!/bin/bash
# Functional test of ldap2pg GSSAPI (native ldapsearch) against Samba AD.
# Run on the pg VM as any user: run-gssapi-test
set -eu

export LANG=C.UTF-8 LC_ALL=C.UTF-8
export LDAPURI=ldap://ldap.bridoulou.fr
export LDAPSASL_MECH=GSSAPI
export PGHOST=/var/run/postgresql
export PGUSER=ldap2pg
# The sample config manages database nominal only: connect to it.
export PGDATABASE=nominal
export NO_COLOR=1

PASS=0
FAIL=0

step() { echo ; echo "=== $* ===" ; }

check() {
	local label=$1 expected=$2 query=$3 got
	got=$(psql -AXtc "$query")
	if [ "$got" = "$expected" ] ; then
		echo "ok: $label"
		PASS=$((PASS + 1))
	else
		echo "FAIL: $label: got '$got', expected '$expected' [$query]"
		FAIL=$((FAIL + 1))
	fi
}

expect_rc() {
	local label=$1 expected=$2 ; shift 2
	local rc=0
	"$@" || rc=$?
	if [ "$rc" = "$expected" ] ; then
		echo "ok: $label (rc=$rc)"
		PASS=$((PASS + 1))
	else
		echo "FAIL: $label: rc=$rc, expected $expected"
		FAIL=$((FAIL + 1))
	fi
}

step "Kerberos ticket"
echo '1Ntegral' | kinit administrator@BRIDOULOU.FR
klist

step "Sanity: native ldapsearch with GSSAPI (sign+seal)"
ldapsearch -Y GSSAPI -H "$LDAPURI" -b cn=users,dc=bridoulou,dc=fr -LLL '(cn=readers)' cn member

step "Root cause of 'Strong Auth Required': GSSAPI without sign/seal is rejected"
out=$(ldapsearch -Y GSSAPI -O maxssf=0 -H "$LDAPURI" -b cn=users,dc=bridoulou,dc=fr -LLL '(cn=readers)' cn 2>&1) && rc=0 || rc=$?
echo "$out"
if [ "$rc" != 0 ] && echo "$out" | grep -qi 'strong\|seal' ; then
	echo "ok: server requires sign/seal, plain GSSAPI rejected as expected"
	PASS=$((PASS + 1))
else
	echo "FAIL: expected rejection of GSSAPI without sign/seal (rc=$rc)"
	FAIL=$((FAIL + 1))
fi

step "Informational: GSSAPI over ldaps:// (the reported failure scenario)"
LDAPTLS_REQCERT=allow ldapsearch -Y GSSAPI -H ldaps://ldap.bridoulou.fr \
	-b cn=users,dc=bridoulou,dc=fr -LLL '(cn=readers)' cn 2>&1 \
	&& echo "info: GSSAPI over ldaps:// accepted by this server" \
	|| echo "info: GSSAPI over ldaps:// rejected by this server (see above)"

cd /opt/ldap2pg-test

step "Dry run (nominal config)"
expect_rc "dry run exits 0" 0 ldap2pg -c ldap2pg.yml

step "Real run (edge config: folded DNs, UTF-8, sub-searches)"
expect_rc "edge real run exits 0" 0 ldap2pg -c ldap2pg-edge.yml --real
check "edge_fold1 exists" "1" "SELECT count(*) FROM pg_roles WHERE rolname = 'edge_fold1'"
check "edge_zoé-fold2 exists" "1" "SELECT count(*) FROM pg_roles WHERE rolname = 'edge_zoé-fold2'"
check "sam_fold1 exists" "1" "SELECT count(*) FROM pg_roles WHERE rolname = 'sam_fold1'"
check "sam_zoé-fold2 exists" "1" "SELECT count(*) FROM pg_roles WHERE rolname = 'sam_zoé-fold2'"
check "no corrupted edge roles" "4" "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'edge\\_%' OR rolname LIKE 'sam\\_%'"

step "Edge config is idempotent"
expect_rc "edge check exits 0" 0 ldap2pg -c ldap2pg-edge.yml --check

step "Real run (nominal config)"
expect_rc "nominal real run exits 0" 0 ldap2pg -c ldap2pg.yml --real

check "groups exist NOLOGIN" "3" "SELECT count(*) FROM pg_roles WHERE rolname IN ('readers', 'writers', 'owners') AND NOT rolcanlogin"
check "users exist LOGIN" "6" "SELECT count(*) FROM pg_roles WHERE rolname IN ('alain', 'corinne', 'alizée', 'charles', 'alter', 'Clothilde') AND rolcanlogin"
check "readers members" "alain,corinne" "SELECT string_agg(u.rolname, ',' ORDER BY u.rolname) FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles u ON u.oid = m.member WHERE g.rolname = 'readers' AND u.rolname <> 'writers'"
check "writers members" "alizée,charles" "SELECT string_agg(u.rolname, ',' ORDER BY u.rolname) FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles u ON u.oid = m.member WHERE g.rolname = 'writers' AND u.rolname <> 'owners'"
check "owners members" "Clothilde,alter" "SELECT string_agg(u.rolname, ',' ORDER BY u.rolname) FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles u ON u.oid = m.member WHERE g.rolname = 'owners'"
check "writers inherits readers" "1" "SELECT count(*) FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles u ON u.oid = m.member WHERE g.rolname = 'readers' AND u.rolname = 'writers'"
check "blacklisted postgres not member" "0" "SELECT count(*) FROM pg_auth_members m JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = 'postgres'"
check "daniel dropped" "0" "SELECT count(*) FROM pg_roles WHERE rolname = 'daniel'"
check "edge roles dropped by nominal run" "0" "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'edge\\_%' OR rolname LIKE 'sam\\_%'"
check "readers can select t1" "t" "SELECT has_table_privilege('readers', 'nominal.t1', 'SELECT')"
check "readers update revoked on t0" "f" "SELECT has_table_privilege('readers', 'nominal.t0', 'UPDATE')"

step "Nominal config is idempotent"
expect_rc "nominal check exits 0" 0 ldap2pg -c ldap2pg.yml --check

step "Without Kerberos ticket, ldap2pg fails cleanly"
kdestroy
rc=0
out=$(ldap2pg -c ldap2pg.yml 2>&1) || rc=$?
if [ "$rc" != 0 ] ; then
	echo "ok: exits non-zero without ticket (rc=$rc)"
	echo "$out" | tail -5
	PASS=$((PASS + 1))
else
	echo "FAIL: expected failure without Kerberos ticket"
	FAIL=$((FAIL + 1))
fi
echo '1Ntegral' | kinit administrator@BRIDOULOU.FR

echo
echo "=== RESULT: $PASS passed, $FAIL failed ==="
[ "$FAIL" = 0 ]
