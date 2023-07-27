# Test order matters.

from __future__ import unicode_literals

import pytest


def test_dry_run(ldap2pg, psql):
    ldap2pg('--verbose', config='ldap2pg.yml')
    roles = list(psql.roles())
    superusers = list(psql.superusers())
    # oscar is not dropped
    assert 'oscar' in roles
    assert 'ALICE' in superusers


def test_check_mode(ldap2pg, psql):
    ldap2pg('--check', config='ldap2pg.yml', _ok_code=1)


def test_real_mode(ldap2pg, psql):
    assert 'keepme' in psql.tables(dbname='olddb')

    ldap2pg('--real', c='ldap2pg.yml')
    # Workaround bug in Postgres: execute on functions to public persists
    # revoke.
    ldap2pg('--real', c='ldap2pg.yml')

    roles = list(psql.roles())
    writers = list(psql.members('writers'))

    assert 'Alan' in roles
    assert 'oscar' not in roles

    assert 'ALICE' in psql.superusers()

    assert 'daniel' in writers
    assert 'david' in writers
    assert 'didier' in writers
    assert 'ALICE' in psql.members('ldap_roles')

    # Assert that table keepme owned by deleted user spurious is not dropped!
    assert 'keepme' in psql.tables(dbname='olddb')
    assert 'keepme' in roles


def test_re_grant(ldap2pg, psql):
    # Ensure db is sync
    ldap2pg('--check', c='ldap2pg.yml')
    # Revoke on one table. This must trigger a re-GRANT
    psql(d='appdb', c='REVOKE SELECT ON appns.table2 FROM readers;')
    # Ensure database is not sync.
    ldap2pg('--check', c='ldap2pg.yml', _ok_code=1)
    # Synchronize all
    ldap2pg('--real', c='ldap2pg.yml')
    ldap2pg('--check', c='ldap2pg.yml')


def test_re_revoke(ldap2pg, psql):
    c = 'ldap2pg.yml'

    # Ensure db is sync
    ldap2pg('--check', c=c)
    # Partial GRANT to oscar. This must trigger a re-REVOKE
    psql(d='appdb', c='GRANT INSERT ON appns.table1 TO readers;')
    # Ensure database is not sync.
    ldap2pg('--check', c=c, _ok_code=1)
    # Synchronize all
    ldap2pg('--real', c=c)
    ldap2pg('--check', c=c)


def test_nothing_to_do(ldap2pg, capsys):
    ldap2pg('--real', config='ldap2pg.yml')

    _, err = capsys.readouterr()
    assert 'Nothing to do' in err
