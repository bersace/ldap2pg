package privilege

import (
	_ "embed"
)

var (
	Builtins map[string]Privilege
	//go:embed sql/database.sql
	inspectDatabase string
	//go:embed sql/global-default.sql
	inspectGlobalDefault string
	//go:embed sql/schema-default.sql
	inspectSchemaDefault string
	//go:embed sql/language.sql
	inspectLanguage string
	//go:embed sql/schema.sql
	inspectSchema string
	//go:embed sql/all-tables.sql
	inspectAllTables string
	//go:embed sql/all-sequences.sql
	inspectAllSequences string
	//go:embed sql/all-functions.sql
	inspectAllFunctions string
)

func init() {
	Builtins = make(map[string]Privilege)

	register("instance", "DATABASE", inspectDatabase)
	register("instance", "LANGUAGE", inspectLanguage)

	register("database", "SCHEMA", inspectSchema)
	register(
		"database", "GLOBAL DEFAULT", inspectGlobalDefault,
		`ALTER DEFAULT PRIVILEGES FOR ROLE %%s GRANT %s ON %s TO %%s;`,
		`ALTER DEFAULT PRIVILEGES FOR ROLE %%s REVOKE %s ON %s FROM %%s;`,
	)
	register(
		"schema", "SCHEMA DEFAULT", inspectSchemaDefault,
		`ALTER DEFAULT PRIVILEGES FOR ROLE %%s IN SCHEMA %%s GRANT %s ON %s TO %%s;`,
		`ALTER DEFAULT PRIVILEGES FOR ROLE %%s IN SCHEMA %%s REVOKE %s ON %s FROM %%s;`,
	)
	register("schema", "ALL TABLES IN SCHEMA", inspectAllTables)
	register("schema", "ALL SEQUENCES IN SCHEMA", inspectAllSequences)
	register("schema", "ALL FUNCTIONS IN SCHEMA", inspectAllFunctions)
}

// queries are grant and revoke queries in order.
func register(scope, object, inspect string, queries ...string) {
	var grant, revoke string

	if 0 < len(queries) {
		grant = queries[0]
		queries = queries[1:]
	} else {
		grant = `GRANT %s ON ` + object + ` %%s TO %%s;`
	}

	if 0 < len(queries) {
		revoke = queries[0]
		queries = queries[1:]
	} else {
		revoke = `REVOKE %s ON ` + object + ` %%s FROM %%s;`
	}

	if 0 < len(queries) {
		panic("too many queries")
	}

	Builtins[object] = Privilege{
		Scope:   scope,
		Object:  object,
		Inspect: inspect,
		Grant:   grant,
		Revoke:  revoke,
	}
}
