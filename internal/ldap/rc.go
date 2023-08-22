// Implements ldap.conf(5)
package ldap

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/exp/slog"
)

var knownOptions = []string{
	"BASE",
	"BINDDN",
	"PASSWORD", // ldap2pg extension.
	"REFERRALS",
	"SASL_AUTHCID",
	"SASL_AUTHZID",
	"SASL_MECH",
	"TIMEOUT",
	"TLS_REQCERT",
	"NETWORK_TIMEOUT",
	"URI",
}

// Holds options with their raw value from either file of env. Marshaling is
// done on demand by getters.
type OptionsMap map[string]RawOption

type RawOption struct {
	Key    string
	Value  string
	Origin string
}

func Initialize() (options OptionsMap, err error) {
	_, ok := os.LookupEnv("LDAPNOINIT")
	if ok {
		slog.Debug("Skip LDAP initialization.")
		return
	}
	path := "/etc/ldap/ldap.conf"
	home, _ := os.UserHomeDir()
	options = make(OptionsMap)
	options.LoadDefaults()
	err = options.LoadFiles(
		path,
		filepath.Join(home, "ldaprc"),
		filepath.Join(home, ".ldaprc"),
		"ldaprc",
	)
	if err != nil {
		return
	}
	path = os.Getenv("LDAPCONF")
	if "" != path {
		err = options.LoadFiles(path)
		if err != nil {
			return
		}
	}
	path = os.Getenv("LDAPRC")
	if "" != path {
		err = options.LoadFiles(
			filepath.Join(home, path),
			fmt.Sprintf("%s/.%s", home, path),
			"./"+path,
		)
	}
	options.LoadEnv()
	return
}

func (m OptionsMap) GetSeconds(name string) time.Duration {
	option, ok := m[name]
	if ok {
		integer, err := strconv.Atoi(option.Value)
		if nil == err {
			slog.Debug("Read LDAP option.", "key", option.Key, "value", option.Value, "origin", option.Origin)
			return time.Duration(integer) * time.Second
		}
		slog.Warn("Bad integer.", "key", name, "value", option.Value, "err", err.Error(), "origin", option.Origin)
	}
	return 0
}

// Like GetString, but does not log value.
func (m OptionsMap) GetSecret(name string) string {
	option, ok := m[name]
	if ok {
		slog.Debug("Read LDAP option.", "key", option.Key, "origin", option.Origin)
		return option.Value
	}
	return ""
}

func (m OptionsMap) GetString(name string) string {
	option, ok := m[name]
	if ok {
		slog.Debug("Read LDAP option.", "key", option.Key, "value", option.Value, "origin", option.Origin)
		return option.Value
	}
	return ""
}

func (m *OptionsMap) LoadDefaults() {
	defaults := map[string]string{
		"NETWORK_TIMEOUT": "30",
		"TLS_REQCERT":     "try",
		"TIMEOUT":         "30",
	}

	for key, value := range defaults {
		(*m)[key] = RawOption{
			Key:    key,
			Value:  value,
			Origin: "default",
		}
	}
}

func (m *OptionsMap) LoadEnv() {
	for _, name := range knownOptions {
		envName := "LDAP" + name
		value, ok := os.LookupEnv(envName)
		if !ok {
			continue
		}
		option := RawOption{
			Key:    strings.TrimPrefix(envName, "LDAP"),
			Value:  value,
			Origin: "env",
		}
		(*m)[option.Key] = option
	}
}

func (m *OptionsMap) LoadFiles(path ...string) (err error) {
	for _, candidate := range path {
		if !filepath.IsAbs(candidate) {
			candidate, _ = filepath.Abs(candidate)
		}
		_, err := os.Stat(candidate)
		if err != nil {
			slog.Debug("Ignoring configuration file.", "path", candidate, "err", err.Error())
			continue
		}
		slog.Debug("Found LDAP configuration file.", "path", candidate)

		fo, err := os.Open(candidate)
		if err != nil {
			return fmt.Errorf("%s: %w", candidate, err)
		}
		for option := range iterFileOptions(fo) {
			option.Origin = candidate
			(*m)[option.Key] = option
		}
	}
	return
}

func iterFileOptions(r io.Reader) <-chan RawOption {
	ch := make(chan RawOption)
	scanner := bufio.NewScanner(r)
	re := regexp.MustCompile(`\s+`)
	go func() {
		defer close(ch)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "#") {
				continue
			}
			line = strings.TrimSpace(line)
			if "" == line {
				continue
			}
			fields := re.Split(line, 2)
			ch <- RawOption{
				Key:   strings.ToUpper(fields[0]),
				Value: fields[1],
			}
		}
	}()
	return ch
}
