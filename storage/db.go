package storage

import (
	"errors"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/schema"
	"net/url"
	"strings"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Db is the SQLite3 db handler ype
type Db struct {
	Location      string
	SkipMigration bool

	// cli flags
	Disabled bool
	S3       bool
	Debug    bool
}

// NewDb sets up a new DB
func NewDb() *Db {
	return &Db{}
}

// parseDBLocation parses the db.Location file path
func parseDBLocation(dbLocation string) (*url.URL, string, error) {
	// Parse the DB URI.
	location, err := url.Parse(dbLocation)
	if err != nil {
		return nil, "", err
	}

	// Ensure the sqlite DB file path is correctly parsed via url.Parse
	if location.Scheme == "sqlite" {
		switch {
		case location.Host == "" && location.Path != "":
			return location, location.Path, nil
		case location.Host != "" && location.Path == "":
			return location, location.Host, nil
		case location.Host == "" && location.Path == "":
			return location, "gowitness.sqlite3", nil
		default:
			return location, strings.TrimPrefix(dbLocation, "sqlite://"), nil
		}
	}
	return location, dbLocation, nil
}

type S3Dialector struct {
}

func (s S3Dialector) Name() string {
	return "S3"
}

func (s S3Dialector) Initialize(db *gorm.DB) error {
	return nil
}

func (s S3Dialector) Migrator(db *gorm.DB) gorm.Migrator {
	return nil
}

func (s S3Dialector) DataTypeOf(field *schema.Field) string {
	return ""
}

func (s S3Dialector) DefaultValueOf(field *schema.Field) clause.Expression {
	return clause.Expr{}
}

func (s S3Dialector) BindVarTo(writer clause.Writer, stmt *gorm.Statement, v interface{}) {
	print(v)
}

func (s S3Dialector) QuoteTo(writer clause.Writer, s2 string) {
}

func (s S3Dialector) Explain(sql string, vars ...interface{}) string {
	return ""
}

// Get gets a db handle
func (db *Db) Get() (*gorm.DB, error) {

	if db.Disabled {
		return nil, nil
	}

	var config = &gorm.Config{}

	if db.S3 {
		open, err := gorm.Open(S3Dialector{}, &gorm.Config{})

		return open, err
	}
	if db.Debug {
		config.Logger = logger.Default.LogMode(logger.Info)
	} else {
		config.Logger = logger.Default.LogMode(logger.Error)
	}

	// Parse the DB URI.
	location, dbLocation, err := parseDBLocation(db.Location)
	if err != nil {
		return nil, err
	}

	var conn *gorm.DB

	switch location.Scheme {
	case "sqlite":
		conn, err = gorm.Open(sqlite.Open(dbLocation+"?cache=shared"), config)
		if err != nil {
			return nil, err
		}
	case "postgres":
		conn, err = gorm.Open(postgres.Open(db.Location), config)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported database URI provided")
	}

	if !db.SkipMigration {
		conn.AutoMigrate(&URL{}, &Header{}, &TLS{}, &TLSCertificate{}, &TLSCertificateDNSName{}, &Technologie{}, &ConsoleLog{}, &NetworkLog{})
	}

	return conn, nil
}

// OrderPerception orders by perception hash if enabled
func OrderPerception(enabled bool) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if enabled {
			return db.Order("perception_hash desc")
		}
		return db
	}
}
