package migrations

import (
	"database/sql"
	"errors"

	"code.cloudfoundry.org/bbs/db/etcd"
	"code.cloudfoundry.org/bbs/encryption"
	"code.cloudfoundry.org/bbs/format"
	"code.cloudfoundry.org/bbs/migration"
	"code.cloudfoundry.org/clock"
	"code.cloudfoundry.org/lager"
)

func init() {
	AppendMigration(NewAddMaxPidsToDesiredLRPs())
}

type AddMaxPidsToDesiredLRPs struct {
	serializer  format.Serializer
	storeClient etcd.StoreClient
	clock       clock.Clock
	rawSQLDB    *sql.DB
	dbFlavor    string
}

func NewAddMaxPidsToDesiredLRPs() migration.Migration {
	return &AddMaxPidsToDesiredLRPs{}
}

func (e *AddMaxPidsToDesiredLRPs) String() string {
	return "1481761088"
}

func (e *AddMaxPidsToDesiredLRPs) Version() int64 {
	return 1481761088
}

func (e *AddMaxPidsToDesiredLRPs) SetStoreClient(storeClient etcd.StoreClient) {
	e.storeClient = storeClient
}

func (e *AddMaxPidsToDesiredLRPs) SetCryptor(cryptor encryption.Cryptor) {
	e.serializer = format.NewSerializer(cryptor)
}

func (e *AddMaxPidsToDesiredLRPs) SetRawSQLDB(db *sql.DB) {
	e.rawSQLDB = db
}

func (e *AddMaxPidsToDesiredLRPs) RequiresSQL() bool         { return true }
func (e *AddMaxPidsToDesiredLRPs) SetClock(c clock.Clock)    { e.clock = c }
func (e *AddMaxPidsToDesiredLRPs) SetDBFlavor(flavor string) { e.dbFlavor = flavor }

func (e *AddMaxPidsToDesiredLRPs) Up(logger lager.Logger) error {
	logger.Info("altering the table", lager.Data{"query": alterDesiredLRPAddMaxPidsSQL})
	_, err := e.rawSQLDB.Exec(alterDesiredLRPAddMaxPidsSQL)
	if err != nil {
		logger.Error("failed-altering-tables", err)
		return err
	}
	logger.Info("altered the table", lager.Data{"query": alterDesiredLRPAddMaxPidsSQL})

	return nil
}

const alterDesiredLRPAddMaxPidsSQL = `ALTER TABLE desired_lrps
	ADD COLUMN max_pids INTEGER DEFAULT 0;`

func (e *AddMaxPidsToDesiredLRPs) Down(logger lager.Logger) error {
	return errors.New("not implemented")
}
