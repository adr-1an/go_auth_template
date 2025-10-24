package logs

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
)

func safeJSON(v any) string {
	if b, err := json.Marshal(v); err == nil {
		return string(b)
	}
	s := fmt.Sprintf("%v", v)
	b, _ := json.Marshal(s)
	return string(b)
}

func Err(db *sql.DB, name, msg string, err error, ctx any, userID int64) {
	// Machine ID (Default 0 if missing)
	machineID := 0
	if s := os.Getenv("MACHINE_ID"); s != "" {
		if v, conv := strconv.Atoi(s); conv == nil {
			machineID = v
		}
	}

	errStr := "unknown error"
	if err != nil {
		errStr = err.Error()
	}

	if os.Getenv("APP_ENVIRONMENT") == "dev" {
		fmt.Println(err)
	}

	_, execErr := db.Exec(`
		INSERT INTO errors
			(machine_id, name, message, error, stack_trace, context, user_id)
		VALUES
			($1, $2, $3, $4, $5, $6::jsonb, $7)
	`,
		machineID,
		name,
		msg,
		errStr,                // NOT NULL
		string(debug.Stack()), // stack
		safeJSON(ctx),         // always valid JSON
		userID,
	)
	if execErr != nil {
		fmt.Println("[log insert failed]", execErr)
	}
}
