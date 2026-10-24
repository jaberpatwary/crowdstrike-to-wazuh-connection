// Package logging configures the bridge's JSON structured logger.
package logging

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

func New(level string) (zerolog.Logger, error) {
	parsed, err := zerolog.ParseLevel(strings.ToLower(level))
	if err != nil {
		return zerolog.Logger{}, fmt.Errorf("invalid LOG_LEVEL %q: %w", level, err)
	}
	return zerolog.New(os.Stdout).
		With().
		Timestamp().
		Logger().
		Level(parsed), nil
}

func init() {
	zerolog.TimeFieldFormat = time.RFC3339Nano
}
