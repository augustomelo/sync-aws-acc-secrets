package util

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var Logger zerolog.Logger

func InitLog(logLevel string) {
	zeroLevel, err := zerolog.ParseLevel(logLevel)

	if err != nil {
		log.Err(err)
		log.Info().Msg("Level provided does not exist using default value: info")
		zeroLevel = zerolog.InfoLevel
	}

	Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		Level(zeroLevel).
		With().
		Timestamp().
		Caller().
		Logger()

}
