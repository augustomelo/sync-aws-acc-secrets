package util

import (
	"flag"
	"regexp"
)

type Options struct {
	CredentialsFile string
	LogLevel        string
	Match           regexp.Regexp
	Region          string
	Source          string
	SyncOperation   SyncOperation
	Target          string
}

type SyncOperation string

const (
	Create        SyncOperation = "c"
	Replace       SyncOperation = "r"
	CreateReplace SyncOperation = "cr"
)

var SyncOperations = map[string]SyncOperation{
	"c":  Create,
	"r":  Replace,
	"cr": CreateReplace,
}

func InitOptions() Options {
	credentialsFile := flag.String("credentialsFile", "", "Credentials file locaiton, if no value is provided it will search on aws default location")
	logLevel := flag.String("logLevel", "info", "Log level, possible values: trace, debug, info, warn, error, panic and disabled")
	match := flag.String("match", "", "Regex that will be matched agains secret names, follows RE2 syntax")
	region := flag.String("region", "", "From which region the secrets should be copied")
	source := flag.String("source", "source", "Source aws account, from each the secrets will be copied, default to `source`")
	syncOperation := flag.String("syncOperation", "cr", "Sync operation that will be done it can be either: 'c' for create 'r' to replace and 'cr' for both operations")
	target := flag.String("target", "target", "Target account where it is going to be copied")

	flag.Parse()

	matchRegex, err := regexp.Compile(*match)

	if *region == "" {
		Logger.Fatal().Msg("Region must be provided!")
	}

	if err != nil {
		Logger.Fatal().Msgf("Unable to compile RegExp: '%s'", *match)
	}

	if _, exists := SyncOperations[*syncOperation]; !exists {
		Logger.Fatal().Msg("Sync operation doesn't exists, use one of the followings: 'c' for create 'r' to replace and 'cr' for both operations")
	}

	options := Options{
		CredentialsFile: *credentialsFile,
		LogLevel:        *logLevel,
		Match:           *matchRegex,
		Region:          *region,
		Source:          *source,
		SyncOperation:   SyncOperations[*syncOperation],
		Target:          *target,
	}

	InitLog(options.LogLevel)

	Logger.Debug().Any("options", options).Send()

	return options
}
