package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

type Options struct {
	CredentialsFile string
	Match           regexp.Regexp
	Region          string
	Source          string
	SyncOperation   SyncOperation
	Target          string
}

type Report struct {
	Created  []string
	Replaced []string
	Skipped  []string
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

// usage example
// syn-aws-acc-secrets --source=source-profile --target=profile1 --match=regex --region=eu-central-1 --credentialsFile=/location --syncOperation=cr

func main() {
	// Possibel impprovements
	// 0. Better logging: https://github.com/rs/zerolog
	// 1. Better desciption on the secret it should be something like: Created by sync-aws-acc-secrets version: 12313, secret ref: arn
	// 2. Use context to geep the connections

	options := InitOptions()
	sourceCfg := LoadConfig(options.Source, options)
	targetCfg := LoadConfig(options.Target, options)
	secretsARNs := RetrieveSecretsARNs(sourceCfg, options.Match)
	secrets := RetrieveSecrets(sourceCfg, secretsARNs)
	report := SyncSecrets(targetCfg, secrets, options.SyncOperation)

	displayReport(report)
}

func displayReport(report Report) {
	log.Println("Secrets created on target: ")
	log.Println(report.Created)
	log.Println("Secrets replaced on target: ")
	log.Println(report.Replaced)
	log.Println("Secrets skipped on the target: ")
	log.Println(report.Skipped)
}

func SyncSecrets(config aws.Config, secrets []*secretsmanager.GetSecretValueOutput, syncOperation SyncOperation) Report {
	conn := secretsmanager.NewFromConfig(config)
	report := Report{
		Created:  make([]string, 0),
		Replaced: make([]string, 0),
		Skipped:  []string{},
	}

	for _, secret := range secrets {
		log.Printf("Synching secret: `%s`", *secret.ARN)

		secretARN := SecretExistsOnTarget(conn, secret.Name)

		if (syncOperation == Create || syncOperation == CreateReplace) && secretARN == "" {
			result, err := conn.CreateSecret(context.TODO(), &secretsmanager.CreateSecretInput{
				Name:         secret.Name,
				Description:  aws.String(fmt.Sprintf("Ref: %s", *secret.ARN)),
				SecretString: secret.SecretString,
			})

			if err != nil {
				log.Panicf("Error: %s", err)
			}

			log.Printf("Created secret, new ARN: `%s`", *result.ARN)
			report.Created = append(report.Created, *secret.ARN)
		} else if (syncOperation == Replace || syncOperation == CreateReplace) && secretARN != "" {
			result, err := conn.UpdateSecret(context.TODO(), &secretsmanager.UpdateSecretInput{
				SecretId:     &secretARN,
				Description:  aws.String(fmt.Sprintf("Ref: %s", *secret.ARN)),
				SecretString: secret.SecretString,
			})

			if err != nil {
				log.Panicf("Error: %s", err)
			}

			log.Printf("Replaced secret content, ARN: `%s`", *result.ARN)
			report.Replaced = append(report.Replaced, *result.ARN)
		} else {
			report.Skipped = append(report.Skipped, fmt.Sprintf("%s: Unable to create/replace secret due to sync operation being '%s'", *secret.ARN, syncOperation))
		}
	}

	return report
}

func SecretExistsOnTarget(conn *secretsmanager.Client, secretName *string) string {
	val, err := conn.ListSecrets(context.TODO(), &secretsmanager.ListSecretsInput{
		Filters: []types.Filter{
			{Key: types.FilterNameStringTypeName, Values: []string{*secretName}},
		},
	})

	if err != nil {
		log.Panicf("Error: %s", err)
	}

	if val != nil {
		for _, secret := range val.SecretList {
			if *secret.Name == *secretName {
				return *secret.ARN
			}
		}
	}

	return ""
}

func RetrieveSecrets(config aws.Config, secretsARNs []string) []*secretsmanager.GetSecretValueOutput {
	conn := secretsmanager.NewFromConfig(config)
	secrets := make([]*secretsmanager.GetSecretValueOutput, 0)

	for _, arn := range secretsARNs {
		result, err := conn.GetSecretValue(context.TODO(), &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(arn),
		})

		if err != nil {
			log.Panicf("Error while getting secret value for ARN: '%s' error: \n%s", arn, err)
		}

		secrets = append(secrets, result)
	}

	log.Printf("Found `%d` secret value", len(secrets))
	return secrets
}

func RetrieveSecretsARNs(config aws.Config, match regexp.Regexp) []string {
	conn := secretsmanager.NewFromConfig(config)
	secretsARNs := make([]string, 0)
	filterSecretList := &secretsmanager.ListSecretsInput{}
	page, err := conn.ListSecrets(context.TODO(), filterSecretList)

	if err != nil {
		log.Printf("Error: '%s", err)
		return secretsARNs
	}

	for i := 1; ; i++ {
		log.Printf("Procesing page %d with %d items", i, len(page.SecretList))

		for _, secret := range page.SecretList {
			log.Printf("Processing secret: %s", *secret.Name)
			if match.MatchString(*secret.Name) {
				log.Printf("Matched secret name: `%s` against: `%s`", *secret.Name, &match)
				secretsARNs = append(secretsARNs, *secret.ARN)
			}
		}

		if page.NextToken == nil {
			log.Printf("No NextToken povided, processed last page")
			break
		}

		filterSecretList.NextToken = page.NextToken
		page, err = conn.ListSecrets(context.TODO(), filterSecretList)

		if err != nil {
			log.Printf("Error: '%s", err)
			return secretsARNs
		}

	}

	log.Printf("Found total secrets: %d", len(secretsARNs))
	log.Printf("Found secrets: %s", secretsARNs)

	return secretsARNs
}

func LoadConfig(profile string, options Options) aws.Config {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
		config.WithRegion(options.Region),
		config.WithSharedCredentialsFiles([]string{options.CredentialsFile}),
	)

	if err != nil {
		log.Panic("Cloudn't load config!", err)
	}

	return cfg
}

func InitOptions() Options {
	credentialsFile := flag.String("credentialsFile", "", "Credentials file locaiton, if no value is provided it will search on aws default location")
	match := flag.String("match", "", "Regex that will be matched agains secret names, follows RE2 syntax")
	region := flag.String("region", "", "From which region the secrets should be copied")
	source := flag.String("source", "source", "Source aws account, from each the secrets will be copied, default to `source`")
	target := flag.String("target", "target", "Target account where it is going to be copied")
	syncOperation := flag.String("syncOperation", "cr", "Sync operation that will be done it can be either: 'c' for create 'r' to replace and 'cr' for both operations")

	flag.Parse()

	matchRegex, err := regexp.Compile(*match)

	if *region == "" {
		log.Panic("Region must be provided")
	}

	if err != nil {
		log.Panicf("Unable to compile RegExp: '%s'", *match)
	}

	if _, exists := SyncOperations[*syncOperation]; !exists {
		log.Panicf("Sync operation doesn't exists, use one of the followings: 'c' for create 'r' to replace and 'cr' for both operations")
	}

  options := Options{
		CredentialsFile: *credentialsFile,
		Match:           *matchRegex,
		Region:          *region,
		Source:          *source,
		SyncOperation:   SyncOperations[*syncOperation],
		Target:          *target,
	}

  result, _ := json.Marshal(options)
  log.Printf("Initialized with option: %s", result)

  return options
}
