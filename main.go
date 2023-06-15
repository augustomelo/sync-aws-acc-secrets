package main

import (
	"context"
	"fmt"
	"regexp"

	"augustomelo/sync-aws-acc-secrets/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

type Report struct {
	Created  []string
	Replaced []string
	Skipped  []string
}


// usage example
// syn-aws-acc-secrets --source=source-profile --target=profile1 --match=regex --region=eu-central-1 --credentialsFile=/location --syncOperation=cr

func main() {
	// Possibel impprovements
	// 0. Better logging: https://github.com/rs/zerolog
	// 1. Better desciption on the secret it should be something like: Created by sync-aws-acc-secrets version: 12313, secret ref: arn
	// 2. Use context to geep the connections

	options := util.InitOptions()
	sourceCfg := LoadConfig(options.Source, options)
	targetCfg := LoadConfig(options.Target, options)
	secretsARNs := RetrieveSecretsARNs(sourceCfg, options.Match)
	secrets := RetrieveSecrets(sourceCfg, secretsARNs)
	report := SyncSecrets(targetCfg, secrets, options.SyncOperation)

	DisplayReport(report)
}

func DisplayReport(report Report) {
	util.Logger.Info().Strs("created", report.Created).Send()
	util.Logger.Info().Strs("replaced", report.Replaced).Send()
	util.Logger.Info().Strs("skipped", report.Skipped).Send()
}

func SyncSecrets(config aws.Config, secrets []*secretsmanager.GetSecretValueOutput, syncOperation util.SyncOperation) Report {
	conn := secretsmanager.NewFromConfig(config)
	report := Report{
		Created:  make([]string, 0),
		Replaced: make([]string, 0),
		Skipped:  []string{},
	}

	for _, secret := range secrets {
		util.Logger.Debug().Msgf("Synching secret: `%s`", *secret.ARN)

		secretARN := SecretExistsOnTarget(conn, secret.Name)

		if (syncOperation == util.Create || syncOperation == util.CreateReplace) && secretARN == "" {
			result, err := conn.CreateSecret(context.TODO(), &secretsmanager.CreateSecretInput{
				Name:         secret.Name,
				Description:  aws.String(fmt.Sprintf("Ref: %s", *secret.ARN)),
				SecretString: secret.SecretString,
			})

			if err != nil {
				util.Logger.Error().Msgf("Error: %s", err)
			}

			util.Logger.Debug().Msgf("Created secret, new ARN: `%s`", *result.ARN)
			report.Created = append(report.Created, *secret.ARN)
		} else if (syncOperation == util.Replace || syncOperation == util.CreateReplace) && secretARN != "" {
			result, err := conn.UpdateSecret(context.TODO(), &secretsmanager.UpdateSecretInput{
				SecretId:     &secretARN,
				Description:  aws.String(fmt.Sprintf("Ref: %s", *secret.ARN)),
				SecretString: secret.SecretString,
			})

			if err != nil {
				util.Logger.Error().Msgf("Error: %s", err)
			}

			util.Logger.Debug().Msgf("Replaced secret content, ARN: `%s`", *result.ARN)
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
		util.Logger.Error().Msgf("Error: %s", err)
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
			util.Logger.Error().Msgf("Error while getting secret value for ARN: '%s' error: %s", arn, err)
		}

		secrets = append(secrets, result)
	}

	util.Logger.Info().Int("totalSecrets", len(secrets)).Send()
	return secrets
}

func RetrieveSecretsARNs(config aws.Config, match regexp.Regexp) []string {
	conn := secretsmanager.NewFromConfig(config)
	secretsARNs := make([]string, 0)
	filterSecretList := &secretsmanager.ListSecretsInput{}
	page, err := conn.ListSecrets(context.TODO(), filterSecretList)

	if err != nil {
		util.Logger.Error().Msgf("Error: '%s", err)
		return secretsARNs
	}

	for i := 1; ; i++ {
		util.Logger.Debug().Msgf("Procesing page %d with %d items", i, len(page.SecretList))

		for _, secret := range page.SecretList {
			util.Logger.Debug().Msgf("Processing secret: %s", *secret.Name)

			if match.MatchString(*secret.Name) {
				util.Logger.Debug().Msgf("Matched secret name: `%s` against: `%s`", *secret.Name, &match)
				secretsARNs = append(secretsARNs, *secret.ARN)
			}
		}

		if page.NextToken == nil {
			util.Logger.Debug().Msgf("No NextToken povided, processed last page")
			break
		}

		filterSecretList.NextToken = page.NextToken
		page, err = conn.ListSecrets(context.TODO(), filterSecretList)

		if err != nil {
			util.Logger.Error().Msgf("Error: '%s", err)
			return secretsARNs
		}

	}

	util.Logger.Info().Int("totalSecretsARNs", len(secretsARNs)).Send()
	util.Logger.Debug().Strs("secretsARNs", secretsARNs).Send()

	return secretsARNs
}

func LoadConfig(profile string, options util.Options) aws.Config {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
		config.WithRegion(options.Region),
		config.WithSharedCredentialsFiles([]string{options.CredentialsFile}),
	)

	if err != nil {
		util.Logger.Fatal().Msgf("Cloudn't load config!", err)
	}

	return cfg
}
