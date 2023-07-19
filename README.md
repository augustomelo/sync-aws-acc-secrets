# sync-aws-acc-secrets

Utility that synchronizes secrets between a source and target accounts on AWS.

## Usage

Possible flags
```
  -credentialsFile string
        Credentials AWS CLI file locaiton (https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html), if no value is provided it will search on AWS default location
  -logLevel string
        Log level, possible values: trace, debug, info, warn, error, panic and disabled (default "info")
  -match string
        Regex that will be matched agains secret names, follows RE2 syntax (https://github.com/google/re2/wiki/Syntax)
  -region string
        From which region the secrets should be copied
  -rename
        If true when creating a secret you will be prompted the new name to be provided. Only works for the creation since it isn't allowd to change a secret name neither the ARN.
  -source source
        Source AWS account, from each the secrets will be copied, default to source (default "source")
  -syncOperation string
        Sync operation that will be done it can be either: 'c' to ONLY create 'r' to ONLY replace and 'cr' for both operations (default "cr")
  -target string
        Target AWS account where the secrets will be copied (default "target")
```

With the default log level (info) the expected output is something like this:

```
2023-06-12T17:23:27+01:00 INF main.go:199 > totalSecretsARNs=1
2023-06-12T17:23:27+01:00 INF main.go:157 > totalSecrets=1
2023-06-12T17:23:27+01:00 INF main.go:67 > created=[arn:aws:secretsmanager:secret_arn:secret_arn:secret:secret_arn, arn:aws:secretsmanager:secret_arn:secret_arn:secret:secret_arn]
2023-06-12T17:23:27+01:00 INF main.go:68 > replaced=[arn:aws:secretsmanager:secret_arn:secret_arn:secret:secret_arn]
2023-06-12T17:23:27+01:00 INF main.go:69 > skipped=["arn:aws:secretsmanager:secret_arn:secret_arn:secret:secret_arn": "Reason why it failed"]
```

## Running

Example: `./sync-aws-acc-secrets -credentialsFile=/home/user/leet/credentials -region=sa-east-1`

With that it will load the credentials (source and target profiles) stored on
home directory ([default location](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)) and it will either create or replace the secrets on the target profile

Other example:

- Only create secrets that match the string `my/secrets` with a custom credentials file :
`./sync-aws-acc-secrets -region=sa-east-1 -credentialsFile=/home/user/leet/credentials -match=my/secrets -syncOperation=c`
