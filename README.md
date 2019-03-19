# LetsEncrypt AWS Lambda

## Setup development environment

[subscribe
guides & tutorials
How to Handle your Python packaging in Lambda with Serverless plugins](https://serverless.com/blog/serverless-python-packaging/)

```shell
$ pip install virtualenv --user
$ virtualenv env --python=python3
$ source venv/bin/activate
```

configure certificate domains and aliyun credential
```shell
$ aws ssm put-parameter --name letsencrypt_domains --type StringList --value "*.abc.com,*.dev.abc.acom|*.def.com"
$ aws ssm put-parameter --name letsencrypt_email --type String --value my@email.com
$ aws ssm put-parameter --name letsencrypt_period --type String --value 30
$ aws ssm put-parameter --name elb_listener_arn --type String --value myelb-listener-arn
$ aws ssm put-parameter --name aliyun_appid --type String --value myappid
$ aws ssm put-parameter --name aliyun_appsecret --type String --value myappsecret
```
different domain split by `|`

## Deploy

```shell
$ serverless deploy
```