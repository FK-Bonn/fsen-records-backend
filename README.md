# fsen-records-backend

Backend for fsen-records

## Setup

```shell
virtualenv -p python3 venv
source venv/bin/activate
pip install -r requirements.txt
```

Create an admin user with the default Database:

```shell
source venv/bin/activate
./create-user.py data/data.db admin password
```

## Running tests

```shell
PYTHONPATH=. pytest
```

## Running (development)

```shell
source venv/bin/activate
TEST_FAKE_SSO_ACTIVE=yup fastapi dev
```
