# fsen-records-backend

Backend for fsen-records

## Setup

```shell
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Create an admin user with the default Database:

```shell
source venv/bin/activate
./create-user.py data/data.db admin password
```

## Running tests

Install the development dependencies (once):
```shell
source venv/bin/activate
pip install -r requirements-dev.txt
```

Then run the test script:
```shell
source venv/bin/activate
./test
```

## Running (development)

```shell
source venv/bin/activate
TEST_FAKE_SSO_ACTIVE=yup fastapi dev
```
