import json
import os
from pathlib import Path

from jose import constants
from jose.backends.rsa_backend import RSAKey

DUMMY_PRIVATE_KEY = '''-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDFycSSICOZDfjJ
jythUjWWEgyUIevccMtfhwaXhPcqZdWUmAC4QQImYCp4A3bT7Js9BFWTgmZR2Us7
W8zgm5/7X+KSVvYQwWro3diMOEXwAoayDZUhjJSNco2+Nj/Yqmb0FUcpziveKtLs
OR+5w8qRE/TfZ+WIX2vzX+MbmE3gUP0mFXEp32/TbC7yBQGJhxeZQutcig8HIu3h
OcTA6l+5+vb0ojuhoXqa/LDajkRpQ2cqkURXdTV9ZmOsJzjGR9Rric/z4MI8zQE0
hlEIVE6r1EMz6rJcWDwRyC+RApx0flSSXKXjOdKu/hvMrc3dWehAADUJC7/BRqtC
LH4EZRWRAgMBAAECggEACcfML2Ck+f7RoF/yyHV4/mKGmjWiNOyj9eWWqxvxX/iY
qugoUvQt/8lOGFCtidW/qHEELU7rsdzxpi4IL8wqSVMowE1KDjKOT5UWzfpDZRau
4/OdfgL2Xpc9UJxcpGFqxWOe+P9/tlT+SJ2bhsNaizmGKJz54fg7/ZUuhREPOsoY
MmxJ3L5sNjRUijAzUw6iExDdal3sHcLF0L30zbnj171Hg1llQK5Jf7xiMolioREf
woevhOOw96uusebodUEcrIml0ZEO2Fu31CPhAObDhc/29P0pcW2GZ+2xiQ6tAohn
+xlbP+gXL4NIG5vRTUo3dJxZSRMUDs0t5ZThKmdQgQKBgQDodYDDQu5qPthY0vCt
xElGDkOqu6PGC/snw0eX5p3g9h/2oxL7g9RdE81WG8NymWRRmx0tEcbnxSRbyQOK
TmGOqCoCR62k4bkBaahMEBRdothcS+tNHNRNllAM8uXva5/d2bQrHPN0PfH3Er0g
9aI++gP0D3zWsepW7O5DDDnooQKBgQDZ0Wx38lVoMcW4u/FP5i9zcgAQSRxHYwB3
5FZ+eorvPgy1Q5rGidypuJDHd5ejWPchwLXoqOaJ9rDevpOlm7Kx7whULr9B0XIb
GJnL9A/M9+H9iq0wE/jvVc0Og3lt6/GtkAI/oG36JoTlZsj33K0x4zLyFeh6rOA2
zt9CjNtW8QKBgAZRMyebSQlgHdcEHIBMZkVeG96m7MN0DeY9u1NYdA/qAGJeeiSV
p47D+/+MD5qsqnpBQeC4q/Qeemd4Jf17NdF/pmybcA+cBsAQE//FLBiDVWfktEdL
MkXNgO1pKHCCNzz7LpdBWSheipXRT4x2wGr/tl3KkfTvrtOf6rWtvmEhAoGALLm8
7RA8i02VDO7CiSZ53dmtu6pXfS0N/pBLVmMxPhjeoSXFlTjfr5XvXJXo9CijbjHU
6HYuCGw4OzSkup+y3Kh5bFfA+/HW3Ut64Q83Y14O8HHWSAYB2psipPVILNMC6CGm
5Iu7qV7ZcQVfBM4yXgkJ//2RpAb1byuhWlfz/fECgYBEgjpbr+6d68ufCuwCPsMp
9FhsODjPZMvBDV/C/3znnX6A5BkPtuXap70KC81evNvY9rnQQc2pvaDVdCjMMM+2
QiqUYmoLeHjpXegkXROLJkBfTrY2nPmNT0ChQ/RzWG5FcyO91dapHcT2g8Zkbn1y
CmospalHXoeHIuRP4LHKHA==
-----END PRIVATE KEY-----
'''
DUMMY_PUBLIC_KEY = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxcnEkiAjmQ34yY8rYVI1
lhIMlCHr3HDLX4cGl4T3KmXVlJgAuEECJmAqeAN20+ybPQRVk4JmUdlLO1vM4Juf
+1/iklb2EMFq6N3YjDhF8AKGsg2VIYyUjXKNvjY/2Kpm9BVHKc4r3irS7DkfucPK
kRP032fliF9r81/jG5hN4FD9JhVxKd9v02wu8gUBiYcXmULrXIoPByLt4TnEwOpf
ufr29KI7oaF6mvyw2o5EaUNnKpFEV3U1fWZjrCc4xkfUa4nP8+DCPM0BNIZRCFRO
q9RDM+qyXFg8EcgvkQKcdH5Uklyl4znSrv4bzK3N3VnoQAA1CQu/wUarQix+BGUV
kQIDAQAB
-----END PUBLIC KEY-----
'''

TEST_JWKS = RSAKey(algorithm=constants.Algorithms.RS256, key=DUMMY_PUBLIC_KEY)

class Config:
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_DAYS = 6 * 31

    SECRET_KEY = os.environ["SECRET_KEY"] \
        if "SECRET_KEY" in os.environ \
        else "1883eb9a04f787018d99ff7dceb4ade9af17cf91d70593336e13a40630dd18c5"
    DB_CONNECTION_STRING = os.environ["DB_CONNECTION_STRING"] \
        if "DB_CONNECTION_STRING" in os.environ \
        else 'sqlite:///' + str(Path(__file__).resolve().parent.parent / 'data' / 'data.db')
    BASE_PROCEEDINGS_DIR = Path(os.environ["BASE_PROCEEDINGS_DIR"]) \
        if "BASE_PROCEEDINGS_DIR" in os.environ \
        else Path(__file__).parent.resolve().parent / 'data' / 'proceedings'
    BASE_DOCUMENTS_DIR = Path(os.environ["BASE_DOCUMENTS_DIR"]) \
        if "BASE_DOCUMENTS_DIR" in os.environ \
        else Path(__file__).parent.resolve().parent / 'data' / 'documents'
    BASE_SGLIEDS_DIR = Path(os.environ["BASE_SGLIEDS_DIR"]) \
        if "BASE_SGLIEDS_DIR" in os.environ \
        else Path(__file__).parent.resolve().parent / 'data' / 'sglieds'
    JWKS = json.loads(Path(os.environ["JWKS_PATH"]).read_text()) \
        if "JWKS_PATH" in os.environ \
        else TEST_JWKS
