import secrets

from tasks import packagepwd
from httpx import Client, post
import datetime
import random
import string
import json


config: dict = json.load(open("config.json"))
domains: dict = json.load(open("templates/domains.json"))


def fix_text(text) -> str:
    return text.replace('\\u002f', "/").replace('\\u003a', ":").replace('\\u0026', "&").replace('\\u003d', "=") \
        .replace('\\u002b', "+")


def random_alphabetic_string(length):
    return "".join(random.choices(string.ascii_letters, k=length))


class OutlookResponse(object):
    def __init__(self, email: str, password: str, error: str = ""):
        self.email = email
        self.password = password
        self.error = error


class OutlookAccount(object):
    def __init__(self, proxy: str) -> None:
        self.cipher = None
        self.client = Client(proxies=proxy)
        self.agent = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " \
                     f"Chrome/{random.randint(77, 108)}.0.{random.randint(1000, 9999)}." \
                     f"{random.randint(0, 144)} Safari/537.36"
        self.domain = random.choice(domains)
        self.captcha_site_key = "B7D8911C-5CC8-A9A3-35B0-554ACEE604DA"
        self.signup_url = f"https://signup.live.com/signup?lic=1&mkt={self.domain.get('mkt')}"
        self.create_url = f"https://signup.live.com/API/CreateAccount?lic=1"
        self.password = "".join(random.choices(string.ascii_letters + string.digits, k=16))
        self.first_name = random_alphabetic_string(16)
        self.last_name = random_alphabetic_string(8)
        self.email = f"{self.first_name}{self.last_name}@{self.domain.get('domain')}".lower()
        self.birthday = self._get_birthday()
        self.key = None
        self.ski = None
        self.random_num = None
        self.canary = None
        self.tcxt = None
        self.uaid = None
        self.encAttemptToken = ""
        self.dfpRequestId = ""
        self._load_register_page()
        self.cipher = packagepwd.package_pwd(self.password, self.random_num, self.key)

    @staticmethod
    def _hand_error(code: str):
        errors = {
            "403": "Bad Username",
            "1040": "SMS Needed",
            "1041": "Enforcement Captcha",
            "1042": "Text Captcha",
            "1043": "Invalid Captcha",
            "1312": "Captcha Error",
            "450": "Daily Limit Reached",
            "1304": "OTP Invalid",
            "1324": "Verification SLT Invalid",
            "1058": "Username Taken",
            "1117": "Domain Blocked",
            "1181": "Reserved Domain",
            "1002": "Incorrect Password",
            "1009": "Password Conflict",
            "1062": "Invalid Email Format",
            "1063": "Invalid Phone Format",
            "1039": "Invalid Birth Date",
            "1243": "Invalid Gender",
            "1240": "Invalid first name",
            "1241": "Invalid last name",
            "1204": "Maximum OTPs reached",
            "1217": "Banned Password",
            "1246": "Proof Already Exists",
            "1184": "Domain Blocked",
            "1185": "Domain Blocked",
            "1052": "Email Taken",
            "1242": "Phone Number Taken",
            "1220": "Signup Blocked",
            "1064": "Invalid Member Name Format",
            "1330": "Password Required",
            "1256": "Invalid Email",
            "1334": "Eviction Warning Required",
            "100": "Bad Register Request"
        }
        return errors[code]

    @staticmethod
    def _get_birthday():
        day = random.randint(1, 27)
        month = random.randint(1, 9)
        year = random.randint(1969, 2000)
        return f"{day}:0{month}:{year}"

    def _load_register_page(self):
        body: str = self.client.get(self.signup_url, headers={
            "User-Agent": self.agent
        }).text

        self.uaid = body.split('"clientTelemetry":{"uaid":"')[1].split('"')[0]
        self.tcxt = fix_text(body.split('"clientTelemetry":{"uaid":"')[1].split(',"tcxt":"')[1].split('"},')[0])
        self.canary = fix_text(body.split('"apiCanary":"')[1].split('"')[0])
        self.random_num = body.split('var randomNum="')[1].split('"')[0]
        self.key = body.split('var Key="')[1].split('"')[0]
        self.ski = body.split('var SKI="')[1].split('"')[0]

    def register_account(self, solved=False):
        body = self._register_body(solved)
        resp = self.client.post(self.create_url, json=body, headers=self._register_headers())
        error = resp.json().get("error")
        if error:
            code = error.get("code")
            if '1041' in code:
                error_data = error.get("data")
                self.encAttemptToken = fix_text(error_data.split('encAttemptToken":"')[1].split('"')[0])
                self.dfpRequestId = fix_text(error_data.split('dfpRequestId":"')[1].split('"')[0])
                return self.register_account(True)
            else:
                return OutlookResponse(self.email, self.password, self._hand_error(code))
        else:
            return OutlookResponse(self.email, self.password)

    def _register_body(self, try_solve: bool) -> dict:
        body = {
            "RequestTimeStamp": str(datetime.datetime.now()).replace(" ", "T")[:-3] + "Z",
            "MemberName": self.email,
            "CheckAvailStateMap": [
                f"{self.email}:undefined"
            ],
            "EvictionWarningShown": [],
            "UpgradeFlowToken": {},
            "FirstName": self.first_name,
            "LastName": self.last_name,
            "MemberNameChangeCount": 1,
            "MemberNameAvailableCount": 1,
            "MemberNameUnavailableCount": 0,
            "CipherValue": self.cipher,
            "SKI": self.ski,
            "BirthDate": self.birthday,
            "Country": self.domain.get('country'),
            "AltEmail": None,
            "IsOptOutEmailDefault": True,
            "IsOptOutEmailShown": True,
            "IsOptOutEmail": True,
            "LW": True,
            "SiteId": "68692",
            "IsRDM": 0,
            "WReply": None,
            "ReturnUrl": None,
            "SignupReturnUrl": None,
            "uiflvr": 1001,
            "uaid": self.uaid,
            "SuggestedAccountType": "OUTLOOK",
            "SuggestionType": "Locked",
            "encAttemptToken": self.encAttemptToken,
            "dfpRequestId": self.dfpRequestId,
            "scid": 100118,
            "hpgid": 201040,
        }
        if try_solve:
            body.update({
                "HType": "enforcement",
                "HSol": self._retry_solve(),
                "HPId": self.captcha_site_key,
            })
        return body

    def _retry_solve(self):
        while True:
            try:
                result = post("https://nigger.zone//captcha/solvers/funcaptcha-instant", json={
                  "api_key": config.get('api-key'),
                  "site": "outlook",
                  "data": {
                    "blob": "undefined"
                  }
                }, timeout=120).json()
                token = result.get("token")
                if token:
                    return token
            except Exception:
                pass

    def _register_headers(self):
        return {
            "accept": "application/json",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "canary": self.canary,
            "content-type": "application/json",
            "dnt": "1",
            "hpgid": f"2006{random.randint(10, 99)}",
            "origin": "https://signup.live.com",
            "pragma": "no-cache",
            "scid": "100118",
            "sec-ch-ua": '" Not A;Brand";v="107", "Chromium";v="96", "Google Chrome";v="96"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "tcxt": self.tcxt,
            "uaid": self.uaid,
            "uiflvr": "1001",
            "user-agent": self.agent,
            "x-ms-apitransport": "xhr",
            "x-ms-apiversion": "2",
            "referer": "https://signup.live.com/?lic=1"
        }
