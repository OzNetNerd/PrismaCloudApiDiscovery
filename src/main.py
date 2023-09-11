from datetime import datetime
import os
import sys
import requests
import copy
from pprint import pprint
import pandas as pd

OFFSET_LIMIT = 50

# DD/MM/YY format
START_DATE = "09/09/23"
END_DATE = "10/09/23"

pd.set_option("display.max_columns", None)
pd.set_option("display.expand_frame_repr", False)


VULNERABILITY_COUNTS = {
    "critical": "vulnCountCritical",
    "high": "vulnCountHigh",
    "medium": "vulnCountMedium",
    "low": "vulnCountLow",
    "total": "vulnCountTotal",
}

RISK_FACTORS = {
    "Attack complexity: low": "riskFactorAttackComplexityLow",
    "Attack vector: network": "riskFactorAttackVectorNetwork",
    "Critical severity": "riskFactorCriticalSeverity",
    "DoS - High": "riskFactorDosHigh",
    "DoS - Low": "riskFactorDosLow",
    "Exploit exists - POC": "riskFactorExploitExistsPoc",
    "Exploit exists - in the wild": "riskFactorExploitExistsInTheWild",
    "Has fix": "riskFactorHasFix",
    "High severity": "riskFactorHighSeverity",
    "Medium severity": "riskFactorMediumSeverity",
    "Package in use": "riskFactorPackageInUse",
    "Recent vulnerability": "riskFactorRecentVulnerability",
    "Remote execution": "riskFactorRemoteExecution",
}

FLATTENED_FORMAT = {
    "appID": "",
    "clientTypes": [],
    "firstSeen": "",
    "hits": 0,
    "host": "",
    "lastChanged": "",
    "lastSeen": "",
    "method": "",
    "owaspAPIAttacks": False,
    "path": "",
    "protectionStatus": "",
    "public": False,
    "responseSensitiveData": False,
    "Attack complexity: low": False,
    "Attack vector: network": False,
    "Critical severity": False,
    "DoS - High": False,
    "DoS - Low": False,
    "Exploit exists - POC": False,
    "Exploit exists - in the wild": False,
    "Has fix": False,
    "High severity": False,
    "Medium severity": False,
    "Package in use": False,
    "Recent vulnerability": False,
    "Remote execution": False,
    "riskScore": 0,
    "ruleID": "",
    "sensitiveData": True,
    "servers": [],
    "critical vulnerabilities": 0,
    "high vulnerabilities": 0,
    "low vulnerabilities": 0,
    "medium vulnerabilities": 0,
    "total vulnerabilities": 0,
}

from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def _get_env_vars(env_var_key: str, custom_error_message: str = "") -> str:
    try:
        env_var = os.environ[env_var_key]

    except KeyError:
        sys.exit(
            f'Error: Please define the "{env_var_key}" environment variable. {custom_error_message}'
        )

    print(f"Successfully retrieved {env_var_key} environment variable")

    return env_var


def _flatten_data(response: dict) -> list:
    flattened_data = []

    for entry in response:
        copied_entry = copy.deepcopy(entry)

        for (
            original_vuln_count_name,
            new_vuln_count_name,
        ) in VULNERABILITY_COUNTS.items():
            copied_entry[new_vuln_count_name] = copied_entry[
                "vulnerabilityDistribution"
            ].get(original_vuln_count_name)

        del copied_entry["vulnerabilityDistribution"]

        for original_risk_factor_name, new_risk_factor_name in RISK_FACTORS.items():
            exists = (
                True
                if isinstance(
                    copied_entry["riskFactors"].get(original_risk_factor_name), dict
                )
                else False
            )
            copied_entry[new_risk_factor_name] = exists

        del copied_entry["riskFactors"]

        flattened_data.append(copied_entry)

    return flattened_data


def _convert_date_string(date: str, end_date: bool = False):
    datetime_obj = datetime.strptime(date, "%d/%m/%y")

    if end_date:
        datetime_obj = datetime_obj.replace(
            hour=23, minute=59, second=59, microsecond=0
        )

    converted_date_string = datetime_obj.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    return converted_date_string


def get_date_range_query_params(start_date: str = START_DATE, end_date: str = END_DATE):
    converted_start_date = _convert_date_string(start_date)
    converted_end_date = _convert_date_string(end_date, end_date=True)

    date_range_query_params = {
        "from": converted_start_date,
        "to": converted_end_date,
    }

    return date_range_query_params


def main():
    path_to_console = _get_env_vars("PRISMA_CLOUD_PATH_TO_CONSOLE")
    compute_url = f"{path_to_console}/api/"
    discovery_url = (
        f"v1/waas/discovered-apis?project=Central+Console&offset=0&limit={OFFSET_LIMIT}"
    )
    api_discovery_url = compute_url + discovery_url
    date_range_query_params = get_date_range_query_params()

    compute_key = _get_env_vars("PRISMA_CLOUD_API_TOKEN")
    headers = {f"Authorization": f"Bearer {compute_key}"}

    response = requests.get(
        api_discovery_url, params=date_range_query_params, headers=headers, verify=False
    ).json()
    flattened_data = _flatten_data(response)

    df = pd.DataFrame.from_dict(flattened_data)
    df.fillna(False, inplace=True)
    print(df)


if __name__ == "__main__":
    main()
