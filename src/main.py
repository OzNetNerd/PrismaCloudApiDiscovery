import os
import sys
import requests
from pprint import pprint

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


def main():
    compute_url = f'{_get_env_vars("PRISMA_CLOUD_PATH_TO_CONSOLE")}/api/'
    discovery_url = "v1/waas/discovered-apis?project=Central+Console&offset=0&limit=20"
    query_url = compute_url + discovery_url

    compute_key = _get_env_vars("PRISMA_CLOUD_API_TOKEN")
    headers = {f"Authorization": f"Bearer {compute_key}"}

    response = requests.get(query_url, headers=headers, verify=False).json()
    pprint(response)

if __name__ == "__main__":
    main()
