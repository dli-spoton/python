import argparse, json, requests, datetime, sys
from base64 import b64encode
from nacl import encoding, public

py_now = datetime.datetime.now()
py_date = py_now.strftime("%y%m%d")
repo_list = []

gh_header_accept = 'application/vnd.github.v3+json'

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--sonarcloud', required=True)
    parser.add_argument('-g', '--github', required=True)
    parser.add_argument('-o', '--org', required=True)
    args = parser.parse_args()
    return args

def check_github(args):
    auth_request = requests.get('https://api.github.com/user', auth=(args.github, ''),headers={'Accept': gh_header_accept})
    if auth_request.status_code == 401:
        sys.exit("Invalid Github personal access token.")

def check_sonarcloud(args):
    auth_request = requests.get('https://sonarcloud.io/api/authentication/validate', auth=(args.sonarcloud, ''))
    auth_response = json.loads(auth_request.content)
    if not auth_response['valid']:
        sys.exit("Invalid Sonarcloud security token.")

def generate_token(args, token_name):
    token_url = 'https://sonarcloud.io/api/user_tokens/generate?name=' + token_name
    token_raw = requests.post(token_url, auth=(args.sonarcloud, ''))
    return json.loads(token_raw.content)

def get_public_key(args, repo):
    public_key_url = 'https://api.github.com/repos/' + args.org + '/' + repo + '/actions/secrets/public-key'
    public_key_raw = requests.get(public_key_url, auth=(args.github, ''),headers={'Accept': gh_header_accept})
    return json.loads(public_key_raw.content)

def encrypt(public_key: str, secret_value: str) -> str:
    """Encrypt a Unicode string using the public key."""
    public_key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return b64encode(encrypted).decode("utf-8")

def add_repo_secret(args, repo, key_id, secret):
    secret_url = 'https://api.github.com/repos/' + args.org + '/' + repo + '/actions/secrets/SONAR_TOKEN'
    secret_request = requests.put(
        secret_url,
        auth=(args.github, ''),
        headers={'Accept': gh_header_accept},
        data=json.dumps({'encrypted_value': secret, 'key_id': key_id})
    )

def main():
    args = parse_args()
    check_github(args)
    check_sonarcloud(args)
    for repo in repo_list:
        token_name = repo + '_github'
        print('Generating Sonarcloud token for: ' + repo)
        private_token = generate_token(args, token_name)
        print('Getting Github public key for: ' + repo)
        public_key = get_public_key(args, repo)
        encrypted_token = encrypt(public_key['key'], private_token['token'])
        print('Adding SONAR_TOKEN to: ' + repo)
        add_repo_secret(args, repo, public_key['key_id'], encrypted_token)

if __name__ == '__main__':
    main()
