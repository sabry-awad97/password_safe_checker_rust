import hashlib
import requests


class PasswordCheckStatus:
    def __init__(self, password, status):
        self.password = password
        self.status = status


class API:
    def __init__(self):
        self.client = requests.Session()

    def get_password_leaks(self, query_char):
        url = "https://api.pwnedpasswords.com/range/{}".format(query_char)
        response = self.client.get(url)
        return response.text


class PasswordHasher:
    def __init__(self):
        self.sha1 = hashlib.sha1()

    def hash_password(self, password):
        self.sha1.update(password.encode('utf-8'))
        sha1_password = self.sha1.hexdigest().upper()
        return sha1_password


def get_password_status(api_response, hash_to_check):
    lines = api_response.splitlines()
    hash_counts = {}
    for line in lines:
        parts = line.split(':')
        hash_counts[parts[0]] = int(parts[1])
    if hash_to_check in hash_counts:
        return PasswordCheckStatus(None, 'Compromised ({})'.format(hash_counts[hash_to_check]))
    else:
        return PasswordCheckStatus(None, 'Safe')


def check_password(api, password):
    password_hasher = PasswordHasher()
    sha1_password = password_hasher.hash_password(password)
    first_5_chars = sha1_password[:5]
    tail = sha1_password[5:]
    api_response = api.get_password_leaks(first_5_chars)
    return get_password_status(api_response, tail)


def main(passwords):
    api = API()

    results = []
    for password in passwords:
        result = check_password(api, password)
        results.append(PasswordCheckStatus(password, result.status))

    for result in results:
        print("The password: {} is {}".format(result.password, result.status))


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Please provide at least one password as a command-line argument.")
        sys.exit(1)
    main(sys.argv[1:])
