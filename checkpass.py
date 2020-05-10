import requests
import hashlib
import sys


def request_api_data(hash_chars):
    url = 'https://api.pwnedpasswords.com/range/' + hash_chars

    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching: {response.status_code}, check the api and try again')

    return response


def get_password_leaks_count(hashes, hash_to_check):
    hashes_tuple = (line.split(':') for line in hashes.splitlines())
    for h, count in hashes_tuple:
        if h == hash_to_check:
            return count

    return 0


def pwned_api_check_password(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_5_chars, tail = sha1password[:5], sha1password[5:]

    response = request_api_data(first_5_chars)

    return get_password_leaks_count(response.text, tail)


def main(args):
    for password in args:
        count = pwned_api_check_password(password)
        if count:
            print(f'{password} was found {count} times. It\'s better if you change your password.')
        else:
            print(f'{password} was NOT found in any breaches.')


sys.exit(main(sys.argv[1:]))
