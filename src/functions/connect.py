from src.endpoints import api_url, servertime_url
from src.config import api_key, api_secret
from functools import wraps
import requests
import hmac
import json
import time


def get_timestamp():
    """Returns current timestamp from Crypto.com server in milliseconds"""
    response = public_requests(servertime_url)
    if response:
        return response.get("result", {}).get("server_time")
    return None


def pre_hash(api_key, method, timestamp, nonce, params):
    """Creates a pre-hash string for Crypto.com"""
    params_str = json.dumps(params, separators=(",", ":"), sort_keys=True)
    return f"{method}{api_url}{timestamp}{nonce}{params_str}"


def signature(api_key, api_secret, message):
    """Generates a HMAC-SHA256 signature for Crypto.com"""
    mac = hmac.new(
        bytes(api_secret, encoding="utf8"),
        bytes(message, encoding="utf-8"),
        digestmod="sha256",
    )
    return mac.hexdigest()


def auth(endpoint, method, **params):
    """Authenticates and return signature for Crypto.com private API requests"""
    timestamp = str(int(time.time() * 1000))
    nonce = str(int(time.time() * 1000))
    message = pre_hash(api_key, method, timestamp, nonce, params)
    sign = signature(api_key, api_secret, message)

    return {
        "api_key": api_key,
        "sig": sign,
        "nonce": nonce,
        "timestamp": timestamp,
        **params,
    }


def rate_limited(delay):
    """Decorator that enforces a delay between function calls"""

    def decorator(func):
        last_called = [0]

        @wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_called[0]
            if elapsed < delay:
                time.sleep(delay - elapsed)
            result = func(*args, **kwargs)
            last_called[0] = time.time()
            return result

        return wrapper

    return decorator


def public_requests(url, method="GET", headers=None, **kwargs):
    """Handles public API requests to Crypto.com"""
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, params=kwargs)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=kwargs)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        print(f"HTTP error: {e}")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"Connection error: {e}")
        return None
    except requests.exceptions.Timeout as e:
        print(f"Request timed out: {e}")
        return None
    except requests.exceptions.TooManyRedirects as e:
        print(f"Too many redirects: {e}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")
        return None
    except json.decoder.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        return None
    except Exception as e:
        print(e)
        return None


def private_requests(endpoint, method="GET", **params):
    """Receives endpoint and sends private requests to Crypto.com API"""
    url = f"{api_url}{endpoint}"
    auth_params = auth(endpoint, method, **params)

    headers = {"Content-Type": "application/json"}

    if method == "GET":
        response = requests.get(url, headers=headers, params=auth_params)
    elif method == "POST":
        response = requests.post(url, headers=headers, json=auth_params)

    return response.json()


