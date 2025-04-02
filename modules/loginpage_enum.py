from bs4 import BeautifulSoup
import requests
import os

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

LOGIN_INDICATORS = {
    'url_paths': ['login', 'signin', 'auth', 'authenticate', 'oauth', 'sso',
                  'sign-in', 'log-in', 'account', 'password', 'verify',
                  'validation', 'access', 'portal', 'session', 'secure',
                  'admin', 'wp-login'],
    'page_titles': ['login', 'sign in', 'authentication', 'account access',
                    'password', 'verify', 'welcome back', 'member login',
                    'admin portal', 'secure access'],
    'technologies': ['oauth', 'saml', 'openid', 'keycloak', 'okta',
                     'auth0', 'ping identity', 'azure ad', 'ldap'],
    'status_codes': [302, 401, 403, 200]
}

def is_login_page(url_data):
    
    """Lightweight detection using metadata fields"""
    url = f"{url_data.get('url') or ''}{url_data.get('final-url') or ''}".lower()


    if any(indicator in url for indicator in LOGIN_INDICATORS['url_paths']):
        return True

    title = url_data.get('title', '').lower()
    if any(indicator in title for indicator in LOGIN_INDICATORS['page_titles']):
        return True

    techs = url_data.get('technologies', [])
    if isinstance(techs, str):
        techs = [t.strip().lower() for t in techs.strip("[]").split(",")]

    if techs and any(tech in LOGIN_INDICATORS['technologies'] for tech in techs):
        return True

    return False

def deep_check_login_page(url):
    """HTML-based detection using BeautifulSoup"""
    try:
        response = requests.get(
            url,
            headers={'User-Agent': 'SecurityScanner/1.0'},
            timeout=5,
            verify=False,
            allow_redirects=True
        )

        if response.status_code not in [200, 401, 403]:
            return False

        soup = BeautifulSoup(response.text, 'html.parser')

        if soup.find('input', {'type': 'password'}):
            return True

        for form in soup.find_all('form', action=True):
            if any(indicator in form['action'].lower()
                   for indicator in LOGIN_INDICATORS['url_paths']):
                return True

        login_selectors = [('id', 'login'), ('id', 'signin'), ('id', 'auth'),
                           ('class', 'login'), ('class', 'signin'), ('class', 'auth')]
        for attr, value in login_selectors:
            if soup.find('form', {attr: value}):
                return True

    except Exception:
        pass

    return False

def analyze_login_interfaces(httpx_results, domain):
    """
    Analyzes HTTPX results and returns login stats.
    Saves login URLs to a file.
    Returns: (login_count, non_login_count, login_urls_file)
    """
    login_count = 0
    login_urls = []

    for result in httpx_results:
        url = result.get('url')
        if not url:
            continue

        if is_login_page(result) or deep_check_login_page(url):
            login_count += 1
            login_urls.append(url)

    non_login_count = len(httpx_results) - login_count

    login_file = os.path.join(f"{domain}_report", f"{domain}_login_urls.txt")
    os.makedirs(os.path.dirname(login_file), exist_ok=True)

    with open(login_file, 'w') as f:
        f.write("\n".join(login_urls))

    return login_count, non_login_count, login_file
