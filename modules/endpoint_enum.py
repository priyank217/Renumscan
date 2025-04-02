import re
import json
import ssl
import os
import certifi
import requests
import jsbeautifier
from urllib.parse import urljoin, urlparse, urldefrag
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.util.ssl_ import create_urllib3_context
from functools import lru_cache
import warnings

ENDPOINT_REGEX = re.compile(
    r"""
    (?:"|')                                  # Start quote
    (?P<url>
        (?:https?:)?//[^"'/]+?\.[a-zA-Z]{2,}[^"']*     # Absolute URL
        
        |                                    
        
        (?:/|\.\.?/)?                         # Relative path starters
        [^"'><,;| *()%%$^/\\\[\]]+            # Path characters
        
        |                                    
        
        [a-zA-Z0-9_\-/]+/                     # Directory structure
        (?:
            [a-zA-Z0-9_\-/.]+\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)   # File endpoint
            |
            [a-zA-Z0-9_\-/]{3,}               # REST-style endpoint
        )
    )
    (?:"|')                                   # End quote
    """, re.VERBOSE
)

STATIC_EXTENSIONS = {
    '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', 
    '.ico', '.mp4', '.webp', '.pdf', '.zip', '.exe', '.dmg', '.txt'
}

JS_LIB_BLACKLIST = {
    'jquery', 'bootstrap', 'react', 'angular', 'vue', 
    'lodash', 'underscore', 'moment', 'chartjs'
}

CDN_DOMAINS = ['cdn.', 'ajax.googleapis.com', 'cloudflare.com', 'bootstrapcdn.com']
GRAPHQL_REGEX = re.compile(r'/(graphql|gql)(/|$|\?)', re.I)
WEBHOOK_REGEX = re.compile(r'webhook|callback|notify', re.I)

class EnhancedSSLAdapter(HTTPAdapter):
    """SSL adapter with certificate management and retries"""
    def __init__(self, domain=None):
        self.domain = domain
        super().__init__()
        
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context()
        context.load_verify_locations(cafile=certifi.where())
        
        if self.domain and os.path.exists(f"certs/{self.domain}.pem"):
            context.load_verify_locations(cafile=f"certs/{self.domain}.pem")
            
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

def create_session(domain):
    """Create configured HTTP session"""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=['GET', 'HEAD']
    )
    adapter = EnhancedSSLAdapter(domain)
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    return session

def determine_parser(content, content_type):
    """Intelligently determine the best parser to use"""
    content_type = content_type.lower()
    
    if 'xml' in content_type:
        return 'xml'
    
    if content.lstrip().startswith('<?xml'):
        return 'xml'
    
    try:
        soup = BeautifulSoup(content, 'xml')
        if soup.find():  # If we found any valid tags
            return 'xml'
    except Exception:
        pass
    
    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
    return 'html.parser'

def fetch_endpoints(url, timeout=30, js_analysis=True):
    """Advanced endpoint discovery with JavaScript analysis"""
    parsed = urlparse(url)
    domain = parsed.netloc
    session = create_session(domain)
    endpoints = set()

    try:
        response = session.get(
            url,
            timeout=timeout,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'},
            allow_redirects=True
        )
        response.raise_for_status()

        if response.status_code == 200:
            content = response.text
            content_type = response.headers.get('content-type', '')
            
            parser = determine_parser(content, content_type)
            warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
            soup = BeautifulSoup(content, parser)
            
            endpoints.update(parse_html_elements(soup, url, domain))
            
            if js_analysis:
                endpoints.update(analyze_javascript(content, url, domain))
                
            endpoints.update(find_rest_apis(soup, url, domain))

    except requests.exceptions.SSLError as e:
        print(f"SSL error for {url}: {e}")
        return []
    except requests.exceptions.TooManyRedirects:
        print(f"Too many redirects for {url}")
        return []
    except requests.exceptions.Timeout:
        print(f"Timeout while fetching {url}")
        return []
    except requests.exceptions.RequestException as e:
        print(f"Request error for {url}: {e}")
        return []

    return sorted(filter_endpoints(endpoints, domain))

def parse_html_elements(soup, base_url, domain):
    """Parse HTML elements for endpoints without recursion warnings"""
    found = set()
    
    for tag in ['a', 'link']:
        for el in soup.find_all(tag, href=True):
            endpoint = normalize_url(el['href'], base_url, domain)
            if endpoint:
                found.add(endpoint)
    
    for tag in ['script', 'img', 'iframe']:
        for el in soup.find_all(tag, src=True):
            endpoint = normalize_url(el['src'], base_url, domain)
            if endpoint:
                found.add(endpoint)
    
    for el in soup.find_all('form', action=True):
        endpoint = normalize_url(el['action'], base_url, domain)
        if endpoint:
            found.add(endpoint)
    
    for el in soup.find_all('meta', content=True):
        if 'http' in el['content'].lower():
            content = el['content'].lower()
            if 'url=' in content:
                url = content.split('url=')[1].split(';')[0].strip('\'\"')
                endpoint = normalize_url(url, base_url, domain)
                if endpoint:
                    found.add(endpoint)
    
    return found

def analyze_javascript(content, base_url, domain):
    """Improved JS analysis with source map support"""
    try:
        source_map_url = None
        if '//# sourceMappingURL=' in content:
            source_map_url = content.split('//# sourceMappingURL=')[1].split()[0]
        
        beautified = jsbeautifier.beautify(content)
        endpoints = find_js_endpoints(beautified, base_url, domain)

        if source_map_url and source_map_url.endswith('.map'):
            try:
                session = create_session(urlparse(base_url).netloc)
                map_url = urljoin(base_url, source_map_url)
                response = session.get(map_url, timeout=10)
                if response.status_code == 200:
                    map_data = response.json()
                    endpoints.update(analyze_source_map(map_data, base_url, domain))
            except Exception:
                pass
                
        return endpoints
    except Exception as e:
        print(f"JS analysis error: {e}")
        return set()

def analyze_source_map(map_data, base_url, domain):
    """Extract endpoints from source map"""
    endpoints = set()
    if 'sources' in map_data:
        for source in map_data['sources']:
            if any(source.endswith(ext) for ext in ['.js', '.ts', '.jsx', '.tsx']):
                endpoint = normalize_url(source, base_url, domain)
                if endpoint:
                    endpoints.add(endpoint)
    return endpoints

def find_js_endpoints(js_content, base_url, domain):
    """Find endpoints in JavaScript content"""
    endpoints = set()
    
    for match in ENDPOINT_REGEX.finditer(js_content):
        url = match.group('url')
        endpoint = normalize_url(url, base_url, domain)
        if endpoint:
            endpoints.add(endpoint)
            
    for line in js_content.split('\n'):
        if 'fetch(' in line or 'XMLHttpRequest' in line or 'axios.' in line:
            parts = re.split(r'[\'"`]', line)
            for part in parts:
                endpoint = normalize_url(part, base_url, domain)
                if endpoint:
                    endpoints.add(endpoint)
                    
    return endpoints

@lru_cache(maxsize=1000)
def normalize_url(url, base_url, domain):
    """More robust URL normalization"""
    if not url or url.startswith(('javascript:', 'mailto:', 'tel:', 'data:')):
        return None
        
    if url.startswith(('~/', '@/', 'src/', 'assets/')) and not url.startswith(('http', '//')):
        url = '/' + url.lstrip('~@')
    
    clean_url = urldefrag(url.split('#')[0].split('?')[0]).url
    
    if clean_url.startswith('//'):
        clean_url = f'https:{clean_url}'
    elif clean_url.startswith('/_next/'):
        clean_url = urljoin(base_url, clean_url)
   
    try:
        full_url = urljoin(base_url, clean_url)
    except ValueError:
        return None
    
    parsed = urlparse(full_url)
    if not parsed.netloc.endswith(domain):
        return None
    
    path = parsed.path.lower()
    is_static = any(path.endswith(ext) for ext in STATIC_EXTENSIONS)
    is_cdn = any(cdn in parsed.netloc for cdn in CDN_DOMAINS)
    if is_static or is_cdn:
        return None
        
    return full_url

def filter_endpoints(endpoints, domain):
    """Prioritize and filter endpoints"""
    prioritized = []
    others = []
    
    for endpoint in endpoints:
        parsed = urlparse(endpoint)
        
        if (re.search(r'/api/|/v\d+/|/rest/|/swagger', parsed.path) or
            GRAPHQL_REGEX.search(parsed.path) or
            WEBHOOK_REGEX.search(parsed.path)):
            prioritized.append(endpoint)
        elif re.search(r'\.(php|asp|aspx|jsp|do|action)$', parsed.path, re.I):
            prioritized.append(endpoint)
        else:
            others.append(endpoint)
            
    return prioritized + others

def find_rest_apis(soup, base_url, domain):
    """Find REST API patterns in HTML"""
    apis = set()
    for el in soup.find_all(['a', 'link'], href=True):
        href = el['href']
        if re.search(r'/api/v\d+/|/rest/|/graphql|/swagger', href, re.I):
            endpoint = normalize_url(href, base_url, domain)
            if endpoint:
                apis.add(endpoint)
    return apis