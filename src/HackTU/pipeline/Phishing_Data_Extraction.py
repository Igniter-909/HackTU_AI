from urllib.parse import urlparse, parse_qs
from typing import Dict, Any
import re
import socket
from datetime import datetime
import dns.resolver
import requests
import whois
import ssl
import OpenSSL
from collections import defaultdict

class URLFeatureExtractor:
    def __init__(self):
        self.features = defaultdict(int)
        
    def _count_chars(self, text: str, char: str) -> int:
        """Count occurrences of a character in text."""
        return text.count(char)
    
    def _count_vowels(self, text: str) -> int:
        """Count vowels in text."""
        return sum(text.lower().count(v) for v in 'aeiou')
    
    def extract_features(self, url: str) -> Dict[str, Any]:
        """Extract all features from a URL."""
        try:
            parsed = urlparse(url)
            
            # Split URL components
            domain = parsed.netloc
            directory = '/'.join(parsed.path.split('/')[:-1]) if parsed.path else ''
            file = parsed.path.split('/')[-1] if parsed.path else ''
            params = parsed.query
            
            # Initialize feature dictionary
            self.features.update({
                # URL features
                'length_url': len(url),
                'qty_dot_url': self._count_chars(url, '.'),
                'qty_hyphen_url': self._count_chars(url, '-'),
                'qty_underline_url': self._count_chars(url, '_'),
                'qty_slash_url': self._count_chars(url, '/'),
                'qty_questionmark_url': self._count_chars(url, '?'),
                'qty_equal_url': self._count_chars(url, '='),
                'qty_at_url': self._count_chars(url, '@'),
                'qty_and_url': self._count_chars(url, '&'),
                'qty_exclamation_url': self._count_chars(url, '!'),
                'qty_space_url': self._count_chars(url, ' '),
                'qty_tilde_url': self._count_chars(url, '~'),
                'qty_comma_url': self._count_chars(url, ','),
                'qty_plus_url': self._count_chars(url, '+'),
                'qty_asterisk_url': self._count_chars(url, '*'),
                'qty_hashtag_url': self._count_chars(url, '#'),
                'qty_dollar_url': self._count_chars(url, '$'),
                'qty_percent_url': self._count_chars(url, '%'),
                
                # Domain features
                'domain_length': len(domain),
                'qty_dot_domain': self._count_chars(domain, '.'),
                'qty_hyphen_domain': self._count_chars(domain, '-'),
                'qty_underline_domain': self._count_chars(domain, '_'),
                'qty_vowels_domain': self._count_vowels(domain),
                'domain_in_ip': 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain) else 0,
                
                # Directory features
                'directory_length': len(directory),
                'qty_dot_directory': self._count_chars(directory, '.'),
                'qty_hyphen_directory': self._count_chars(directory, '-'),
                'qty_underline_directory': self._count_chars(directory, '_'),
                'qty_slash_directory': self._count_chars(directory, '/'),
                
                # File features
                'file_length': len(file),
                'qty_dot_file': self._count_chars(file, '.'),
                'qty_hyphen_file': self._count_chars(file, '-'),
                'qty_underline_file': self._count_chars(file, '_'),
                
                # Parameters features
                'params_length': len(params),
                'qty_params': len(parse_qs(params)),
                'qty_dot_params': self._count_chars(params, '.'),
                'qty_hyphen_params': self._count_chars(params, '-'),
                'qty_underline_params': self._count_chars(params, '_'),
                'qty_equal_params': self._count_chars(params, '='),
                'qty_and_params': self._count_chars(params, '&'),
            })
            
            # Additional security/domain features
            try:
                # DNS resolution
                self.features['qty_ip_resolved'] = len(socket.gethostbyname_ex(domain)[2])
                
                # DNS records
                resolver = dns.resolver.Resolver()
                self.features['qty_nameservers'] = len(resolver.resolve(domain, 'NS'))
                self.features['qty_mx_servers'] = len(resolver.resolve(domain, 'MX'))
                
                # WHOIS information
                domain_info = whois.whois(domain)
                self.features['time_domain_activation'] = domain_info.creation_date.timestamp() if domain_info.creation_date else -1
                self.features['time_domain_expiration'] = domain_info.expiration_date.timestamp() if domain_info.expiration_date else -1
                
                # SSL/TLS certificate
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                    s.connect((domain, 443))
                    cert = s.getpeercert()
                self.features['tls_ssl_certificate'] = 1 if cert else 0
                
                # Response time
                response = requests.get(f"http://{domain}", timeout=5)
                self.features['time_response'] = response.elapsed.total_seconds()
                
                # Google indexing (simplified check)
                self.features['url_google_index'] = 1 if requests.get(f"https://www.google.com/search?q=site:{url}").ok else 0
                self.features['domain_google_index'] = 1 if requests.get(f"https://www.google.com/search?q=site:{domain}").ok else 0
                
            except Exception:
                # Set default values for failed checks
                self.features.update({
                    'qty_ip_resolved': -1,
                    'qty_nameservers': -1,
                    'qty_mx_servers': -1,
                    'time_domain_activation': -1,
                    'time_domain_expiration': -1,
                    'tls_ssl_certificate': 0,
                    'time_response': -1,
                    'url_google_index': 0,
                    'domain_google_index': 0
                })
            
            return dict(self.features)
            
        except Exception as e:
            print(f"Error extracting features: {str(e)}")
            return {}
