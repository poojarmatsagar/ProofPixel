"""
Comprehensive URL Analyzer Module
Provides real-time URL validation and security analysis
"""

import re
import ipaddress
import socket
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlunparse
import requests
from tldextract import extract


class URLAnalyzer:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'verify', 'bank', 'update', 'free', 'secure',
            'account', 'password', 'signin', 'confirm', 'suspended',
            'blocked', 'expired', 'urgent', 'immediate', 'warning'
        ]
        
        self.url_shorteners = {
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee',
            'tiny.cc', 'short.link', 'cutt.ly', 'rb.gy', 'short.io'
        }
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.session.timeout = 10

    def analyze_url(self, url):
        """
        Main analysis function - returns comprehensive URL analysis
        """
        try:
            # Step 1: Normalize and validate URL
            normalized_url = self._normalize_url(url)
            if not normalized_url:
                return self._create_result(url, False, 100, ["Invalid URL format"])
            
            parsed = urlparse(normalized_url)
            
            # Step 2: Initialize analysis
            risk_score = 0
            reasons = []
            
            # Step 3: Perform various checks
            risk_score, reasons = self._check_url_structure(parsed, risk_score, reasons)
            risk_score, reasons = self._check_dns_resolution(parsed.netloc, risk_score, reasons)
            risk_score, reasons = self._check_domain_info(parsed.netloc, risk_score, reasons)
            risk_score, reasons = self._check_web_content(normalized_url, risk_score, reasons)
            risk_score, reasons = self._check_security_indicators(parsed, risk_score, reasons)
            
            # Step 4: Determine final safety
            is_safe = risk_score < 50
            
            return self._create_result(
                original_url=url,
                normalized_url=normalized_url,
                is_safe=is_safe,
                risk_score=min(risk_score, 100),
                reasons=reasons
            )
            
        except Exception as e:
            return self._create_result(url, False, 100, [f"Analysis error: {str(e)}"])

    def _validate_url_format(self, url):
        """Simple URL validation"""
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False

    def _normalize_url(self, url):
        """Normalize URL format"""
        try:
            url = url.strip()
            
            # Check if URL has scheme
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url  # Default to HTTPS
            
            # Validate URL format
            if not self._validate_url_format(url):
                return None
            
            # Parse and reconstruct to ensure consistency
            parsed = urlparse(url)
            if not parsed.netloc:
                return None
            
            # Remove default ports
            if (parsed.scheme == 'http' and parsed.port == 80) or \
               (parsed.scheme == 'https' and parsed.port == 443):
                netloc = parsed.hostname
            else:
                netloc = parsed.netloc
            
            return urlunparse((
                parsed.scheme,
                netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                ''  # Remove fragment
            ))
            
        except:
            return None

    def _check_url_structure(self, parsed, risk_score, reasons):
        """Check URL structure for suspicious patterns"""
        # Check for IP address instead of domain
        try:
            ipaddress.ip_address(parsed.hostname)
            risk_score += 30
            reasons.append("URL uses IP address instead of domain name")
        except ValueError:
            pass  # Not an IP address, which is good
        
        # Check for excessive subdomains
        domain_parts = parsed.hostname.split('.')
        if len(domain_parts) > 4:
            risk_score += 15
            reasons.append("Excessive subdomains detected")
        
        # Check for suspicious keywords
        url_lower = urlunparse(parsed).lower()
        found_keywords = [kw for kw in self.suspicious_keywords if kw in url_lower]
        if found_keywords:
            risk_score += len(found_keywords) * 10
            reasons.append(f"Suspicious keywords found: {', '.join(found_keywords)}")
        
        # Check for URL shorteners
        if parsed.hostname in self.url_shorteners:
            risk_score += 20
            reasons.append("URL shortening service detected")
        
        # Check for long URLs
        if len(urlunparse(parsed)) > 200:
            risk_score += 10
            reasons.append("Unusually long URL")
        
        # Check for excessive parameters
        if len(parsed.query.split('&')) > 10:
            risk_score += 15
            reasons.append("Excessive URL parameters")
        
        return risk_score, reasons

    def _check_dns_resolution(self, hostname, risk_score, reasons):
        """Check DNS resolution"""
        try:
            # Try to resolve the hostname
            ip = socket.gethostbyname(hostname)
            
            # Check for suspicious IP ranges
            ip_obj = ipaddress.ip_address(ip)
            # Check for private IPs
            if ip_obj.is_private:
                risk_score += 25
                reasons.append("URL resolves to private IP address")
            # Check for localhost
            elif ip_obj.is_loopback:
                risk_score += 40
                reasons.append("URL resolves to localhost")
                
        except socket.gaierror:
            risk_score += 50
            reasons.append("Domain does not resolve")
        except Exception:
            risk_score += 20
            reasons.append("DNS resolution check failed")
        
        return risk_score, reasons

    def _check_domain_info(self, hostname, risk_score, reasons):
        """Check basic domain information"""
        try:
            # Extract domain using tldextract
            extracted = extract(hostname)
            domain = extracted.domain + '.' + extracted.suffix if extracted.suffix else extracted.domain
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.cc', '.biz', '.info']
            if any(extracted.suffix.endswith(tld) for tld in suspicious_tlds):
                risk_score += 15
                reasons.append("Domain uses suspicious TLD")
            
            # Check for very long domain names
            if len(extracted.domain) > 30:
                risk_score += 10
                reasons.append("Unusually long domain name")
            
            # Check for domain with numbers (often used for phishing)
            if any(char.isdigit() for char in extracted.domain):
                risk_score += 10
                reasons.append("Domain contains numbers")
            
            # Check for domain with hyphens
            if '-' in extracted.domain:
                risk_score += 5
                reasons.append("Domain contains hyphens")
                        
        except Exception:
            # Domain analysis failed - not necessarily suspicious
            pass
        
        return risk_score, reasons

    def _check_web_content(self, url, risk_score, reasons):
        """Check web content and HTTP response"""
        try:
            response = self.session.get(url, allow_redirects=True, timeout=10)
            
            # Check status code
            if response.status_code >= 400:
                risk_score += 20
                reasons.append(f"HTTP error status: {response.status_code}")
            
            # Check redirect chain
            if len(response.history) > 3:
                risk_score += 15
                reasons.append("Excessive redirects detected")
            
            # Check final URL after redirects
            if response.url != url:
                final_parsed = urlparse(response.url)
                if final_parsed.hostname != urlparse(url).hostname:
                    risk_score += 25
                    reasons.append("URL redirects to different domain")
            
            # Check content for suspicious patterns
            content_lower = response.text.lower()
            
            # Check for forms
            if '<form' in content_lower and ('password' in content_lower or 'login' in content_lower):
                risk_score += 15
                reasons.append("Page contains login/password forms")
            
            # Check for suspicious scripts
            dangerous_scripts = ['eval(', 'document.write', 'innerHTML']
            found_scripts = [script for script in dangerous_scripts if script in content_lower]
            if found_scripts:
                risk_score += 20
                reasons.append("Page contains potentially dangerous scripts")
            
            # Check for HTTPS
            if not url.startswith('https://'):
                risk_score += 20
                reasons.append("URL does not use HTTPS")
            
        except requests.exceptions.Timeout:
            risk_score += 15
            reasons.append("Request timeout")
        except requests.exceptions.ConnectionError:
            risk_score += 30
            reasons.append("Connection failed")
        except Exception as e:
            risk_score += 10
            reasons.append(f"Content analysis failed: {str(e)}")
        
        return risk_score, reasons

    def _check_security_indicators(self, parsed, risk_score, reasons):
        """Additional security checks"""
        # Check for @ symbol (credential injection attempt)
        if '@' in urlunparse(parsed):
            risk_score += 35
            reasons.append("URL contains @ symbol (potential credential injection)")
        
        # Check for port specification
        if parsed.port and parsed.port not in [80, 443]:
            risk_score += 15
            reasons.append(f"URL uses non-standard port: {parsed.port}")
        
        # Check for encoded characters
        if '%' in urlunparse(parsed):
            risk_score += 10
            reasons.append("URL contains encoded characters")
        
        # Check for double slashes in path (potential bypass)
        if '//' in parsed.path:
            risk_score += 10
            reasons.append("URL contains double slashes in path")
        
        return risk_score, reasons

    def _create_result(self, original_url, is_safe=True, risk_score=0, reasons=None, 
                      normalized_url=None):
        """Create standardized result format"""
        return {
            "url": original_url,
            "normalized_url": normalized_url or original_url,
            "is_safe": is_safe,
            "risk_score": risk_score,
            "reasons": reasons or [],
            "timestamp": datetime.now().isoformat()
        }


# Global analyzer instance
url_analyzer = URLAnalyzer()
