"""
DNS Authenticator for Forpsi DNS provider
"""
import logging
import pyotp
from typing import Any, Callable, Optional
import re
import requests
from certbot import errors
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Forpsi DNS"""

    description = "Obtain certificates using a DNS TXT record with Forpsi."
    ttl = 60

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[dns_common.CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None]) -> None:
        super().add_parser_arguments(add, default_propagation_seconds=120)
        add("admin-site", help="Forpsi admin site (e.g., admin.forpsi.com)")
        add("credentials", help="Forpsi credentials INI file.")
        add("username", help="Forpsi username (alternative to credentials file)")
        add("password", help="Forpsi password (alternative to credentials file)")
        add("totp-secret", help="Forpsi TOTP secret for 2FA (optional)")

    def more_info(self) -> str:
        return "This plugin configures a DNS TXT record to respond to a dns-01 challenge using the Forpsi admin interface."

    def _setup_credentials(self) -> None:
        # Check if CLI parameters are provided
        cli_admin_site = self.conf("admin-site")
        cli_username = self.conf("username")
        cli_password = self.conf("password")
        cli_totp_secret = self.conf("totp-secret")
        
        logger.debug(f"CLI parameters - admin-site: {cli_admin_site}, username: {cli_username}, password: {'***' if cli_password else None}")
        
        # If CLI parameters are provided, use them
        if cli_admin_site and cli_username and cli_password:
            logger.debug("Using CLI parameters for authentication")
            # Create a mock credentials object for CLI parameters
            self.credentials = type('MockCredentials', (), {
                'conf': lambda self, key: {
                    'admin_site': cli_admin_site,
                    'username': cli_username,
                    'password': cli_password,
                    'totp_secret': cli_totp_secret
                }.get(key)
            })()
        else:
            logger.debug("CLI parameters incomplete, falling back to INI file")
            # Fall back to INI file
            self.credentials = self._configure_credentials(
                "credentials",
                "Forpsi credentials INI file",
                {
                    "admin_site": "Forpsi admin site (e.g., admin.forpsi.com)",
                    "username": "Forpsi username",
                    "password": "Forpsi password",
                    "totp_secret": "Forpsi TOTP secret (optional)",
                },
            )
            
        # Validate admin_site from credentials file
        admin_site = self.credentials.conf("admin_site")
        if admin_site and not admin_site.startswith(('admin.forpsi.', 'forpsi.')):
            raise errors.PluginError(
                "Invalid admin site. Must be a Forpsi admin site like 'admin.forpsi.com'"
            )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        client = self._get_forpsi_client()
        client._authenticate()
        client.add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        try:
            client = self._get_forpsi_client()
            if not client._authenticated:
                client._authenticate()
            client.del_txt_record(domain, validation_name, validation)
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")
            # Don't raise the exception - cleanup failures shouldn't break certbot

    def _get_forpsi_client(self) -> "_ForpsiClient":
        if not self.credentials:
            raise errors.PluginError("Plugin has not been prepared.")
        
        admin_site = self.credentials.conf("admin_site")
        username = self.credentials.conf("username")
        password = self.credentials.conf("password")
        
        if not admin_site:
            raise errors.PluginError("Admin site is required. Please specify --dns-forpsi-admin-site or add admin_site to credentials file.")
        if not username:
            raise errors.PluginError("Username is required. Please specify --dns-forpsi-username or add username to credentials file.")
        if not password:
            raise errors.PluginError("Password is required. Please specify --dns-forpsi-password or add password to credentials file.")
        
        return _ForpsiClient(
            admin_site,
            username,
            password,
            self.credentials.conf("totp_secret") if self.credentials.conf("totp_secret") else None,
        )


class _ForpsiClient:
    """
    Encapsulates all communication with the Forpsi admin interface.
    """

    def __init__(self, admin_site: str, username: str, password: str, totp_secret: Optional[str] = None) -> None:
        self.admin_site = admin_site
        self.username = username
        self.password = password
        self.totp_secret = totp_secret
        self.session = requests.Session()
        self.base_url = f"https://{admin_site}"
        self._authenticated = False

    def _generate_otp_code(self) -> Optional[str]:
        """Generate TOTP code from secret if provided"""
        if not self.totp_secret:
            return None
        
        try:
            totp = pyotp.TOTP(self.totp_secret)
            return totp.now()
        except Exception as e:
            raise errors.PluginError(f"Failed to generate TOTP code: {e}")

    def _authenticate(self) -> None:
        """
        Authenticate with Forpsi admin interface using the two-step process
        """
        try:
            # Step 1: Get initial session cookie
            logger.debug("Getting initial session cookie from Forpsi")
            response = self.session.get(
                f"{self.base_url}/index.php",
                headers={
                        'Origin': f'https://{self.admin_site}',
                        'DNT': '1',
                        'Referer': f'https://{self.admin_site}/index.php',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'en-US',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0'
                }
            )
            
            if response.status_code != 200:
                raise errors.PluginError(f"Failed to connect to Forpsi admin site {self.admin_site}. Please check the admin site URL and your internet connection.")

            # Step 2: Login with username and password
            logger.debug("Performing first login step with username and password")
            login_data = {
                'login_action': 'client_login',
                'user_name': self.username,
                'password': self.password,
                'otp_code': ''
            }

            response = self.session.post(
                f"{self.base_url}/index.php",
                data=login_data,
                headers={
                    'Origin': f'https://{self.admin_site}',
                    'DNT': '1',
                    'Referer': f'https://{self.admin_site}/index.php',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0'
                }
            )
            
            if response.status_code != 200:
                raise errors.PluginError(f"Login failed with status {response.status_code}. Please check your credentials and try again.")
            
            # if the response body has an alert javascript, it means the login failed, print the alert message
            if 'alert(' in response.text:
                start = response.text.find('alert(') + len('alert(')
                end = response.text.find(')', start)
                alert_message = response.text[start:end].strip('"')
                raise errors.PluginError(f"Login failed: {alert_message}. Please check your username and password.")

            # Look for <div class="otp_box"> that doesn't have style="display:none"
            otp_box_pattern = r'<div[^>]*class="otp_box"[^>]*(?!.*style="[^"]*display:\s*none)[^>]*>'
            
            if not re.search(otp_box_pattern, response.text):
                raise errors.PluginError("Login failed - unable to proceed to 2FA step. Please check your username and password.")

            # Step 3: If TOTP secret is provided, generate OTP and perform second login step
            otp_code = self._generate_otp_code()
            if otp_code:
                logger.debug("Performing second login step with generated TOTP code")
                otp_data = {
                    'login_action': 'client_login',
                    'user_name': self.username,
                    'password': '',
                    'otp_code': otp_code
                }
                
                response = self.session.post(
                    f"{self.base_url}/index.php",
                    data=otp_data,
                    allow_redirects=False,
                    headers={
                        'Host': self.admin_site,
                        'Connection': 'keep-alive',
                        'Origin': f'https://{self.admin_site}',
                        'DNT': '1',
                        'Referer': f'https://{self.admin_site}/index.php',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'en-US',
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0'
                    }
                )

                if 'alert(' in response.text:
                    start = response.text.find('alert(') + len('alert(')
                    end = response.text.find(')', start)
                    alert_message = response.text[start:end].strip('"')
                    raise errors.PluginError(f"2FA authentication failed: {alert_message}. Please check your TOTP secret.")

                if response.status_code not in [302]:
                    raise errors.PluginError(f"2FA authentication failed with status {response.status_code}. Please check your TOTP secret.")

            # Check if authentication was successful by looking for FAUTH cookie
            fauth_cookie = None
            for cookie in self.session.cookies:
                if cookie.name == 'FAUTH':
                    fauth_cookie = cookie.value
                    break
            
            if not fauth_cookie:
                raise errors.PluginError("Authentication failed - login session not established. Please check your credentials and try again.")
                    
            logger.info("Successfully authenticated with Forpsi")
            self._authenticated = True
            
        except requests.RequestException as e:
            raise errors.PluginError(f"Error during authentication: {e}")

    def _get_domain_id(self, domain: str) -> tuple[str, str]:
        """
        Get domain ID by fetching domain list and parsing HTML for matching domain.
        Handles subdomains by finding the root domain in the account.
        Returns tuple of (domain_id, actual_root_domain)
        """
        logger.debug(f"Looking up domain ID for domain: {domain}")
        
        try:
            # Fetch the domains list page
            logger.debug("Fetching domain list from /domain/domains-list.php")
            response = self.session.get(
                f"{self.base_url}/domain/domains-list.php",
                headers={
                    'Host': self.admin_site,
                    'Connection': 'keep-alive',
                    'Origin': f'https://{self.admin_site}',
                    'DNT': '1',
                    'Referer': f'https://{self.admin_site}/index.php',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0'
                }
            )
            
            if response.status_code != 200:
                raise errors.PluginError(f"Failed to fetch domain list: {response.status_code}")
            
            logger.debug(f"Successfully fetched domain list page ({len(response.text)} bytes)")
            
            # Pattern to match domain links with IDs
            pattern = r'<a\s+href="domains-detail\.php\?new=1&amp;id=(\d+)&amp;[^"]*">([^<]+)</a>'
            matches = re.findall(pattern, response.text)
            
            logger.debug(f"Found {len(matches)} domains in account")
            
            # First try exact match
            for domain_id, found_domain in matches:
                logger.debug(f"Found domain: {found_domain} (ID: {domain_id})")
                if found_domain.strip() == domain:
                    logger.debug(f"Found exact matching domain ID {domain_id} for {domain}")
                    return domain_id, domain
            
            # If no exact match, try to find root domain for subdomains
            # For example, if domain is "sub2.sub1.example.com", try to find "example.com"
            domain_parts = domain.split('.')
            if len(domain_parts) > 2:
                # Try progressively shorter domain suffixes
                for i in range(1, len(domain_parts) - 1):
                    candidate_domain = '.'.join(domain_parts[i:])
                    logger.debug(f"Checking candidate root domain: {candidate_domain}")
                    
                    for domain_id, found_domain in matches:
                        if found_domain.strip() == candidate_domain:
                            logger.info(f"Found root domain ID {domain_id} for {candidate_domain} (from {domain})")
                            return domain_id, candidate_domain
            
            # Log available domains for debugging
            available_domains = [d[1] for d in matches]
            logger.error(f"Domain '{domain}' (or its root domain) not found in account. Available domains: {available_domains}")
            raise errors.PluginError(f"Domain '{domain}' (or its root domain) not found in your Forpsi account. Available domains: {available_domains}")
            
        except requests.RequestException as e:
            raise errors.PluginError(f"Error fetching domain list: {e}")

    def add_txt_record(self, domain: str, name: str, value: str) -> None:
        """
        Add a TXT record using the Forpsi admin interface
        """
        
        # Auto-discover domain ID (this will find the root domain if needed)
        domain_id, root_domain = self._get_domain_id(domain)
        
        try:
            # Extract the record name by removing the root domain suffix
            # name is typically like "_acme-challenge.almafa.snwr.xyz" 
            # root_domain is "snwr.xyz"
            # record_name should be "_acme-challenge.almafa"
            if name.endswith(f".{root_domain}"):
                record_name = name[:-len(f".{root_domain}")]
            else:
                record_name = name
            
            logger.info(f"Adding TXT record '{record_name}' with value '{value}' for domain {domain} (root: {root_domain}, ID: {domain_id})")
            
            # Prepare the POST data for adding TXT record
            # URL parameter for domains-dns.php
            url_encoded = f"/domain/domains-dns.php?id={domain_id}"
            
            post_data = {
                'ak': 'record_add',
                'type': 'TXT',
                'url': url_encoded,
                'srv_service': '',
                'srv_protocol': '_tcp',
                'tlsa_port': '',
                'tlsa_protocol': '_tcp',
                'name': record_name,
                'ttl': '60',
                'mx_priority': '10',
                'srv_priority': '10',
                'srv_weight': '',
                'srv_port': '',
                'flags': '0',
                'tag': 'issue',
                'rdata': value
            }
            
            response = self.session.post(
                f"{self.base_url}/domain/domains-dns.php?id={domain_id}",
                data=post_data,
                headers={
                    'Origin': f'https://{self.admin_site}',
                    'DNT': '1',
                    'Referer': f'https://{self.admin_site}/index.php',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Priority': 'u=0, i',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'same-origin',
                    'Sec-Fetch-User': '?1',
                    'Sec-GPC': '1',
                    'TE': 'trailers',
                    'Upgrade-Insecure-Requests': '1',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0'
                }
            )
            
            if response.status_code != 200:
                raise errors.PluginError(f"Failed to add TXT record: {response.status_code}")
            
            # Verify the record was actually created by checking for its presence in the HTML
            # The record should appear in a table row like:
            # <tr class="rowl editable">
            #   <td class="rowc truncate truncate-dns-domain" ... title="test3.snwr.xyz">
            #     test3.<span style="color:#797979;">snwr.xyz</span></td>
            #   <td class="rowc" width="60">60</td>
            #   <td class="rowc" width="60">TXT</td>
            #   <td class="rowc truncate truncate-dns-rdata" title="ASD">ASD</td>
            
            # Build the expected record name for verification
            if record_name:
                expected_record_display = f"{record_name}.{root_domain}"
            else:
                expected_record_display = root_domain
            
            logger.debug(f"Verifying TXT record creation for '{expected_record_display}'")
            
            # Pattern to match TXT record rows with the expected name and value
            # Look for the record name in the title attribute and TXT type
            # Updated pattern to handle actual HTML structure with spans
            record_pattern = rf'<td[^>]*title="{re.escape(expected_record_display)}"[^>]*>.*?</td>\s*<td[^>]*>60</td>\s*<td[^>]*>TXT</td>\s*<td[^>]*title="{re.escape(value)}"[^>]*>{re.escape(value)}</td>'
            if re.search(record_pattern, response.text, re.DOTALL):
                logger.debug(f"Successfully verified TXT record '{expected_record_display}' with value '{value}' was created")
            else:
                # More lenient check - just look for the record name, TXT type, and value
                name_pattern = rf'<td[^>]*title="{re.escape(expected_record_display)}"[^>]*>'
                txt_pattern = r'<td[^>]*>TXT</td>'
                value_pattern = rf'<td[^>]*title="{re.escape(value)}"[^>]*>{re.escape(value)}</td>'
                
                name_found = re.search(name_pattern, response.text)
                txt_found = re.search(txt_pattern, response.text)
                value_found = re.search(value_pattern, response.text)
                
                if name_found and txt_found and value_found:
                    logger.debug(f"Successfully verified TXT record '{expected_record_display}' with value '{value}' was created (lenient check)")
                elif name_found and txt_found:
                    logger.warning(f"TXT record '{expected_record_display}' appears to be created, but value verification failed")
                else:
                    logger.error(f"Could not verify TXT record creation in HTML response")
                    # Log a snippet of the response for debugging
                    raise errors.PluginError(f"TXT record may not have been created properly - verification failed")
            
            logger.info(f"Successfully added TXT record '{record_name}' for domain {domain}")
            
        except requests.RequestException as e:
            raise errors.PluginError(f"Error adding TXT record: {e}")

    def del_txt_record(self, domain: str, name: str, value: str) -> None:
        """
        Delete a TXT record using the Forpsi admin interface
        """
        # Auto-discover domain ID
        domain_id, root_domain = self._get_domain_id(domain)
        
        try:
            # Extract the record name by removing the root domain suffix
            if name.endswith(f".{root_domain}"):
                record_name = name[:-len(f".{root_domain}")]
            else:
                record_name = name
            
            # Build the expected record name for searching
            if record_name:
                expected_record_display = f"{record_name}.{root_domain}"
            else:
                expected_record_display = root_domain
            
            logger.info(f"Deleting TXT record '{expected_record_display}' with value '{value}' for domain {domain} (root: {root_domain}, ID: {domain_id})")
            
            # First, fetch the DNS page to find the record ID
            logger.debug("Fetching DNS page to find record ID for deletion")
            response = self.session.get(
                f"{self.base_url}/domain/domains-dns.php?id={domain_id}",
                headers={
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0',
                    'Referer': f'{self.base_url}/index.php'
                }
            )
            
            if response.status_code != 200:
                raise errors.PluginError(f"Failed to fetch DNS page: {response.status_code}")
            
            # Pattern to match ALL delete_row JavaScript calls with record IDs
            delete_pattern = rf'href="javascript:delete_row\((\d+),\s*\'[^\']*{re.escape(expected_record_display)}\s+TXT[^\']*\'\);?"'
            
            matches = re.findall(delete_pattern, response.text)
            if not matches:
                # Try a more lenient pattern - just look for TXT records with the name
                delete_pattern = rf'href="javascript:delete_row\((\d+),\s*\'[^\']*{re.escape(record_name)}[^\']*TXT[^\']*\'\);?"'
                matches = re.findall(delete_pattern, response.text)
            
            if not matches:
                logger.debug(f"Could not find TXT record '{expected_record_display}' to delete, assuming it has been already deleted")
                return
            
            logger.debug(f"Found {len(matches)} TXT record(s) with name '{expected_record_display}' to delete")
            
            # Delete all matching records
            deleted_count = 0
            for record_id in matches:
                logger.debug(f"Deleting TXT record with ID: {record_id}")
                
                post_data = {
                    'ak': 'record_del',
                    'r_ID': record_id
                }
                
                response = self.session.post(
                    f"{self.base_url}/domain/domains-dns.php?id={domain_id}",
                    data=post_data,
                    headers={
                        'Origin': f'https://{self.admin_site}',
                        'DNT': '1',
                        'Referer': f'https://{self.admin_site}/domain/domains-dns.php?id={domain_id}',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'en-US',
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0'
                    }
                )
                
                if response.status_code != 200:
                    logger.error(f"Failed to delete TXT record with ID {record_id}: {response.status_code}")
                    continue
                
                deleted_count += 1
                logger.debug(f"Successfully deleted TXT record with ID: {record_id}")
            
            if deleted_count == 0:
                raise errors.PluginError(f"Failed to delete any TXT records for '{expected_record_display}'")
            
            # Verify the records were actually deleted by checking they're no longer in the HTML
            # Fetch the page again to check
            response = self.session.get(
                f"{self.base_url}/domain/domains-dns.php?id={domain_id}",
                headers={
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0',
                    'Referer': f'{self.base_url}/index.php'
                }
            )
            
            if response.status_code == 200:
                delete_pattern = rf'href="javascript:delete_row\(\d+,\s*\'[^\']*{re.escape(expected_record_display)}\s+TXT[^\']*\'\);?"'
                remaining_matches = re.findall(delete_pattern, response.text)
                
                if remaining_matches:
                    logger.warning(f"Found {len(remaining_matches)} TXT record(s) still present after deletion")
                else:
                    logger.debug(f"Successfully verified all TXT records '{expected_record_display}' were deleted")
            
            logger.info(f"Successfully deleted {deleted_count} TXT record(s) '{expected_record_display}' for domain {domain}")
            
        except requests.RequestException as e:
            raise errors.PluginError(f"Error deleting TXT record: {e}")