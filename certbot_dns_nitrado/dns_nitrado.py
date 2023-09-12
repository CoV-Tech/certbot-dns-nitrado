"""DNS Authenticator for Nitrado."""
import logging

import zope.interface

from certbot import interfaces
from certbot.plugins import dns_common


import requests

logger = logging.getLogger(__name__)

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Nitrado

    This Authenticator uses the Nitrado REST API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using Nitrado for DNS)."
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=100
        )
        add("credentials", help="Nitrado credentials INI file.")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
            + "the Nitrado REST API."
        )

    def _setup_credentials(self):
        self._configure_file('credentials',
                             'Absolute path to Nitrado credentials INI file')
        dns_common.validate_file_permissions(self.conf('credentials'))
        self.credentials = self._configure_credentials(
            "credentials",
            "Nitrado credentials INI file",
            {
                "token": "Token for the Nitrado API (Token Long Life).",
            },
        )

    def _remove_subdomains(self, domain):
        split_domain = domain.split('.')
        return f'{split_domain[-2]}.{split_domain[-1]}'

    def _perform(self, domain, validation_name, validation):
        self._get_nitrado_client().add_txt_record(
            self._remove_subdomains(domain), validation_name, validation
        )

    def _cleanup(self, domain, validation_name, validation):
        self._get_nitrado_client().del_txt_record(
            self._remove_subdomains(domain), validation_name, validation
        )

    def _get_nitrado_client(self):
        return _NitradoLexiconClient(
            self.credentials.conf("token"),
            self.ttl
        )


class _NitradoLexiconClient:
    """
    Encapsulates all communication with the Njalla API via Lexicon.
    """

    def __init__(self, api_token, ttl):
        self.ttl = ttl
        self.api_token = api_token


    def add_txt_record(self, domain: str, name: str, content: str):
        if not name.endswith(domain):
            raise RuntimeError('Invalid domain')
        name = name[:-(1+len(domain))]
        requests.post(f'https://api.nitrado.net/domain/{domain}/records', json={
            'name': name,
            'type': 'TXT',
            'content': content,
            'ttl': self.ttl
        }, headers= {
            'Authorization': 'Bearer ' + self.api_token
        })
    
    def del_txt_record(self, domain: str, name: str, content: str):
        if not name.endswith(domain):
            raise RuntimeError('Invalid domain')
        name = name[:-(1+len(domain))]
        requests.delete(f'https://api.nitrado.net/domain/{domain}/records', json={
            'name': name,
            'type': 'TXT',
            'content': content
        }, headers= {
            'Authorization': 'Bearer ' + self.api_token
        })