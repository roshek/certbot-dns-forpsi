"""
Certbot DNS Forpsi plugin

This package provides a Certbot DNS authenticator plugin for Forpsi DNS provider.
It enables automated certificate generation using DNS-01 challenge validation
through the Forpsi admin interface.
"""

__version__ = "0.1.0"
__author__ = "Ákos Szabados"
__email__ = "public.repo.uncover565@passmail.net"

from .dns_forpsi import Authenticator

__all__ = ["Authenticator"]