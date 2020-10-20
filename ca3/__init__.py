"""
Cryptanalib - A series of useful functions for cryptanalysis
by Daniel "unicornFurnace" Crowley

dependencies - PyCryptodome
"""

__all__ = ['helpers', 'modern', 'classical']

from .helpers import *
from .modern import *
from .classical import *
import pydoc
import re

def show_help(object_to_help_with):
    help_contents = pydoc.render_doc(object_to_help_with)
    help_contents = re.sub(r'={.*}', '={...trimmed...}', help_contents)
    help_contents = re.sub(r'=\[.*\]', '=[...trimmed...]', help_contents)
    pydoc.pager(help_contents)
