"""
Cryptanalib - A series of useful functions for cryptanalysis
by Daniel "unicornFurnace" Crowley

dependencies - PyCryptodome
"""

__all__ = ['helpers', 'modern', 'classical', 'hash_length_extension', 'hashes']

from .helpers import *
from .modern import *
from .classical import *
from .hash_length_extension import *
from .hashes import *
import pydoc
import re

def show_help(object_to_help_with):
    help_contents = pydoc.render_doc(object_to_help_with)
    help_contents = re.sub(r'={.*}', '={...trimmed...}', help_contents)
    help_contents = re.sub(r'=\[.*\]', '=[...trimmed...]', help_contents)
    pydoc.pager(help_contents)
