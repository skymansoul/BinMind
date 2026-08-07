import os
import sys
_MOD_DEBUG = False
import unittest
import json
from unittest.mock import patch, mock_open

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.cwe_mapper import CWEMapper, CWEMapping, CWEClassification


