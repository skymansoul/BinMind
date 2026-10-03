
import pytest


class TestNewModuleImports:
    """Verify new modules can be imported."""

    def test_import_attack_surface(self):
        """Test attack_surface module."""
        from modules import attack_surface
        assert attack_surface is not None

    def test_import_poc_generator(self):
        """Test poc_generator module."""
        from modules import poc_generator
        assert poc_generator is not None

    def test_import_pii_scanner(self):
        """Test pii_scanner module."""
        from modules import pii_scanner
        assert pii_scanner is not None


