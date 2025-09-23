#!/usr/bin/env python3
"""
Unit tests for ShellAI model output validation.

This test suite loads test prompts from a YAML file and validates
that the model generates appropriate shell commands.
"""

import os
import sys
import re
import yaml
import pytest
from unittest.mock import patch, MagicMock

# Add the parent directory to the path to import shellai
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shellai import ShellAI

def load_test_cases(test_data_file):
    """Load test cases from the YAML file."""
    try:
        with open(test_data_file, 'r') as file:
            data = yaml.safe_load(file)
            return data.get('test_cases', [])
    except FileNotFoundError:
        pytest.skip(f"Test data file not found: {test_data_file}")
    except yaml.YAMLError as e:
        pytest.fail(f"Error parsing YAML file: {e}")


class TestShellAIOutput:
    """Test class for validating ShellAI model output."""
    
    @classmethod
    def setup_class(cls):
        """Set up the test class with shared resources."""
        cls.test_data_file = os.path.join(os.path.dirname(__file__), 'test_prompts.yaml')
        cls.shellai = ShellAI()
        cls.shellai.load_model()
    
    @pytest.mark.parametrize("test_case", load_test_cases("test_prompts.yaml"))
    def test_model_output_patterns(self, test_case):
        """Test that model output contains expected patterns."""
        test_name = test_case['name']
        description = test_case.get('description', '')
        prompt = test_case['prompt']
        expected_patterns = test_case.get('expected_patterns', [])

        generated_command = self.shellai.generate_command(prompt)

        # Validate that the command is not empty
        assert generated_command, f"Generated command is empty for test: {test_name}"
        
        # Check expected patterns
        for pattern in expected_patterns:
            assert re.search(pattern, generated_command, re.IGNORECASE), (
                f"Expected pattern '{pattern}' not found in generated command "
                f"'{generated_command}' for test: {test_name} ({description})"
            )

if __name__ == "__main__":
    # Run tests when script is executed directly
    pytest.main([__file__, "-v"])
