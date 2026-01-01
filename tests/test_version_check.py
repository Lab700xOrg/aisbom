import pytest
from unittest.mock import patch, MagicMock
from aisbom.version_check import check_latest_version

@patch("aisbom.version_check.requests.get")
@patch("aisbom.version_check.importlib.metadata.version")
def test_check_latest_version_update_available(mock_version, mock_get):
    """
    Test that functionality works when an update IS available.
    """
    # 1. Mock current version
    mock_version.return_value = "0.4.0"

    # 2. Mock API response
    mock_response = MagicMock()
    mock_response.json.return_value = {"latest": "0.5.0"}
    mock_response.raise_for_status.return_value = None
    mock_get.return_value = mock_response

    # 3. Call
    result = check_latest_version()

    # 4. Assert
    assert result == "0.5.0"
    mock_get.assert_called_once()
    assert "User-Agent" in mock_get.call_args[1]["headers"]
    assert "aisbom-cli/0.4.0" in mock_get.call_args[1]["headers"]["User-Agent"]

@patch("aisbom.version_check.requests.get")
@patch("aisbom.version_check.importlib.metadata.version")
def test_check_latest_version_no_update(mock_version, mock_get):
    """
    Test that it returns None when current version >= latest.
    """
    mock_version.return_value = "0.4.1"
    
    mock_response = MagicMock()
    mock_response.json.return_value = {"latest": "0.4.1"}
    mock_get.return_value = mock_response

    result = check_latest_version()
    assert result is None

@patch("aisbom.version_check.os.getenv")
def test_privacy_compliance(mock_getenv):
    """
    Test that it aborts immediately if NO_TELEMETRY is set.
    """
    mock_getenv.return_value = "1" # Simulate env var set
    
    # We strip mocking requests here because it shouldn't even reach requests
    with patch("aisbom.version_check.requests.get") as mock_get:
        result = check_latest_version()
        assert result is None
        mock_get.assert_not_called()

@patch("aisbom.version_check.requests.get")
def test_network_failure_safety(mock_get):
    """
    Test that it handles network exceptions gracefully (returns None).
    """
    mock_get.side_effect = Exception("Connection Timeout")
    
    result = check_latest_version()
    assert result is None
