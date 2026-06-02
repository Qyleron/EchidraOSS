import uuid

from classifier.features.session import SessionFeatures


def make_features(**overrides):
    data = {
        "session_id": uuid.uuid4(),
        "protocol": "tcp_shell",
        "persona_id": "generic_linux",
        "end_reason": "logout",
        "duration_seconds": 10.0,
        "command_count": 4,
        "commands_per_minute": 24.0,
        "unique_command_count": 3,
        "repeated_command_count": 1,
        "discovery_command_count": 3,
        "file_read_count": 1,
        "sensitive_file_read_count": 1,
        "decoy_files_surfaced": ["/etc/passwd"],
        "decoy_files_surfaced_count": 1,
        "exit_command_present": False,
        "inter_command_intervals_seconds": [1.0, 2.0, 3.0],
        "average_inter_command_interval_seconds": 2.0,
        "command_names": ["whoami", "ls", "cat", "ls"],
    }
    data.update(overrides)
    return SessionFeatures.parse_obj(data)
