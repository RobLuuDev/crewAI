from datetime import datetime
import json
import logging
import os
from typing import Any, TypedDict

from typing_extensions import Unpack

from crewai.utilities.lock_store import lock as store_lock


logger = logging.getLogger(__name__)


class LogEntry(TypedDict, total=False):
    """TypedDict for log entry kwargs with optional fields for flexibility."""

    task_name: str
    task: str
    agent: str
    status: str
    output: str
    input: str
    message: str
    level: str
    crew: str
    flow: str
    tool: str
    error: str
    duration: float
    metadata: dict[str, Any]


class FileHandler:
    """Handler for file operations supporting both JSON and text-based logging.

    Attributes:
        _path: The path to the log file.
    """

    def __init__(self, file_path: bool | str) -> None:
        """Initialize the FileHandler with the specified file path.
        Args:
            file_path: Path to the log file or boolean flag.
        """
        self._initialize_path(file_path)

    def _initialize_path(self, file_path: bool | str) -> None:
        """Initialize the file path based on the input type.

        Args:
            file_path: Path to the log file or boolean flag.

        Raises:
            ValueError: If file_path is neither a string nor a boolean.
        """
        if file_path is True:  # File path is boolean True
            self._path = os.path.join(os.curdir, "logs.txt")

        elif isinstance(file_path, str):  # File path is a string
            if file_path.endswith((".json", ".txt")):
                self._path = (
                    file_path  # No modification if the file ends with .json or .txt
                )
            else:
                self._path = (
                    file_path + ".txt"
                )  # Append .txt if the file doesn't end with .json or .txt

        else:
            raise ValueError(
                "file_path must be a string or boolean."
            )  # Handle the case where file_path isn't valid

    def log(self, **kwargs: Unpack[LogEntry]) -> None:
        """Log data with structured fields.

        Keyword Args:
            task_name: Name of the task.
            task: Description of the task.
            agent: Name of the agent.
            status: Status of the operation.
            output: Output data.
            input: Input data.
            message: Log message.
            level: Log level (e.g., INFO, ERROR).
            crew: Name of the crew.
            flow: Name of the flow.
            tool: Name of the tool used.
            error: Error message if any.
            duration: Duration of the operation in seconds.
            metadata: Additional metadata as a dictionary.

        Raises:
            ValueError: If logging fails.
        """
        try:
            with store_lock(f"file:{os.path.realpath(self._path)}"):
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_entry = {"timestamp": now, **kwargs}

                if self._path.endswith(".json"):
                    # Append log in JSON format
                    try:
                        # Try reading existing content to avoid overwriting
                        with open(self._path, encoding="utf-8") as read_file:
                            existing_data = json.load(read_file)
                            existing_data.append(log_entry)
                    except (json.JSONDecodeError, FileNotFoundError):
                        # If no valid JSON or file doesn't exist, start with an empty list
                        existing_data = [log_entry]

                    with open(self._path, "w", encoding="utf-8") as write_file:
                        json.dump(existing_data, write_file, indent=4)
                        write_file.write("\n")

                else:
                    # Append log in plain text format
                    message = (
                        f"{now}: "
                        + ", ".join(
                            [f'{key}="{value}"' for key, value in kwargs.items()]
                        )
                        + "\n"
                    )
                    with open(self._path, "a", encoding="utf-8") as file:
                        file.write(message)

        except Exception as e:
            raise ValueError(f"Failed to log message: {e!s}") from e


class PickleHandler:
    """Handler for saving and loading crew state using JSON serialization.

    Replaces the former pickle-based implementation to eliminate the risk of
    arbitrary code execution via crafted .pkl files (CWE-502). Legacy .pkl
    files are intentionally not loaded; call initialize_file() to start fresh.

    Attributes:
        file_path: The path to the JSON data file.
    """

    def __init__(self, file_name: str) -> None:
        """Initialize the PickleHandler with the name of the file where data will be stored.

        The file will be saved in the current directory.

        Args:
            file_name: The name of the file for saving and loading data.
                       Legacy .pkl extensions are automatically remapped to .json.
        """
        if file_name.endswith(".pkl"):
            file_name = file_name[:-4] + ".json"
        elif not file_name.endswith(".json"):
            file_name += ".json"

        self.file_path = os.path.join(os.getcwd(), file_name)

    def initialize_file(self) -> None:
        """Initialize the file with an empty dictionary and overwrite any existing data."""
        self.save({})

    def save(self, data: Any) -> None:
        """Save the data to the specified file using JSON serialization.

        Args:
          data: The data to be saved to the file. Must be JSON-serializable.

        Raises:
            TypeError: If data contains values that cannot be serialized to JSON.
        """
        with store_lock(f"file:{os.path.realpath(self.file_path)}"):
            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump(data, f)

    def load(self) -> Any:
        """Load the data from the specified file.

        Returns:
            The data loaded from the file, or an empty dict if the file does not exist
            or is empty.
        """
        legacy_pkl = self.file_path[:-5] + ".pkl"
        if os.path.exists(legacy_pkl):
            logger.warning(
                "Legacy pickle file found at %s. It will not be loaded to prevent "
                "unsafe deserialization (CWE-502). Delete it and call "
                "initialize_file() to reset state.",
                legacy_pkl,
            )

        with store_lock(f"file:{os.path.realpath(self.file_path)}"):
            if (
                not os.path.exists(self.file_path)
                or os.path.getsize(self.file_path) == 0
            ):
                return {}

            with open(self.file_path, encoding="utf-8") as file:
                try:
                    return json.load(file)
                except (json.JSONDecodeError, EOFError):
                    return {}
