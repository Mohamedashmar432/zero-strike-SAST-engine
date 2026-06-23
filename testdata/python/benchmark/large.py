import os
import sys
import json
import hashlib
import subprocess
import threading
import time
import re
import socket
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

# Configuration constants
MAX_RETRIES = 3
DEFAULT_TIMEOUT = 30
BASE_URL = "https://example.com"
MAX_CONNECTIONS = 100
BUFFER_SIZE = 4096
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class Config:
    """Application configuration manager."""

    def __init__(self, path: str):
        self.path = path
        self.data: Dict[str, Any] = {}
        self._loaded = False

    def load(self) -> "Config":
        with open(self.path) as f:
            self.data = json.load(f)
        self._loaded = True
        return self

    def get(self, key: str, default=None):
        return self.data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self.data[key] = value

    def save(self) -> None:
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2)

    def is_loaded(self) -> bool:
        return self._loaded

    def keys(self) -> List[str]:
        return list(self.data.keys())


class Logger:
    """Application logger wrapper."""

    def __init__(self, name: str):
        self.name = name
        self.level = "INFO"
        self._logger = logging.getLogger(name)

    def info(self, message: str) -> None:
        print(f"[INFO] {self.name}: {message}")

    def error(self, message: str) -> None:
        print(f"[ERROR] {self.name}: {message}")

    def debug(self, message: str) -> None:
        if self.level == "DEBUG":
            print(f"[DEBUG] {self.name}: {message}")

    def warning(self, message: str) -> None:
        print(f"[WARN] {self.name}: {message}")

    def set_level(self, level: str) -> None:
        self.level = level


class FileProcessor:
    """Handles file reading, writing, and transformation."""

    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.processed: List[str] = []

    def read_text(self, filename: str) -> str:
        path = os.path.join(self.base_dir, filename)
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    def write_text(self, filename: str, content: str) -> None:
        path = os.path.join(self.base_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        self.processed.append(filename)

    def list_files(self, extension: str = "") -> List[str]:
        entries = os.listdir(self.base_dir)
        if extension:
            entries = [e for e in entries if e.endswith(extension)]
        return entries

    def file_exists(self, filename: str) -> bool:
        return os.path.exists(os.path.join(self.base_dir, filename))

    def delete_file(self, filename: str) -> bool:
        path = os.path.join(self.base_dir, filename)
        if os.path.exists(path):
            os.remove(path)
            return True
        return False

    def copy_file(self, src: str, dst: str) -> None:
        content = self.read_text(src)
        self.write_text(dst, content)

    def get_size(self, filename: str) -> int:
        path = os.path.join(self.base_dir, filename)
        return os.path.getsize(path)


class NetworkClient:
    """Simple HTTP-like network client."""

    def __init__(self, host: str, port: int, timeout: int = DEFAULT_TIMEOUT):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._socket: Optional[socket.socket] = None

    def connect(self) -> bool:
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(self.timeout)
            self._socket.connect((self.host, self.port))
            return True
        except socket.error:
            return False

    def send(self, data: bytes) -> int:
        if self._socket is None:
            raise RuntimeError("Not connected")
        return self._socket.send(data)

    def receive(self, size: int = BUFFER_SIZE) -> bytes:
        if self._socket is None:
            raise RuntimeError("Not connected")
        return self._socket.recv(size)

    def disconnect(self) -> None:
        if self._socket:
            self._socket.close()
            self._socket = None

    def is_connected(self) -> bool:
        return self._socket is not None


class DataProcessor:
    """Processes and transforms data collections."""

    def __init__(self):
        self.cache: Dict[str, Any] = {}
        self.stats: Dict[str, int] = {"processed": 0, "errors": 0, "skipped": 0}

    def process_list(self, items: List[Any]) -> List[Any]:
        results = []
        for item in items:
            try:
                result = self._transform(item)
                results.append(result)
                self.stats["processed"] += 1
            except Exception:
                self.stats["errors"] += 1
        return results

    def _transform(self, item: Any) -> Any:
        if isinstance(item, str):
            return item.strip().lower()
        if isinstance(item, (int, float)):
            return item * 2
        if isinstance(item, dict):
            return {k: self._transform(v) for k, v in item.items()}
        if isinstance(item, list):
            return [self._transform(i) for i in item]
        return item

    def filter_items(self, items: List[Any], predicate) -> List[Any]:
        return [item for item in items if predicate(item)]

    def group_by(self, items: List[Dict], key: str) -> Dict[str, List]:
        groups: Dict[str, List] = {}
        for item in items:
            value = str(item.get(key, "unknown"))
            if value not in groups:
                groups[value] = []
            groups[value].append(item)
        return groups

    def get_stats(self) -> Dict[str, int]:
        return dict(self.stats)

    def reset_stats(self) -> None:
        self.stats = {"processed": 0, "errors": 0, "skipped": 0}

    def cache_get(self, key: str) -> Optional[Any]:
        return self.cache.get(key)

    def cache_set(self, key: str, value: Any) -> None:
        self.cache[key] = value

    def cache_clear(self) -> None:
        self.cache.clear()


class TaskQueue:
    """Thread-safe task queue for background processing."""

    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self._queue: List[Any] = []
        self._lock = threading.Lock()
        self._workers: List[threading.Thread] = []
        self._running = False

    def enqueue(self, task) -> None:
        with self._lock:
            self._queue.append(task)

    def dequeue(self) -> Optional[Any]:
        with self._lock:
            if self._queue:
                return self._queue.pop(0)
            return None

    def size(self) -> int:
        with self._lock:
            return len(self._queue)

    def start(self) -> None:
        self._running = True
        for i in range(self.max_workers):
            t = threading.Thread(target=self._worker_loop, daemon=True)
            self._workers.append(t)
            t.start()

    def stop(self) -> None:
        self._running = False

    def _worker_loop(self) -> None:
        while self._running:
            task = self.dequeue()
            if task is not None:
                try:
                    task()
                except Exception:
                    pass
            else:
                time.sleep(0.01)


class Validator:
    """Input validation utilities."""

    EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    URL_PATTERN = re.compile(r"^https?://[^\s/$.?#].[^\s]*$")

    @staticmethod
    def validate_email(email: str) -> bool:
        return bool(Validator.EMAIL_PATTERN.match(email))

    @staticmethod
    def validate_url(url: str) -> bool:
        return bool(Validator.URL_PATTERN.match(url))

    @staticmethod
    def validate_length(value: str, min_len: int, max_len: int) -> bool:
        return min_len <= len(value) <= max_len

    @staticmethod
    def validate_int_range(value: int, min_val: int, max_val: int) -> bool:
        return min_val <= value <= max_val

    @staticmethod
    def sanitize_string(value: str) -> str:
        return re.sub(r"[<>\"'&]", "", value)

    @staticmethod
    def is_numeric(value: str) -> bool:
        try:
            float(value)
            return True
        except ValueError:
            return False


class HashHelper:
    """Cryptographic hashing utilities."""

    @staticmethod
    def sha256(data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def sha512(data: str) -> str:
        return hashlib.sha512(data.encode()).hexdigest()

    @staticmethod
    def md5_file(path: str) -> str:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(BUFFER_SIZE), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def sha256_file(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(BUFFER_SIZE), b""):
                h.update(chunk)
        return h.hexdigest()


class PathHelper:
    """Path manipulation and filesystem utilities."""

    def __init__(self, root: str):
        self.root = Path(root)

    def resolve(self, *parts: str) -> Path:
        return self.root.joinpath(*parts).resolve()

    def ensure_dir(self, *parts: str) -> Path:
        path = self.resolve(*parts)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def glob(self, pattern: str) -> List[Path]:
        return list(self.root.glob(pattern))

    def relative(self, path: Path) -> str:
        return str(path.relative_to(self.root))

    def is_safe(self, path: Path) -> bool:
        try:
            path.resolve().relative_to(self.root.resolve())
            return True
        except ValueError:
            return False


class RetryHelper:
    """Retry logic with exponential backoff."""

    def __init__(self, max_attempts: int = MAX_RETRIES, base_delay: float = 1.0):
        self.max_attempts = max_attempts
        self.base_delay = base_delay

    def execute(self, func, *args, **kwargs):
        last_error = None
        for attempt in range(self.max_attempts):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_error = e
                if attempt < self.max_attempts - 1:
                    delay = self.base_delay * (2 ** attempt)
                    time.sleep(delay)
        raise RuntimeError(f"All {self.max_attempts} attempts failed") from last_error

    def with_timeout(self, func, timeout: float, *args, **kwargs):
        result = [None]
        error = [None]

        def run():
            try:
                result[0] = func(*args, **kwargs)
            except Exception as e:
                error[0] = e

        t = threading.Thread(target=run)
        t.start()
        t.join(timeout)
        if t.is_alive():
            raise TimeoutError(f"Function timed out after {timeout}s")
        if error[0]:
            raise error[0]
        return result[0]


class CommandRunner:
    """Safe command execution wrapper."""

    def __init__(self, working_dir: Optional[str] = None):
        self.working_dir = working_dir
        self.history: List[Dict[str, Any]] = []

    def run(self, command: List[str], capture: bool = True) -> Tuple[int, str, str]:
        result = subprocess.run(
            command,
            capture_output=capture,
            text=True,
            cwd=self.working_dir,
        )
        entry = {
            "command": command,
            "returncode": result.returncode,
            "stdout": result.stdout if capture else "",
            "stderr": result.stderr if capture else "",
        }
        self.history.append(entry)
        return result.returncode, result.stdout, result.stderr

    def run_and_check(self, command: List[str]) -> str:
        code, stdout, stderr = self.run(command)
        if code != 0:
            raise RuntimeError(f"Command failed: {stderr}")
        return stdout

    def clear_history(self) -> None:
        self.history.clear()

    def last_exit_code(self) -> Optional[int]:
        if self.history:
            return self.history[-1]["returncode"]
        return None


class MetricsCollector:
    """Collects and aggregates runtime metrics."""

    def __init__(self):
        self._counters: Dict[str, int] = {}
        self._timings: Dict[str, List[float]] = {}
        self._start = time.time()

    def increment(self, name: str, amount: int = 1) -> None:
        self._counters[name] = self._counters.get(name, 0) + amount

    def record_timing(self, name: str, duration: float) -> None:
        if name not in self._timings:
            self._timings[name] = []
        self._timings[name].append(duration)

    def get_count(self, name: str) -> int:
        return self._counters.get(name, 0)

    def get_avg_timing(self, name: str) -> Optional[float]:
        timings = self._timings.get(name, [])
        if not timings:
            return None
        return sum(timings) / len(timings)

    def get_p95_timing(self, name: str) -> Optional[float]:
        timings = self._timings.get(name, [])
        if not timings:
            return None
        sorted_timings = sorted(timings)
        idx = int(len(sorted_timings) * 0.95)
        return sorted_timings[min(idx, len(sorted_timings) - 1)]

    def uptime(self) -> float:
        return time.time() - self._start

    def summary(self) -> Dict[str, Any]:
        return {
            "counters": dict(self._counters),
            "uptime_seconds": self.uptime(),
            "timing_keys": list(self._timings.keys()),
        }


def compute_checksum(data: bytes) -> str:
    """Compute SHA-256 checksum of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def load_json_file(path: str) -> Any:
    """Load and parse a JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json_file(path: str, data: Any, indent: int = 2) -> None:
    """Serialize data to a JSON file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent)


def find_files(directory: str, pattern: str) -> List[str]:
    """Recursively find files matching a glob pattern."""
    root = Path(directory)
    return [str(p) for p in root.glob(pattern)]


def chunk_list(items: List[Any], size: int) -> List[List[Any]]:
    """Split a list into chunks of the given size."""
    return [items[i : i + size] for i in range(0, len(items), size)]


def flatten(nested: List[List[Any]]) -> List[Any]:
    """Flatten a list of lists into a single list."""
    result = []
    for sublist in nested:
        result.extend(sublist)
    return result


def merge_dicts(*dicts: Dict) -> Dict:
    """Merge multiple dictionaries, later ones take precedence."""
    result: Dict = {}
    for d in dicts:
        result.update(d)
    return result


def retry(func, attempts: int = MAX_RETRIES, delay: float = 0.5):
    """Simple retry decorator helper."""
    for i in range(attempts):
        try:
            return func()
        except Exception:
            if i == attempts - 1:
                raise
            time.sleep(delay)


def format_bytes(size: int) -> str:
    """Human-readable file size."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size //= 1024
    return f"{size} PB"


def parse_env_file(path: str) -> Dict[str, str]:
    """Parse a .env file into a dictionary."""
    result: Dict[str, str] = {}
    if not os.path.exists(path):
        return result
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                result[key.strip()] = value.strip()
    return result


def deep_get(data: Dict, *keys, default=None):
    """Safely get a nested value from a dictionary."""
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
        if current is default:
            return default
    return current


def truncate(text: str, max_length: int, suffix: str = "...") -> str:
    """Truncate a string to max_length characters."""
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)] + suffix


def camel_to_snake(name: str) -> str:
    """Convert CamelCase to snake_case."""
    s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def snake_to_camel(name: str) -> str:
    """Convert snake_case to CamelCase."""
    components = name.split("_")
    return components[0] + "".join(x.title() for x in components[1:])


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a TCP port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.error, OSError):
        return False


def get_env(key: str, default: str = "") -> str:
    """Get an environment variable with a default."""
    return os.environ.get(key, default)


def require_env(key: str) -> str:
    """Get a required environment variable, raise if missing."""
    value = os.environ.get(key)
    if value is None:
        raise EnvironmentError(f"Required environment variable '{key}' is not set")
    return value


# Entry point
if __name__ == "__main__":
    logger = Logger("main")
    metrics = MetricsCollector()

    logger.info("Starting large benchmark script")
    metrics.increment("start")

    config_path = get_env("CONFIG_PATH", "config.json")
    if os.path.exists(config_path):
        cfg = Config(config_path).load()
        logger.info(f"Loaded config from {config_path}")
    else:
        logger.warning(f"Config not found at {config_path}, using defaults")

    processor = DataProcessor()
    sample_data = [1, 2, 3, "hello", "world", {"key": "value"}, [1, 2, 3]]
    results = processor.process_list(sample_data)
    metrics.increment("items_processed", len(results))

    validator = Validator()
    test_emails = ["user@example.com", "invalid-email", "admin@domain.org"]
    for email in test_emails:
        if validator.validate_email(email):
            logger.info(f"Valid email: {email}")
        else:
            logger.debug(f"Invalid email: {email}")

    hasher = HashHelper()
    checksum = hasher.sha256("benchmark test data")
    logger.info(f"Checksum: {checksum[:16]}...")

    runner = CommandRunner()
    code, out, err = runner.run(["python", "--version"])
    if code == 0:
        logger.info(f"Python version: {out.strip()}")

    chunked = chunk_list(list(range(50)), 10)
    flat = flatten(chunked)
    assert len(flat) == 50

    logger.info(f"Metrics summary: {metrics.summary()}")
    logger.info("Benchmark script complete")
