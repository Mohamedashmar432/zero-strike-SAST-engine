# ZS-PY-050: yaml.unsafe_load constructs arbitrary Python objects
import yaml


def parse_config(stream):
    return yaml.unsafe_load(stream)
