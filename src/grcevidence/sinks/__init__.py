"""Evidence sinks."""

from grcevidence.sinks.base import Sink, SinkError
from grcevidence.sinks.http import HttpSink
from grcevidence.sinks.local import LocalSink
from grcevidence.sinks.s3 import S3Sink

__all__ = ["HttpSink", "LocalSink", "S3Sink", "Sink", "SinkError"]
