"""Evidence subpackage: activity evidence collection and matching."""
from .cloudtrail import (
    ActivityEvent,
    collect_activity_events,
    filter_window,
    parse_cloudtrail_event,
    summarize_events,
)

__all__ = [
    "ActivityEvent",
    "collect_activity_events",
    "filter_window",
    "parse_cloudtrail_event",
    "summarize_events",
]
