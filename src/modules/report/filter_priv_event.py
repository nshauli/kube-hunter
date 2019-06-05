import logging
import re

from __main__ import config
from src.core.events import handler
from src.core.events.types import Event, Service, Vulnerability, HuntFinished, HuntStarted, EventFilterBase
from src.modules.hunting.kubelet import PrivilegedContainers


@handler.subscribe(PrivilegedContainers)
class PrivilegedVulnerabilityFilter(EventFilterBase):
    def __init__(self,event):
        EventFilterBase.__init__(self, event)
    def execute(self):
        event = self.event
        
        if re.match("aqua", self.event.evidence):
            event = None

        return event