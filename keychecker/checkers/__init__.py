"""Registry of all available service checkers.

To add a new service, create a module in this package with a ``BaseChecker``
subclass and register it in ``_CHECKER_CLASSES`` below.
"""

from __future__ import annotations

from typing import Dict, List, Type

from .base import BaseChecker
from .binaryedge import BinaryEdgeChecker
from .censys import CensysChecker
from .fofa import FofaChecker
from .greynoise import GreyNoiseChecker
from .hunter import HunterChecker
from .securitytrails import SecurityTrailsChecker
from .shodan import ShodanChecker
from .virustotal import VirusTotalChecker
from .zoomeye import ZoomEyeChecker

_CHECKER_CLASSES: List[Type[BaseChecker]] = [
    ShodanChecker,
    CensysChecker,
    FofaChecker,
    SecurityTrailsChecker,
    VirusTotalChecker,
    BinaryEdgeChecker,
    ZoomEyeChecker,
    HunterChecker,
    GreyNoiseChecker,
]

#: Mapping of service name -> checker class.
REGISTRY: Dict[str, Type[BaseChecker]] = {cls.name: cls for cls in _CHECKER_CLASSES}


def get_checker(name: str) -> Type[BaseChecker]:
    return REGISTRY[name]


def all_names() -> List[str]:
    return list(REGISTRY.keys())


__all__ = ["BaseChecker", "REGISTRY", "get_checker", "all_names"]
