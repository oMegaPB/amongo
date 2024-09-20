import datetime
from typing import Generic, List

from attrs import field, define

from .typings import T

@define
class Response(Generic[T]):
    value: T = field(repr=False)
    n_documents: int = field(init=False, default=0)

    def __attrs_post_init__(self) -> None:
        if self.value is None: 
            return
        self.n_documents = len(self.value) if isinstance(self.value, list) else 1

@define
class HelloResult:
    local_time: datetime.datetime
    connection_id: int
    read_only: bool
    requires_auth: bool = field(init=False, repr=False)
    mechanisms: List[str] = field(default=None)

    def __attrs_post_init__(self) -> None:
        self.requires_auth = self.mechanisms is not None and len(self.mechanisms) > 0
