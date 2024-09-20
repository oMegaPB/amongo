from typing import TypeVar, Dict, Any, Union, Literal, TypeAlias

from bson import SON

T = TypeVar("T")
xJsonT: TypeAlias = Dict[str, Any]
Document: TypeAlias = Union[xJsonT, SON]
OP_T: TypeAlias = Literal[2004, 2013]