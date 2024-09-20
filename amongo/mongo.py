from __future__ import annotations

import os
import sys
import random
import struct
import asyncio
from typing import (
    Mapping,
    Optional,
    Any,
    Literal,
    List,
    Union
)
from collections.abc import Mapping

from attrs import define
import bson # bson dependency from pymongo. pip install pymongo
from bson.codec_options import DEFAULT_CODEC_OPTIONS
from bson import ObjectId

from .auth import AuthCredentials, Auth
from .typings import xJsonT, Document, OP_T
from .models import Response, HelloResult
from .datatypes import Int32, Char

@define
class Serializer:
    def _randint(self) -> int:
        return int.from_bytes(os.urandom(4), signed=True)

    def _pack_message(self, op: int, data: bytes) -> tuple[int, bytes]:
        rid = self._randint()
        header = b"".join(map(Int32, [16 + len(data), rid, 0, op]))
        return rid, header + data

    def _query_impl(self, doc: Document) -> bytes:
        encoded = bson.encode(doc, check_keys=False, codec_options=DEFAULT_CODEC_OPTIONS)
        return b"".join([
            Int32(0),
            bson._make_c_string("admin.$cmd"),
            Int32(0),
            Int32(-1),
            encoded,
        ])

    def _op_msg_no_header(
        self,
        command: Mapping[str, Any]
    ) -> bytes:
        encoded = bson.encode(command, False, DEFAULT_CODEC_OPTIONS)
        return b"".join([
            Int32(0), 
            Char(0, signed=False), 
            encoded
        ])

    def get_reply(
        self, 
        msg: bytes, 
        op_code: int,
    ) -> xJsonT:
        # flags, ptype, psize = struct.unpack_from("<IBi", msg)
        message = msg[5:] if op_code != 1 else msg[20:]
        return bson._decode_all_selective(message, codec_options=DEFAULT_CODEC_OPTIONS, fields=None)[0]

    def get_message(
        self, 
        doc: Document, 
        op: OP_T = 2013
    ) -> tuple[int, bytes]:
        func = {2013: self._op_msg_no_header, 2004: self._query_impl}[op]
        return self._pack_message(op, func(doc))

    def verify_rid(self, data: bytes, rid: int) -> tuple[int, int]:
        length, _, response_to, op_code = struct.unpack("<iiii", data) # _ is response id
        assert response_to == rid, f"wrong response id {response_to} (should be {rid})"
        return length, op_code

@define
class MongoSocket:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    serializer: Serializer = Serializer()
    lock: asyncio.Lock = asyncio.Lock()

    @classmethod
    async def make(cls, host: str, port: int) -> MongoSocket:
        reader, writer = await asyncio.open_connection(host, port)
        return cls(reader, writer)

    async def send(self, msg: bytes) -> None:
        self.writer.write(msg)
        await self.writer.drain()

    async def recv(self, size: int) -> bytes:
        return await self.reader.readexactly(size) # ... 13.05.2024 # https://stackoverflow.com/a/29068174

    def get_hello_payload(self) -> xJsonT:
        uname = os.uname() # TODO: Windows
        impl = sys.implementation
        platform = impl.name + " " + ".".join(map(str, impl.version))
        return {
            "hello": 1.0, 
            "client": {
                "driver": {
                    "name": "async_mongo", 
                    "version": "0.3.2"
                }, 
                "os": {
                    "type": os.name, 
                    "name": uname.sysname, 
                    "architecture": uname.machine, 
                    "version": uname.release
                }, 
                "platform": platform
            }
        }
    
    async def request(
        self,
        doc: Document,
        session: Optional[xJsonT] = None,
        raise_on_error: bool = True,
        op: OP_T = 2013
    ) -> xJsonT:
        if session:
            doc["lsid"] = session
        rid, msg = self.serializer.get_message(doc, op=op)
        async with self.lock:
            await self.send(msg)
            length, op_code = self.serializer.verify_rid(await self.recv(16), rid)
            reply = self.serializer.get_reply(await self.recv(length - 16), op_code)
        if raise_on_error:
            assert reply.get("ok") == 1.0, reply
        return reply

    async def query(self, doc: xJsonT) -> xJsonT:
        return await self.request(doc, op=2004)

    async def hello(
        self,
        compression: Optional[List[Literal["zlib", "zstd", "snappy"]]] = None, # TODO
        credentials: Optional[AuthCredentials] = None
    ) -> HelloResult:
        payload = self.get_hello_payload()

        if compression:
            payload["compression"] = compression
        if credentials:
            payload["saslSupportedMechs"] = f"{credentials.db_name}.{credentials.username}"
        
        hello = await self.query(payload)
        
        return HelloResult(**{
            "mechanisms": hello.get("saslSupportedMechs", []),
            "local_time": hello["localTime"],
            "connection_id": hello["connectionId"],
            "read_only": hello["readOnly"]
        })

    async def refresh_sessions(self, sessions: List[xJsonT], db_name: str) -> bool:
        request = await self.request({"refreshSessions": sessions, "$db": db_name})
        return request["ok"] == 1.0

    async def end_sessions(self, sessions: List[xJsonT], db_name: str) -> bool:
        request = await self.request({"endSessions": sessions, "$db": db_name})
        return request["ok"] == 1.0

    async def start_session(self, db_name: str) -> xJsonT:
        return (await self.request({"startSession": 1.0, "$db": db_name}))["id"]

    async def create_user(
        self,
        username: str,
        password: str,
        roles: List[Union[Document, str]],
        db_name: Optional[str] = None,
        mechanisms: List[str] = ["SCRAM-SHA-1", "SCRAM-SHA-256"]
    ) -> bool:
        command = {"createUser": username, "pwd": password, "roles": roles, "mechanisms": mechanisms, "$db": "admin" if db_name is None else db_name}
        return (await self.request(command))["ok"] == 1.0

    async def drop_user(self, username: str, db_name: str):
        command = {"dropUser": username, "$db": db_name}
        return (await self.request(command))["ok"] == 1.0

    async def drop_database(self, db_name: str) -> bool:
        command = {"dropDatabase": 1.0, "$db": db_name}
        return (await self.request(command))["ok"] == 1.0

    async def list_databases(self) -> List[str]:
        command = {"listDatabases": 1.0, "nameOnly": True, "$db": "admin"}
        request = await self.request(command)
        print(request)
        return [x["name"] for x in request["databases"]]

    async def grant_roles_to_user(self, username: str, roles: List[Union[str, Document]]) -> bool:
        command = {"grantRolesToUser": username, "roles": roles, "$db": "admin"}
        request = await self.request(command)
        return request["ok"] == 1.0

    async def list_users(self) -> List[Document]:
        params = {"find": "system.users", "filter": {}, "$db": "admin"}
        request = await self.request(params)
        return [x for x in request["cursor"]["firstBatch"]]

@define
class AsyncMongo:
    socket: MongoSocket
    db_name: str
    session: Optional[Document]

    @classmethod
    async def create(
        cls,
        db_name: str,
        host: str = "127.0.0.1",
        port: int = 27017,
        credentials: Optional[AuthCredentials] = None,
        start_session: bool = False
    ) -> AsyncMongo:
        socket = await MongoSocket.make(host, port)
        hello = await socket.hello(credentials=credentials)
        if hello.requires_auth and credentials:
            mechanism = random.choice(hello.mechanisms)
            signature = await Auth(socket).create(mechanism, credentials)
            print(f"SUCCESSFUL AUTH USING {mechanism} | sig: {signature.hex()[:16]}...")
        if start_session:
            session = await socket.start_session(db_name=db_name)
        else:
            session = None
        return cls(socket, db_name, session)

    async def add_one(self, doc: Document, collection: str) -> Response[ObjectId]:
        doc = doc.copy(); doc["_id"] = ObjectId()
        params = {"insert": collection, "ordered": True, "$db": self.db_name, "documents": [doc]}
        await self.socket.request(params, self.session)
        return Response(doc["_id"])

    async def add_many(self, docs: List[Document], collection: str) -> Response[List[ObjectId]]:
        assert len(docs) > 0, "Empty sequence of documents"
        docs = [doc.copy() for doc in docs] # make copy
        for doc in docs:
            doc["_id"] = ObjectId()
        params = {"insert": collection, "ordered": True, "$db": self.db_name, "documents": docs}
        await self.socket.request(params, self.session)
        return Response([doc["_id"] for doc in docs])

    async def collection_names(self) -> List[str]:
        request = await self.socket.request({"listCollections": 1.0, "$db": self.db_name})
        return [x["name"] for x in request["cursor"]["firstBatch"]]

    async def count_documents(
        self,
        filter: Document,
        collection: str
    ) -> int:
        pipeline: List[xJsonT] = [{"$match": filter}, {"$group": {"_id": 1, "n": {"$sum": 1}}}]
        cmd = {"aggregate": collection, "pipeline": pipeline, "cursor": {}, "$db": self.db_name}
        request = await self.socket.request(cmd, self.session)
        if request["cursor"]["firstBatch"]:
            return request["cursor"]["firstBatch"][0]["n"]
        return 0

    async def update_one(self, filter: Document, to_replace: Document, collection: str, upsert: bool = False) -> Response[int]:
        params = {"update": collection, "ordered": True, "$db": self.db_name, "updates": [{"q": filter, "u": {"$set": to_replace}, "multi": False, "upsert": upsert}]}
        request = await self.socket.request(params, self.session)
        return Response(request["nModified"])

    async def update_many(self, filter: Document, to_replace: Document, collection: str, upsert: bool = False) -> Response[int]:
        params = {"update": collection, "ordered": True, "$db": self.db_name, "updates": [{"q": filter, "u": {"$set": to_replace}, "multi": True, "upsert": upsert}]}
        request = await self.socket.request(params, self.session)
        return Response(request["nModified"])

    async def delete_one(self, filter: Document, collection: str) -> Response[bool]:
        params = {"delete": collection, "ordered": True, "$db": self.db_name, "deletes": [{"q": filter, "limit": 1}]}
        request = await self.socket.request(params, self.session)
        return Response(request["n"])

    async def delete_many(self, filter: Document, collection: str, limit: int = 0) -> Response[int]:
        params = {"delete": collection, "ordered": True, "$db": self.db_name, "deletes": [{"q": filter, "limit": limit}]}
        request = await self.socket.request(params, self.session)
        return Response(request["n"])

    async def find_one(self, filter: Document, collection: str) -> Response[Document]:
        request = await self.aggregate([{"$match": filter}, {"$limit": 1}, {"$unset": "_id"}], collection)
        return Response(request[0] if request else request)

    async def find_all(self, filter: Document, collection: str, skip: int = 0, limit: int = 0) -> Response[List[Document]]:
        command = {"find": collection, "filter": filter, "skip": skip, "limit": limit, "projection": {"_id": 0}, "$db": self.db_name}
        request = await self.socket.request(command, self.session)
        docs = request["cursor"]["firstBatch"]
        if request["cursor"]["id"] != 0:
            command = {
                "getMore": request["cursor"]["id"],
                "$db": self.db_name,
                "collection": collection
            }
            request = await self.socket.request(command, self.session)
            docs += request["cursor"]["nextBatch"]
        return Response(docs)

    async def aggregate(self, pipeline: List[Document], collection: str):
        cmd = {"aggregate": collection, "pipeline": pipeline, "cursor": {}, "$db": self.db_name}
        request = await self.socket.request(cmd, self.session)
        return request["cursor"]["firstBatch"]
