from __future__ import annotations

import os
import hashlib
import base64
from hmac import HMAC, compare_digest
from typing import TYPE_CHECKING, Dict

from attrs import define, field
from bson import Binary

if TYPE_CHECKING:
    from .mongo import MongoSocket

@define(frozen=True)
class AuthCredentials:
    username: str
    password: str = field(repr=False)
    db_name: str = field(default="admin")

    def md5_hash(self) -> bytes:
        hash = hashlib.md5(f"{self.username}:mongo:{self.password}".encode())
        return hash.hexdigest().encode("u8")

@define
class Auth:
    socket: MongoSocket

    def parse_scram_response(self, payload: bytes) -> Dict[str, bytes]:
        values = [item.split(b"=", 1) for item in payload.split(b",")]
        return {k.decode(): v for k, v in values}

    def xor(self, fir: bytes, sec: bytes) -> bytes:
        """XOR two byte strings together."""
        return b"".join([bytes([x ^ y]) for x, y in zip(fir, sec)])
    
    async def start_auth(self, mechanism: str, username: str, db_name: str) -> tuple[bytes, bytes, bytes, int]:
        user = username.encode("utf-8").replace(b"=", b"=3D").replace(b",", b"=2C")
        nonce = base64.b64encode(os.urandom(32))
        first_bare = b"n=" + user + b",r=" + nonce
        command = {"saslStart": 1.0, "mechanism": mechanism, "payload": Binary(b"n,," + first_bare), "autoAuthorize": 1, "options": {"skipEmptyExchange": True}, "$db": db_name}
        request = await self.socket.request(command)
        return nonce, request["payload"], first_bare, request["conversationId"]

    async def create(self, mechanism: str, credentials: AuthCredentials) -> bytes:
        if mechanism == "SCRAM-SHA-1":
            digest = "sha1"
            digestmod = hashlib.sha1
            data = credentials.md5_hash()
        else:
            digest = "sha256"
            digestmod = hashlib.sha256
            data = credentials.password.encode("utf-8") # prob requires saslprep
        nonce, server_first, first_bare, cid = await self.start_auth(mechanism, credentials.username, credentials.db_name)

        parsed = self.parse_scram_response(server_first)
        iterations = int(parsed["i"])
        assert iterations > 4096, "Server returned an invalid iteration count."
        salt, rnonce = parsed["s"], parsed["r"]
        assert rnonce.startswith(nonce), "Server returned an invalid nonce."

        without_proof = b"c=biws,r=" + rnonce
        salted_pass = hashlib.pbkdf2_hmac(digest, data, base64.b64decode(salt), iterations)
        client_key = HMAC(salted_pass, b"Client Key", digestmod).digest()
        server_key = HMAC(salted_pass, b"Server Key", digestmod).digest()

        stored_key = digestmod(client_key).digest()
        auth_msg = b",".join((first_bare, server_first, without_proof))
        client_sig = HMAC(stored_key, auth_msg, digestmod).digest()
        client_proof = b"p=" + base64.b64encode(self.xor(client_key, client_sig))
        client_final = b",".join((without_proof, client_proof))
        server_sig = base64.b64encode(HMAC(server_key, auth_msg, digestmod).digest())

        cmd = {"saslContinue": 1.0, "conversationId": cid, "payload": Binary(client_final), "$db": credentials.db_name}
        request = await self.socket.request(cmd)
        parsed = self.parse_scram_response(request["payload"])
        assert compare_digest(parsed["v"], server_sig) and request["done"]

        return parsed["v"]