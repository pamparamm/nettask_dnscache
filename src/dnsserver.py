import pickle
import struct
from pathlib import Path
from socket import AF_INET, SOCK_DGRAM, socket
from time import time

from src.util import Utils

BUFFER_SIZE = 1024


class DnsServer:
    """Caching server instance."""

    def __init__(self, port: int, src: str, cache_path: Path):
        self.port = port
        self._src_data = src.split(":")
        self.src_ip = self._src_data[0]
        self.src_port = int(self._src_data[1])
        self.cache_path = cache_path
        self.cache_data: dict[DnsQuestion, DnsRecord] = {}
        self._init_server()

    def _init_server(self):
        if not self.cache_path.exists():
            return
        with self.cache_path.open("rb") as file:
            self.cache_data = pickle.load(file)

    def start(self):
        with socket(AF_INET, SOCK_DGRAM) as sock:
            sock.bind(("", self.port))
            print(f"Serving on port {self.port}")
            while True:
                data, client_address = sock.recvfrom(4096)
                proceeded_data = self._proceed_data(data)
                sock.sendto(proceeded_data, client_address)

    def _proceed_data(self, data: bytes) -> bytes:
        client_request = DnsRequest(data)
        for question in client_request.questions:
            if not question in self.cache_data or self.cache_data[
                question
            ].expiration_time < int(time()):
                return self._get_data_from_src(data)
            if question.question_type == 6:
                client_request.authority[question] = self.cache_data[question]
                client_request.auth_req_count += 1
            else:
                client_request.answers[question] = self.cache_data[question]
                client_request.answ_req_count += 1
        client_request.flags = 0x8580
        return client_request.to_bytes_repr()

    def _get_data_from_src(self, data: bytes) -> bytes:
        with socket(AF_INET, SOCK_DGRAM) as sock:
            sock.connect((self.src_ip, self.src_port))
            sock.send(data)
            response = sock.recv(BUFFER_SIZE)
            self.cache_data.update(DnsRequest(response).answers)
            return response

    def stop(self):
        if not self.cache_path.parents[0].exists():
            self.cache_path.parents[0].mkdir(parents=True, exist_ok=True)
        self.cache_path.touch()
        with self.cache_path.open("wb") as file:
            pickle.dump(self.cache_data, file)
            print(f"Server was closed, cache was saved to {self.cache_path}")


class DnsRequest:
    """Dns request object containing queries and records."""

    def __init__(self, data: bytes):
        (
            self.id,
            self.flags,
            self.qstn_req_count,
            self.answ_req_count,
            self.auth_req_count,
            self.add_req_count,
        ) = struct.unpack_from("!HHHHHH", data, 0)
        self.questions: list[DnsQuestion] = []
        self.answers: dict[DnsQuestion, DnsRecord] = {}
        self.authority: dict[DnsQuestion, DnsRecord] = {}
        self.current_offset = 12
        for _ in range(self.qstn_req_count):
            question = DnsQuestion(data, self.current_offset)
            self.current_offset = question.current_offset
            self.questions.append(question)
        for _ in range(
            self.answ_req_count + self.auth_req_count + self.add_req_count
        ):
            question = DnsQuestion(data, self.current_offset)
            self.current_offset = question.current_offset
            record = DnsRecord(
                data, self.current_offset, question.question_type == 2
            )
            self.current_offset = record.current_offset + record.length
            self.answers[question] = record

    def to_bytes_repr(self) -> bytes:
        output = struct.pack(
            "!HHHHHH",
            self.id,
            self.flags,
            self.qstn_req_count,
            self.answ_req_count,
            self.auth_req_count,
            self.add_req_count,
        )
        for question in self.questions:
            output += question.to_bytes_repr()
        for question, answer in self.answers.items() | self.authority.items():
            output += question.to_bytes_repr() + answer.to_bytes_repr()
        return output


class DnsQuestion:
    def __init__(self, data: bytes, offset: int):
        self.current_offset = offset
        self.url, self.current_offset = Utils.url_from_bytes(
            data, self.current_offset
        )
        self.question_type, self.current_offset = Utils.short_from_bytes(
            data, self.current_offset
        )
        self.question_class, self.current_offset = Utils.short_from_bytes(
            data, self.current_offset
        )

    def to_bytes_repr(self) -> bytes:
        return Utils.url_to_bytes(self.url) + struct.pack(
            "!HH", self.question_type, self.question_class
        )

    def __eq__(self, second: "DnsQuestion"):
        return (
            self.url == second.url
            and self.question_class == second.question_class
            and self.question_type == second.question_type
        )

    def __hash__(self):
        return (
            hash(self.url)
            * hash(self.question_class)
            * hash(self.question_type)
        )


class DnsRecord:
    def __init__(self, data: bytes, offset: int, contains_link=False):
        self.current_offset = offset
        self.ttl, self.current_offset = Utils.int_from_bytes(
            data, self.current_offset
        )
        self.expiration_time = int(time()) + self.ttl
        self.length, self.current_offset = Utils.short_from_bytes(
            data, self.current_offset
        )
        if contains_link:
            self.info = Utils.url_to_bytes(
                Utils.url_from_bytes(data, self.current_offset)[0]
            )
        else:
            self.info = data[
                self.current_offset : self.current_offset + self.length
            ]

    def to_bytes_repr(self) -> bytes:
        return (
            struct.pack(
                "!IH", self.expiration_time - int(time()), len(self.info)
            )
            + self.info
        )
