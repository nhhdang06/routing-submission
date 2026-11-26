
####################################################
# LSrouter.py
# Name: NGUYEN HUU HAI DANG
# HUID:24020431
#####################################################

import json
from router import Router
from packet import Packet


class LSrouter(Router):
    """Link state routing protocol implementation."""

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)

        self.heartbeat_time = heartbeat_time
        self.last_time = 0

        # Các liên kết trực tiếp: port -> (endpoint, cost)
        self.neighbors = {}

        # Cơ sở dữ liệu Link State:
        # router -> (sequence number, danh sách liên kết)
        self.link_state = {
            self.addr: (0, [])
        }

        # Số thứ tự LSA của chính router này
        self.sequence_number = 0

        # Đích đến -> port cần gửi gói tin
        self.forwarding_table = {}

    def _get_local_links(self):
        """Lấy danh sách các liên kết trực tiếp của router."""
        return [
            [endpoint, cost]
            for endpoint, cost in self.neighbors.values()
        ]

    def _update_local_state(self):
        """Cập nhật LSA của router hiện tại."""
        self.sequence_number += 1

        self.link_state[self.addr] = (
            self.sequence_number,
            self._get_local_links()
        )

        self._recompute_routes()

    def _create_lsa_packet(self):
        """Tạo gói tin quảng bá trạng thái liên kết."""
        content = json.dumps({
            "seq": self.sequence_number,
            "links": self._get_local_links()
        })

        return Packet(
            Packet.ROUTING,
            self.addr,
            self.addr,
            content
        )

    def _broadcast_lsa(self):
        """Gửi LSA của router đến tất cả các láng giềng."""
        packet = self._create_lsa_packet()

        for port in list(self.neighbors.keys()):
            self.send(port, packet)

    def _recompute_routes(self):
        """Dùng thuật toán Dijkstra để tính đường đi ngắn nhất."""

        # Xây dựng đồ thị từ cơ sở dữ liệu Link State
        graph = {}

        for router, state in self.link_state.items():
            _, links = state
            graph.setdefault(router, [])

            for neighbor, raw_cost in links:
                cost = float(raw_cost)

                graph[router].append((neighbor, cost))
                graph.setdefault(neighbor, [])

        # Khởi tạo Dijkstra
        distances = {self.addr: 0}
        first_hop = {}

        unvisited = set(graph.keys())
        unvisited.add(self.addr)

        while unvisited:
            reachable = [
                node for node in unvisited
                if node in distances
            ]

            if not reachable:
                break

            current = min(
                reachable,
                key=lambda node: distances[node]
            )

            unvisited.remove(current)

            for neighbor, cost in graph.get(current, []):
                if cost < 0:
                    continue

                new_distance = distances[current] + cost

                if new_distance < distances.get(
                    neighbor, float("inf")
                ):
                    distances[neighbor] = new_distance

                    if current == self.addr:
                        first_hop[neighbor] = neighbor
                    else:
                        first_hop[neighbor] = first_hop[current]

        # Ánh xạ địa chỉ láng giềng sang port.
        # Nếu có nhiều liên kết đến cùng một láng giềng,
        # chọn liên kết có chi phí thấp nhất.
        port_for_neighbor = {}

        for port, (endpoint, cost) in self.neighbors.items():
            old = port_for_neighbor.get(endpoint)

            if old is None or cost < old[0]:
                port_for_neighbor[endpoint] = (cost, port)

        # Xây dựng bảng chuyển tiếp
        new_table = {}

        for destination, next_hop in first_hop.items():
            if destination == self.addr:
                continue

            if next_hop in port_for_neighbor:
                new_table[destination] = (
                    port_for_neighbor[next_hop][1]
                )

        self.forwarding_table = new_table

    def handle_packet(self, port, packet):
        """Xử lý gói tin nhận được."""

        # Gói tin dữ liệu thông thường
        if packet.is_traceroute:
            out_port = self.forwarding_table.get(
                packet.dst_addr
            )

            if out_port is not None:
                self.send(out_port, packet)

            return

        # Chỉ xử lý gói tin định tuyến
        if not packet.is_routing:
            return

        # Đọc nội dung LSA
        try:
            message = json.loads(packet.content)

            sequence = int(message["seq"])
            received_links = []

            for item in message["links"]:
                if len(item) != 2:
                    return

                neighbor = item[0]
                cost = float(item[1])

                received_links.append((neighbor, cost))

        except (TypeError, ValueError, KeyError):
            return

        # Địa chỉ router đã tạo LSA
        origin = packet.src_addr

        # Không xử lý lại LSA của chính mình
        if origin == self.addr:
            return

        old_state = self.link_state.get(origin)

        # Chỉ nhận LSA có sequence number mới hơn
        if old_state is not None:
            if sequence <= old_state[0]:
                return

        # Cập nhật cơ sở dữ liệu Link State
        self.link_state[origin] = (
            sequence,
            received_links
        )

        # Tính lại đường đi ngắn nhất
        self._recompute_routes()

        # Flood LSA đến các láng giềng khác,
        # không gửi ngược lại port vừa nhận
        for out_port in list(self.neighbors.keys()):
            if out_port != port:
                self.send(out_port, packet)

    def handle_new_link(self, port, endpoint, cost):
        """Xử lý khi xuất hiện liên kết mới."""

        self.neighbors[port] = (endpoint, cost)

        self._update_local_state()
        self._broadcast_lsa()

    def handle_remove_link(self, port):
        """Xử lý khi một liên kết bị ngắt."""

        self.neighbors.pop(port, None)

        self._update_local_state()
        self._broadcast_lsa()

    def handle_time(self, time_ms):
        """Phát LSA định kỳ."""

        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self._broadcast_lsa()

    def __repr__(self):
        """Thông tin router khi debug."""
        return (
            f"LSrouter(addr={self.addr}, "
            f"routes={self.forwarding_table})"
        )
