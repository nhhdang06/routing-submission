
####################################################
# DVrouter.py
# Name:NGUYEN HUU HAI DANG
# HUID:
#####################################################

import json
from packet import Packet
from router import Router


class DVrouter(Router):

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)  # DO NOT REMOVE

        self.heartbeat_time = heartbeat_time
        self.last_time = 0

        # Maximum distance (infinity)
        self.infinity = 16

        # Direct neighbors: port -> (neighbor address, link cost)
        self.neighbors = {}

        # Distance vectors received from neighbors
        # port -> {destination: distance}
        self.neighbor_vectors = {}

        # My distance vector
        self.distance_vector = {addr: 0}

        # Destination -> outgoing port
        self.forwarding_table = {}

    def _recompute_routes(self):
        """Recompute routes using the Bellman-Ford algorithm."""

        destinations = set(self.distance_vector.keys())

        for endpoint, cost in self.neighbors.values():
            destinations.add(endpoint)

        for vector in self.neighbor_vectors.values():
            destinations.update(vector.keys())

        new_dv = {self.addr: 0}
        new_forwarding = {}

        for destination in destinations:
            if destination == self.addr:
                continue

            best_cost = self.infinity
            best_port = None

            for port, (neighbor, cost) in self.neighbors.items():

                if destination == neighbor:
                    candidate = cost
                else:
                    neighbor_distance = self.neighbor_vectors.get(
                        port, {}
                    ).get(destination, self.infinity)

                    if neighbor_distance >= self.infinity:
                        continue

                    candidate = cost + neighbor_distance

                if candidate < best_cost and candidate < self.infinity:
                    best_cost = candidate
                    best_port = port

            new_dv[destination] = best_cost

            if best_port is not None:
                new_forwarding[destination] = best_port

        changed = (
            new_dv != self.distance_vector
            or new_forwarding != self.forwarding_table
        )

        self.distance_vector = new_dv
        self.forwarding_table = new_forwarding

        return changed

    def _broadcast_distance_vector(self):
        """Send my distance vector to all neighbors using poison reverse."""

        for port, (neighbor, cost) in self.neighbors.items():

            advertised_vector = dict(self.distance_vector)

            # Poison reverse
            for destination, next_port in self.forwarding_table.items():
                if next_port == port:
                    advertised_vector[destination] = self.infinity

            packet = Packet(
                Packet.ROUTING,
                self.addr,
                neighbor,
                json.dumps(advertised_vector)
            )

            self.send(port, packet)

    def handle_packet(self, port, packet):
        """Process incoming packet."""

        if packet.is_traceroute:

            next_port = self.forwarding_table.get(packet.dst_addr)

            if next_port is not None:
                self.send(next_port, packet)

            return

        if not packet.is_routing:
            return

        neighbor_info = self.neighbors.get(port)

        if neighbor_info is None or neighbor_info[0] != packet.src_addr:
            return

        try:
            received_vector = json.loads(packet.content)
        except (TypeError, ValueError):
            return

        if not isinstance(received_vector, dict):
            return

        clean_vector = {}

        for destination, distance in received_vector.items():
            if isinstance(distance, (int, float)) and distance >= 0:
                clean_vector[destination] = min(
                    distance, self.infinity
                )

        if clean_vector != self.neighbor_vectors.get(port):

            self.neighbor_vectors[port] = clean_vector

            if self._recompute_routes():
                self._broadcast_distance_vector()

    def handle_new_link(self, port, endpoint, cost):
        """Handle new link."""

        self.neighbors[port] = (endpoint, cost)

        self.neighbor_vectors.pop(port, None)

        self._recompute_routes()
        self._broadcast_distance_vector()

    def handle_remove_link(self, port):
        """Handle removed link."""

        self.neighbors.pop(port, None)
        self.neighbor_vectors.pop(port, None)

        self._recompute_routes()
        self._broadcast_distance_vector()

    def handle_time(self, time_ms):
        """Handle current time."""

        if time_ms - self.last_time >= self.heartbeat_time:

            self.last_time = time_ms

            self._broadcast_distance_vector()

    def __repr__(self):
        """Representation for debugging."""

        return (
            f"DVrouter(addr={self.addr}, "
            f"distance_vector={self.distance_vector})"
        )
