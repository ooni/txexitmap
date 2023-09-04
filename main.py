import json
from pathlib import Path
import csv
from datetime import datetime
import random

from tqdm import tqdm

from twisted.internet.task import react
from twisted.internet.defer import ensureDeferred

import treq
import txtorcon
from txtorcon.torcontrolprotocol import TorDisconnectError

URL_LIST = [
    "https://ooni.org/robots.txt",
    "https://www.google.com/robots.txt",
    "https://www.apple.com/robots.txt",
    "https://www.bbc.com/robots.txt",
]


async def get_exit_list(reactor, randomize=True):
    resp = await treq.get(
        "https://onionoo.torproject.org/details?search=flag:Exit",
    )
    data = await resp.text()
    j = json.loads(data)
    exit_list = []
    for relay in j["relays"]:
        # XXX ignore relays whos exit policy is incompatible with our target
        if relay["running"] is not True:
            continue

        exit_list.append(
            {
                "nickname": relay["nickname"],
                "fingerprint": relay["fingerprint"],
                "country": relay["country"],
                "as": relay["as"],
            }
        )
    if randomize:
        random.shuffle(exit_list)
    return exit_list


async def measure_relay(reactor, tor_launcher, relay, url_list, csvwriter):
    tor = tor_launcher.tor
    tor_state = tor_launcher.state
    await tor.protocol.get_info("ns/id/" + relay["fingerprint"])
    await tor.protocol.get_info("md/id/" + relay["fingerprint"])

    first_hop = random.choice(list(tor_state.guards.values()))
    exit_hop = tor_state.routers_by_hash["$" + relay["fingerprint"]]
    tqdm.write(f"Creating a circuit via {relay['nickname']} ({relay['fingerprint']})")
    circ = await tor_state.build_circuit([first_hop, exit_hop], using_guards=False)
    await circ.when_built()

    tqdm.write("  path: {}".format(" -> ".join([r.ip for r in circ.path])))

    config = await tor.get_config()
    for url in url_list:
        tqdm.write(f"* fetching {url} over {relay['fingerprint']}")
        row = {
            "exit_fp": relay["fingerprint"],
            "exit_nickname": relay["nickname"],
            "exit_cc": relay["country"],
            "exit_asn": relay["as"],
            "url": url,
            "status": None,
            "response_length": None,
            "date": datetime.utcnow(),
        }
        try:
            resp = await treq.get(
                url,
                agent=circ.web_agent(reactor, config.socks_endpoint(reactor)),
                timeout=10,
            )
            data = await resp.text()
            row["status"] = "ok"
            row["response_length"] = len(data)
        except Exception as exc:
            row["status"] = str(exc)

        csvwriter.writerow(row)


# This class is currently needed as a workaround to: https://github.com/meejah/txtorcon/issues/389
# Depending on how and if this is fixed, we might be able to drop it.
class TorLauncher:
    def __init__(self, reactor, data_directory, log_file=None):
        if data_directory:
            data_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.data_directory = data_directory
        self._reactor = reactor
        self.tor_log_file = None
        self._tor = None
        self._state = None
        if log_file:
            self.tor_log_file = log_file.open("w")

    @property
    def tor(self):
        return self._tor

    @property
    def state(self):
        return self._state

    def _log(self, msg):
        if self.tor_log_file:
            self.tor_log_file.write(msg)

    def close(self):
        if self.tor_log_file:
            self.tor_log_file.close()

    async def launch(self):
        if self._tor is not None:
            # XXX do I need to do something to clean it up?
            self._tor = None
            self._state = None

        tor = await txtorcon.launch(
            self._reactor,
            data_directory=self.data_directory,
            kill_on_stderr=False,
            progress_updates=lambda x, y, z: print(f"{x}%: {y} - {z}"),
        )

        tor.protocol.add_event_listener("INFO", self._log)
        print("🏁 Started Tor version {}".format(tor.version))
        self._state = await tor.create_state()
        self._tor = tor


async def main(reactor):
    with open("exitmap-results.csv", "w") as out_file:
        csvwriter = csv.DictWriter(
            out_file,
            fieldnames=[
                "exit_fp",
                "exit_nickname",
                "exit_cc",
                "exit_asn",
                "url",
                "status",
                "response_length",
                "date",
            ],
        )
        csvwriter.writeheader()

        # Uncomment if you would like to connect to a running tor instance
        # tor = await txtorcon.connect(
        #    reactor,
        #    UNIXClientEndpoint(reactor, "/var/run/tor/control")
        # )

        data_directory = Path("~/.config/txexitmap/tor_datadir").expanduser()
        tor_launcher = TorLauncher(reactor, data_directory)

        print("🚂 Starting tor")
        await tor_launcher.launch()

        exit_list = await get_exit_list(reactor)
        for relay in tqdm(exit_list):
            try:
                await measure_relay(reactor, tor_launcher, relay, URL_LIST, csvwriter)
            except TorDisconnectError:
                tqdm.write("Tor disconnected unexpectectedly, restarting")
                await tor_launcher.launch()
                continue
            except Exception as exc:
                tqdm.write(f"FAILED to measure via {relay['fingerprint']} {exc}")

        tor_launcher.close()


@react
def _main(reactor):
    return ensureDeferred(main(reactor))
