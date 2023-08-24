import json
import csv
from datetime import datetime
import random

from tqdm import tqdm

from twisted.internet.task import react
from twisted.internet.defer import inlineCallbacks, ensureDeferred
from twisted.internet.endpoints import UNIXClientEndpoint

import treq
import txtorcon

URL_LIST = [
    "https://ooni.org/robots.txt",
    "https://www.google.com/robots.txt",
    "https://www.apple.com/robots.txt",
    "https://www.bbc.com/robots.txt",
]


async def get_exit_list(reactor):
    resp = await treq.get(
        "https://onionoo.torproject.org/details?search=flag:Exit",
    )
    data = await resp.text()
    j = json.loads(data)
    exit_list = []
    for relay in j["relays"]:
        # XXX ignore relays whos exit policy is incompatible with our target
        if relay["running"] != True:
            continue

        exit_list.append(
            {
                "nickname": relay["nickname"],
                "fingerprint": relay["fingerprint"],
                "country": relay["country"],
                "as": relay["as"],
            }
        )
    return exit_list


async def measure_relay(reactor, tor, tor_state, relay, url_list, csvwriter):
    exit_fp = relay["fingerprint"]
    ns_info = await tor.protocol.get_info("ns/id/" + exit_fp)
    md_info = await tor.protocol.get_info("md/id/" + exit_fp)

    first_hop = random.choice(list(tor_state.guards.values()))
    exit_hop = tor_state.routers_by_hash["$" + exit_fp]
    tqdm.write(f"Creating a circuit via {relay['nickname']} ({relay['fingerprint']})")
    circ = await tor_state.build_circuit([first_hop, exit_hop], using_guards=False)
    await circ.when_built()

    tqdm.write("  path: {}".format(" -> ".join([r.ip for r in circ.path])))

    config = await tor.get_config()
    for url in url_list:
        tqdm.write(f"* fetching {url} over {exit_fp}")
        row = {
            "exit_fp": exit_fp,
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


class TorLogger:
    def __init__(self, prefix=""):
        self.prefix = prefix

    def write(self, msg):
        tqdm.write(f"{self.prefix}{msg.strip()}")


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

        print("🚂 Starting tor")
        try:
            tor = await txtorcon.launch(
                reactor,
                stdout=TorLogger("  "),
                stderr=TorLogger("ERR: "),
                kill_on_stderr=False,
                progress_updates=lambda x, y, z: print(f"{x}%: {y} - {z}"),
            )
        except Exception as exc:
            print(f"FAILED to start tor {exc}")
            return

        print("🏁 Started Tor version {}".format(tor.version))

        exit_list = await get_exit_list(reactor)
        state = await tor.create_state()
        for relay in tqdm(exit_list):
            try:
                await measure_relay(reactor, tor, state, relay, URL_LIST, csvwriter)
            except Exception as exc:
                tqdm.write(f"FAILED to measure via {relay['fingerprint']} {exc}")


@react
def _main(reactor):
    return ensureDeferred(main(reactor))
