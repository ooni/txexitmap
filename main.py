"""
OONI-specific version of TxExitmap
"""

from datetime import datetime
from pathlib import Path
from time import time
import csv
import json
import logging
import random
import sys

import twisted.internet.error
from twisted.internet.task import react
from twisted.internet.defer import ensureDeferred

# debdeps: python3-treq python3-txtorcon
import treq
import txtorcon
from txtorcon.torcontrolprotocol import TorDisconnectError

# debdeps: python3-clickhouse-driver
from clickhouse_driver import Client as Clickhouse
#from systemd.journal import JournalHandler  # debdeps: python3-systemd

import statsd  # debdeps: python3-statsd

URL_LIST = [
    "https://ooni.org/robots.txt",
    "https://www.google.com/robots.txt",
    "https://www.apple.com/robots.txt",
    "https://www.bbc.com/robots.txt",
]
write_csv = False
clickhouse_client = None


metrics = statsd.StatsClient("localhost", 8125, prefix="txexitmap")

log = logging.getLogger("txexitmap")
#log.addHandler(JournalHandler(SYSLOG_IDENTIFIER="txexitmap"))
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
debug = True
log.setLevel(logging.DEBUG if debug else logging.INFO)


async def get_exit_list(reactor, randomize=True):
    t0 = time()
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
    metrics.timing("get_exit_list", (time() - t0) * 1000)
    return exit_list


async def measure_relay(reactor, tor_launcher, relay, url_list, datawriter):
    t0 = time()
    tor = tor_launcher.tor
    tor_state = tor_launcher.state
    await tor.protocol.get_info("ns/id/" + relay["fingerprint"])
    await tor.protocol.get_info("md/id/" + relay["fingerprint"])

    first_hop = random.choice(list(tor_state.guards.values()))
    exit_hop = tor_state.routers_by_hash["$" + relay["fingerprint"]]
    log.info(f"Creating a circuit via {relay['nickname']} ({relay['fingerprint']})")
    circ = await tor_state.build_circuit([first_hop, exit_hop], using_guards=False)
    await circ.when_built()

    log.info("path: {}".format(" -> ".join([r.ip for r in circ.path])))

    config = await tor.get_config()
    for url in url_list:
        t1 = time()
        log.info(f"fetching {url} over {relay['fingerprint']}")
        row = {
            "fingerprint": relay["fingerprint"],
            "nickname": relay["nickname"],
            "cc": relay["country"],
            "asn": relay["as"],
            "url": url,
            "status": None,
            "response_length": 0,
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

        metrics.timing("measure_url", (time() - t1) * 1000)
        row["timing"] = time() - t1
        datawriter(row)

    metrics.timing("measure_relay", (time() - t0) * 1000)


# This class is currently needed as a workaround of:
# https://github.com/meejah/txtorcon/issues/389
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
        )
        # progress_updates=lambda x, y, z: log.info(f"{x}%: {y} - {z}"),

        tor.protocol.add_event_listener("INFO", self._log)
        log.info(f"Started Tor version {tor.version}")
        self._state = await tor.create_state()
        self._tor = tor


def store_row_in_clickhouse(row: dict):
    log.info(row)
    sql = """INSERT INTO tor_web_connectivity (fingerprint, nickname,
    cc, asn, url, status, response_length, date) VALUES
    """
    try:
        clickhouse_client.execute(sql, [row])
    except Exception as e:
        log.error(e, exc_info=True)


"""
CREATE TABLE default.tor_web_connectivity
(
    `date` DateTime DEFAULT now(),
    `fingerprint` String,
    `nickname` String,
    `cc` String,
    `asn` String,
    `url` String,
    `status` String,
    `response_length` UInt32,
    `timing` Float32
)
ENGINE = ReplacingMergeTree(test_time)
ORDER BY test_time
SETTINGS index_granularity = 1
"""


async def main(reactor):
    if write_csv:
        out_file = open("exitmap-results.csv", "w")
        csvwriter = csv.DictWriter(
            out_file,
            fieldnames=[
                "fingerprint",
                "nickname",
                "cc",
                "asn",
                "url",
                "status",
                "response_length",
                "date",
            ],
        )
        csvwriter.writeheader()
        datawriter = csvwriter.writerow
    else:
        global clickhouse_client
        clickhouse_client = Clickhouse.from_url("clickhouse://localhost")
        log.info("Connected to Clickhouse")
        datawriter = store_row_in_clickhouse

    # Uncomment if you would like to connect to a running tor instance
    # tor = await txtorcon.connect(
    #    reactor,
    #    UNIXClientEndpoint(reactor, "/var/run/tor/control")
    # )

    data_directory = Path("~/.config/txexitmap/tor_datadir").expanduser()
    tor_launcher = TorLauncher(reactor, data_directory)

    log.info("Starting tor")
    await tor_launcher.launch()

    exit_list = await get_exit_list(reactor)
    for relay in exit_list:
        try:
            await measure_relay(reactor, tor_launcher, relay, URL_LIST, datawriter)
        except TorDisconnectError:
            log.info("Tor disconnected unexpectectedly, restarting")
            await tor_launcher.launch()
            continue
        except Exception as exc:
            log.info(f"FAILED to measure via {relay['fingerprint']} {exc}")

    tor_launcher.close()


async def wrapper(reactor):
    try:
        await main(reactor)
    except twisted.internet.error.ReactorNotRunning:
        log.info("exiting")
        sys.exit()


@react
def _main(reactor):
    return ensureDeferred(wrapper(reactor))
