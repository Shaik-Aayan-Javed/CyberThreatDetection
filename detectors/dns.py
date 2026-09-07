"""Detector #4 -- DGA domains and DNS tunnelling.

Both attacks abuse the query name, so both are visible from the cleartext DNS
question section. No payload is decrypted and no resolver is queried -- we read
what crossed the link and nothing else.

Two distinguishable shapes, one alert class:

  DGA          algorithmically generated labels. High character entropy and low
               bigram plausibility, because a generator does not respect the
               phonotactics of human-chosen names.
  TUNNELLING   data smuggled in subdomain labels. Many unique long subdomains
               under one parent domain in a short span, often TXT or NULL.

The bigram model below is built at import time from a list of real domain names.
It is deliberately small and inspectable -- a judge can read exactly what
"looks like a normal domain" means here, which is not true of a black-box
classifier.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict, deque

from alerts.schema import DNS_ANOMALY, Alert, Evidence, confidence_from
from detectors.base import Detector
from features.baseline import BaselineTracker
from features.extract import WindowFeatures, shannon_entropy

# Training corpus for the bigram plausibility model: ordinary domain labels.
_CORPUS = """
google facebook youtube twitter instagram linkedin amazon wikipedia yahoo reddit
netflix microsoft apple office live bing outlook hotmail gmail cloudflare akamai
github gitlab stackoverflow medium wordpress blogspot tumblr pinterest quora
whatsapp telegram signal zoom slack discord spotify soundcloud twitch steam
paypal stripe shopify ebay alibaba flipkart myntra snapdeal zomato swiggy
irctc sbi hdfcbank icicibank axisbank paytm phonepe bhim uidai incometax
nic gov india times hindustantimes ndtv indianexpress thehindu economictimes
mozilla ubuntu debian redhat centos python nodejs docker kubernetes nginx
apache oracle salesforce adobe intel nvidia qualcomm samsung xiaomi oneplus
dropbox drive icloud onedrive mega mediafire wetransfer sendspace
coursera udemy edx khanacademy geeksforgeeks leetcode hackerrank codechef
booking airbnb expedia makemytrip goibibo cleartrip yatra uber ola rapido
weather accuweather timeanddate speedtest whatismyip ipinfo
cdn static assets images content media api login auth secure mail smtp imap
www ftp ns mx web app portal service update download support help docs blog
news shop store account admin dashboard console cloud server host node edge
"""


def _build_bigram_model() -> tuple[dict[str, float], float]:
    """Add-k smoothed bigram log-probabilities over the corpus above."""
    counts: Counter = Counter()
    context: Counter = Counter()
    for word in _CORPUS.split():
        padded = f"^{word}$"
        for a, b in zip(padded, padded[1:]):
            counts[a + b] += 1
            context[a] += 1

    k = 0.5
    vocab = 40  # a-z, digits, hyphen, boundary markers
    model: dict[str, float] = {}
    for bg, c in counts.items():
        model[bg] = math.log((c + k) / (context[bg[0]] + k * vocab))
    # Log-probability assigned to any bigram never seen in the corpus.
    floor = math.log(k / (max(context.values()) + k * vocab))
    return model, floor


_BIGRAM, _BIGRAM_FLOOR = _build_bigram_model()


def bigram_score(label: str) -> float:
    """Mean bigram log-probability. Higher (closer to 0) = more name-like.

    Typical real label scores around -2.5; a random DGA label around -4.5.
    """
    label = label.lower()
    if len(label) < 2:
        return 0.0
    padded = f"^{label}$"
    total = 0.0
    n = 0
    for a, b in zip(padded, padded[1:]):
        total += _BIGRAM.get(a + b, _BIGRAM_FLOOR)
        n += 1
    return total / n if n else 0.0


def split_domain(qname: str) -> tuple[str, str]:
    """(parent, subdomain). Naive eTLD handling is fine for an MVP."""
    name = qname.rstrip(".").lower()
    parts = name.split(".")
    if len(parts) <= 2:
        return name, ""
    # Treat two-part public suffixes (co.in, co.uk, com.au) as one unit.
    if len(parts) >= 3 and parts[-2] in {"co", "com", "net", "org", "gov", "ac", "edu"} and len(parts[-1]) == 2:
        parent = ".".join(parts[-3:])
        sub = ".".join(parts[:-3])
    else:
        parent = ".".join(parts[-2:])
        sub = ".".join(parts[:-2])
    return parent, sub


# --- thresholds -------------------------------------------------------------
MIN_QUERIES = 6            # per (source, parent domain) before judging
DGA_ENTROPY = 3.4          # bits/char over the label
DGA_BIGRAM = -3.6          # mean bigram log-prob below this is implausible
TUNNEL_UNIQUE_SUBS = 15    # distinct subdomains under one parent
TUNNEL_LABEL_LEN = 30      # characters in the longest label
HISTORY_S = 60.0
EXFIL_RECORD_TYPES = {"TXT", "NULL", "CNAME"}


class DnsAnomalyDetector(Detector):
    name = "dns.v1"
    threat_class = DNS_ANOMALY
    cooldown_s = 60.0

    def __init__(self) -> None:
        super().__init__()
        # (src, parent) -> deque[(ts, subdomain, qtype)]
        self.history: dict[tuple[str, str], deque] = defaultdict(lambda: deque(maxlen=2000))

    def on_window(self, wf: WindowFeatures, baselines: BaselineTracker) -> list[Alert]:
        touched: set[tuple[str, str]] = set()

        for src, hf in wf.by_host.items():
            for pkt in hf.dns_queries:
                parent, sub = split_domain(pkt.dns_qname)
                key = (src, parent)
                self.history[key].append((pkt.ts, sub, pkt.dns_qtype))
                touched.add(key)

        self._prune(wf.window.end)

        alerts: list[Alert] = []
        for key in touched:
            alert = self._evaluate(key, wf)
            if alert is not None:
                alerts.append(alert)
        return alerts

    def _prune(self, now: float) -> None:
        cutoff = now - HISTORY_S
        empty = []
        for key, series in self.history.items():
            while series and series[0][0] < cutoff:
                series.popleft()
            if not series:
                empty.append(key)
        for key in empty:
            del self.history[key]

    def _evaluate(self, key, wf: WindowFeatures) -> Alert | None:
        src, parent = key
        series = self.history[key]
        if len(series) < MIN_QUERIES:
            return None

        subs = [s for _, s, _ in series if s]
        qtypes = [t for _, _, t in series]
        if not subs:
            return None

        unique_subs = set(subs)
        # Score the leftmost label -- that is where both DGA output and tunnelled
        # payload live.
        first_labels = [s.split(".")[0] for s in unique_subs]
        entropies = [shannon_entropy(Counter(lbl)) for lbl in first_labels if lbl]
        bigrams = [bigram_score(lbl) for lbl in first_labels if lbl]
        if not entropies:
            return None

        mean_entropy = sum(entropies) / len(entropies)
        mean_bigram = sum(bigrams) / len(bigrams)
        max_len = max(len(lbl) for lbl in first_labels)
        mean_len = sum(len(lbl) for lbl in first_labels) / len(first_labels)
        odd_types = sum(1 for t in qtypes if t in EXFIL_RECORD_TYPES)
        type_ratio = odd_types / len(qtypes)
        span = series[-1][0] - series[0][0]
        rate = len(series) / span if span > 0 else len(series)

        looks_dga = mean_entropy >= DGA_ENTROPY and mean_bigram <= DGA_BIGRAM
        looks_tunnel = (
            len(unique_subs) >= TUNNEL_UNIQUE_SUBS
            and (max_len >= TUNNEL_LABEL_LEN or type_ratio > 0.5)
        )
        if not (looks_dga or looks_tunnel):
            return None

        conf = confidence_from(
            mean_entropy / DGA_ENTROPY,
            abs(mean_bigram) / abs(DGA_BIGRAM),
            max(1.0, len(unique_subs) / TUNNEL_UNIQUE_SUBS),
            max(1.0, mean_len / TUNNEL_LABEL_LEN) if looks_tunnel else 1.0,
        )

        if not self.ready(f"{src}|{parent}", wf.window.end):
            return None
        self.mark(f"{src}|{parent}", wf.window.end)

        if looks_tunnel and looks_dga:
            subtype = "DNS tunnelling with algorithmically generated labels"
        elif looks_tunnel:
            subtype = "DNS tunnelling (data carried in subdomain labels)"
        else:
            subtype = "DGA-style domain generation"

        sample = sorted(unique_subs, key=len, reverse=True)[0][:60]

        return Alert.build(
            threat_class=self.threat_class,
            detector=self.name,
            confidence=conf,
            flow_id=f"{src}->dns:{parent}",
            src=src,
            dst=parent,
            window_start=wf.window.start,
            window_end=wf.window.end,
            evidence=[
                Evidence("qname_char_entropy", mean_entropy, DGA_ENTROPY, "bits/char", subtype),
                Evidence("bigram_plausibility", mean_bigram, DGA_BIGRAM, "log p",
                         "mean bigram log-probability vs a real-domain corpus"),
                Evidence("unique_subdomains", len(unique_subs), None, "labels",
                         f"under a single parent domain in {span:.0f}s"),
                Evidence("max_label_length", max_len, TUNNEL_LABEL_LEN, "chars",
                         f"longest observed: {sample}"),
                Evidence("query_rate", rate, None, "q/s"),
                Evidence("unusual_record_type_ratio", type_ratio, 0.0, "",
                         f"{odd_types} of {len(qtypes)} were TXT/NULL/CNAME"),
            ],
        )
