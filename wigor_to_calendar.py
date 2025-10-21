#!/usr/bin/env python3
# wigor_to_calendar.py
# -*- coding: utf-8 -*-

"""
Wigor → ICS (connexion CAS, découverte automatique hashURL, collecte et export ICS)
Fenêtre par défaut: aujourd'hui → +14 jours (pratique pour un rafraîchissement horaire).

Dépendances:
  pip install requests beautifulsoup4 icalendar pytz

Exemples:
  # mode interactif (mot de passe masqué), logs + dumps HTML
  WIGOR_DEBUG=1 python wigor_to_calendar.py --user prenom.nom --debug --dump-dir /tmp/wigor_dump

  # mot de passe via CLI (attention à l'historique shell)
  python wigor_to_calendar.py --user prenom.nom --password 'mon_mdp'

  # mot de passe via variable d'environnement
  export WIGOR_PASS='mon_mdp'
  python wigor_to_calendar.py --user prenom.nom
"""

from __future__ import annotations

import os
import re
import sys
import getpass
import hashlib
import argparse
import datetime as dt
from dataclasses import dataclass
from typing import List, Optional, Tuple
from html import unescape as html_unescape
from urllib.parse import urlparse, parse_qs, quote, unquote

import pytz
import requests
from bs4 import BeautifulSoup
from icalendar import Calendar, Event, vCalAddress, vText

# ============================
# Constantes
# ============================
PARIS = pytz.timezone("Europe/Paris")
CAS_LOGIN = "https://cas-p.wigorservices.net/cas/login"
BASE_URL = "https://ws-edt-cd.wigorservices.net/WebPsDyn.aspx"

# ============================
# Debug helpers
# ============================
DEBUG = False
DUMP_DIR: Optional[str] = None

def dbg(msg: str, *args):
    if DEBUG:
        print("[DEBUG] " + (msg % args if args else msg), file=sys.stderr)

def mask(s: Optional[str], keep: int = 12) -> str:
    if not s:
        return ""
    return s[:keep] + "…"

def cookies_snapshot(sess: requests.Session) -> str:
    parts = []
    for c in sess.cookies:
        parts.append(f"{c.domain} {c.name}={mask(c.value)}")
    return "; ".join(parts)

def dump_resp(label: str, resp: requests.Response, base_name: str):
    dbg("%s: %s %s", label, resp.status_code, resp.url)
    if "Location" in resp.headers:
        dbg("  header Location: %s", resp.headers["Location"])
    dbg("  cookies: %s", cookies_snapshot(resp))
    if DUMP_DIR:
        try:
            os.makedirs(DUMP_DIR, exist_ok=True)
            path = os.path.join(DUMP_DIR, base_name)
            with open(path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(resp.text or "")
            dbg("  dumped to: %s", path)
        except Exception as e:
            dbg("  dump failed: %s", e)

def prompt_password_interactif(prompt: str = "Mot de passe Wigor: ") -> str:
    """
    Essaie getpass (saisie masquée). Si indisponible (pas de TTY),
    repli sur input() avec avertissement.
    """
    try:
        return getpass.getpass(prompt)
    except Exception:
        print("[WARN] Saisie masquée indisponible; le mot de passe sera visible.", file=sys.stderr)
        return input(prompt)

# ============================
# Modèle
# ============================
@dataclass
class Cours:
    date: dt.date
    start: dt.time
    end: dt.time
    title: str
    location: str
    teacher: Optional[str]
    group: Optional[str]
    teams_url: Optional[str]

# ============================
# Parsing util
# ============================
TIME_RE = re.compile(r"(\d{2}):(\d{2})\s*-\s*(\d{2}):(\d{2})")
LEFT_RE = re.compile(r"left\s*:\s*([0-9.]+)%", re.I)
DATE_REQ_RE = re.compile(r"__DateReq='(\d{2}/\d{2}/\d{4})'")

def parse_percent_left(style: str) -> Optional[float]:
    m = LEFT_RE.search(style or "")
    return float(m.group(1)) if m else None

def monday_of_week(d: dt.date) -> dt.date:
    return d - dt.timedelta(days=d.weekday())

def week_mondays(date_min: dt.date, date_max: dt.date):
    cur = monday_of_week(date_min)
    while cur <= date_max:
        yield cur
        cur += dt.timedelta(days=7)

def mmddyyyy(d: dt.date) -> str:
    return d.strftime("%m/%d/%Y")

def safe_uid(c: Cours) -> str:
    base = f"{c.date.isoformat()}|{c.start.isoformat()}|{c.end.isoformat()}|{c.title}|{c.location}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:24] + "@epsi-wigor"

# ============================
# CAS
# ============================
def parse_hidden_fields(html: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form")
    if not form:
        return {}
    data = {}
    for inp in form.find_all("input"):
        name = inp.get("name")
        if not name:
            continue
        if name in ("username", "password"):
            continue
        data[name] = inp.get("value", "")
    return data

def deep_unquote(s: str, rounds: int = 5) -> str:
    prev = s
    for _ in range(rounds):
        cur = unquote(prev)
        if cur == prev:
            break
        prev = cur
    return prev

def cas_login_and_get_service(session: requests.Session,
                              cas_login_url: str,
                              service_url: str,
                              username: str,
                              password: str) -> tuple[requests.Response, str, str]:
    """
    Retourne (final_response, service_with_ticket_url, final_url_sans_ticket)
    """
    service_q = quote(service_url, safe="")
    dbg("CAS GET login page: %s?service=%s", cas_login_url, service_q)
    login_get = session.get(f"{cas_login_url}?service={service_q}", timeout=30)
    dump_resp("CAS login GET", login_get, "cas_login_get.html")
    login_get.raise_for_status()

    hidden = parse_hidden_fields(login_get.text)
    dbg("hidden fields: %s", ", ".join(sorted(hidden.keys())))

    payload = {
        **hidden,
        "username": username,
        "password": password,
        "_eventId": hidden.get("_eventId", "submit"),
        # champs tolérés par beaucoup de CAS; laissent à vide si absents
        "geolocation": hidden.get("geolocation", ""),
        "deviceFingerprint": hidden.get("deviceFingerprint", ""),
    }

    dbg("CAS POST with creds (masqué).")
    login_post = session.post(f"{cas_login_url}?service={service_q}",
                              data=payload,
                              allow_redirects=False,
                              timeout=30)
    dump_resp("CAS login POST", login_post, "cas_login_post.html")

    if login_post.status_code not in (302, 303) or "Location" not in login_post.headers:
        raise RuntimeError("Échec CAS: pas de redirection avec ticket (identifiants/champs ?).")

    service_with_ticket = login_post.headers["Location"]

    step1 = session.get(service_with_ticket, allow_redirects=False, timeout=30)
    dump_resp("Service step1 (consume ticket)", step1, "service_step1.html")

    if step1.status_code in (301, 302, 303) and "Location" in step1.headers:
        final_url = step1.headers["Location"]  # souvent la même URL sans 'ticket'
        final = session.get(final_url, allow_redirects=True, timeout=30)
        dump_resp("Service final", final, "service_final.html")
    else:
        final_url = step1.url
        final = step1
        dump_resp("Service final (no redirect)", final, "service_final.html")

    if final.status_code != 200:
        raise RuntimeError(f"Échec côté service: HTTP {final.status_code}")

    return final, service_with_ticket, final_url

# ============================
# hashURL discovery
# ============================
_HASH_RE_PLAIN = re.compile(r"hashURL=([A-Fa-f0-9]{16,})")
_HASH_RE_ENC   = re.compile(r"hashURL%3D([A-Fa-f0-9]{16,})", re.I)

def _extract_hash_from_url(url: str) -> Optional[str]:
    try:
        q = parse_qs(urlparse(url).query)
        hv = q.get("hashURL", [""])[0]
        return hv or None
    except Exception:
        return None

def _extract_hash_from_nested_service(url: str) -> Optional[str]:
    try:
        outer_q = parse_qs(urlparse(url).query)
        service_vals = outer_q.get("service")
        if not service_vals:
            return None
        inner = deep_unquote(service_vals[0])
        inner_q = parse_qs(urlparse(inner).query)
        hv = inner_q.get("hashURL", [""])[0]
        return hv or None
    except Exception:
        return None

def _extract_hash_from_text_like_html(text: str) -> Optional[str]:
    if not text:
        return None
    t = html_unescape(text)

    m = _HASH_RE_PLAIN.search(t)
    if m:
        return m.group(1)
    m = _HASH_RE_ENC.search(t)
    if m:
        return m.group(1)

    for href in re.findall(r'https?://[^\s"\'<>]+', t):
        hv = _extract_hash_from_url(href) or _extract_hash_from_nested_service(href)
        if hv:
            return hv
    return None

def discover_hashurl(session: requests.Session,
                     tel: str,
                     service_with_ticket: Optional[str] = None,
                     final_url: Optional[str] = None) -> Optional[str]:
    dbg(">>> discover_hashurl start")

    # 1) regarder les URLs vues pendant le flux CAS
    for label, url in (("service_with_ticket", service_with_ticket),
                       ("final_url", final_url)):
        if not url:
            continue
        dbg("check %s: %s", label, url)
        hv = _extract_hash_from_url(url) or _extract_hash_from_nested_service(url)
        if hv:
            dbg("hashURL via %s: %s", label, hv)
            return hv

    # 2) probes GET avec/ sans Tel/ date
    today = dt.date.today()
    candidates = [
        {"action": "posEDTLMS", "serverID": "C", "Tel": tel, "date": mmddyyyy(today)},
        {"action": "posEDTLMS", "serverID": "C", "date": mmddyyyy(today)},
        {"action": "posEDTLMS", "date": mmddyyyy(today)},
        {"action": "posEDTLMS"},
    ]
    for i, params in enumerate(candidates, 1):
        dbg("hash probe %d: %s", i, params)
        r = session.get(BASE_URL, params=params, allow_redirects=True, timeout=30)
        dump_resp(f"hash_probe_{i}", r, f"hash_probe_{i}.html")
        hv = _extract_hash_from_url(r.url) or _extract_hash_from_nested_service(r.url)
        if hv:
            dbg("hashURL via URL: %s", hv)
            return hv
        hv = _extract_hash_from_text_like_html(r.text)
        if hv:
            dbg("hashURL via HTML: %s", hv)
            return hv

    dbg("hashURL non trouvé; on continue sans (fallback).")
    return None  # <<< volontairement non bloquant

# ============================
# Parsing Wigor
# ============================
def extract_date_req(soup: BeautifulSoup) -> Optional[dt.date]:
    for tag in soup.find_all("script"):
        if not tag.string:
            continue
        m = DATE_REQ_RE.search(tag.string)
        if m:
            return dt.datetime.strptime(m.group(1), "%m/%d/%Y").date()
    return None

def find_midweek_day_headers(soup: BeautifulSoup) -> List[Tuple[float, dt.date]]:
    date_req = extract_date_req(soup)
    if not date_req:
        raise RuntimeError("Impossible de retrouver __DateReq (date de référence).")
    monday = monday_of_week(date_req)

    candidates = []
    for d in soup.select("div.Jour"):
        left = parse_percent_left(d.get("style", ""))
        if left is None:
            continue
        if 100.0 <= left < 200.0:
            candidates.append((left, d))
    candidates.sort(key=lambda t: t[0])
    candidates = candidates[:5]  # lundi..vendredi
    mapping = []
    for i, (left, _) in enumerate(candidates):
        mapping.append((left, monday + dt.timedelta(days=i)))
    return mapping

def nearest_day(date_by_left: List[Tuple[float, dt.date]], left_val: float) -> dt.date:
    return min(date_by_left, key=lambda t: abs(t[0] - left_val))[1]

def parse_cours_from_week(html: str) -> List[Cours]:
    soup = BeautifulSoup(html, "html.parser")
    date_by_left = find_midweek_day_headers(soup)

    cours_list: List[Cours] = []
    for case in soup.select("div.Case"):
        left = parse_percent_left(case.get("style", ""))
        if left is None or not (100.0 <= left < 200.0):
            continue

        title_cell = case.select_one("td.TCase")
        if not title_cell:
            continue
        title = " ".join(title_cell.get_text(" ", strip=True).split())

        teach_cell = case.select_one("td.TCProf")
        teacher, group = None, None
        if teach_cell:
            raw = teach_cell.get_text("\n", strip=True)
            lines = [ln.strip() for ln in raw.split("\n") if ln.strip()]
            if lines:
                teacher = lines[0]
                if len(lines) >= 2:
                    group = lines[1]

        time_cell = case.select_one("td.TChdeb")
        room_cell = case.select_one("td.TCSalle")
        if not time_cell:
            continue
        m = TIME_RE.search(time_cell.get_text(" ", strip=True))
        if not m:
            continue
        sh, sm, eh, em = map(int, m.groups())

        location = ""
        if room_cell:
            txt = room_cell.get_text(" ", strip=True)
            location = re.sub(r"^\s*Salle\s*:\s*", "", txt, flags=re.I)

        date = nearest_day(date_by_left, left)

        teams_url = None
        teams_div = case.select_one("div.Teams")
        if teams_div:
            a = teams_div.find("a", href=True)
            if a:
                teams_url = a["href"]

        cours_list.append(Cours(
            date=date,
            start=dt.time(sh, sm),
            end=dt.time(eh, em),
            title=title,
            location=location,
            teacher=teacher,
            group=group,
            teams_url=teams_url
        ))
    return cours_list

# ============================
# Heuristique: page Wigor valide ?
# ============================
def looks_like_wigor(html: str) -> bool:
    if not html:
        return False
    h = html.lower()
    if "cas/login" in h:
        return False
    return ("class=\"case\"" in h) or ("__datereq='" in h)

# ============================
# Récup pages + collecte
# ============================
def fetch_week_html(session: requests.Session, tel: str, any_date_in_week: dt.date, hash_url: Optional[str]) -> str:
    base_params = [
        {"action": "posEDTLMS", "serverID": "C", "Tel": tel, "date": mmddyyyy(any_date_in_week)},
        {"action": "posEDTLMS", "serverID": "C", "date": mmddyyyy(any_date_in_week)},
        {"action": "posEDTLMS", "date": mmddyyyy(any_date_in_week)},
        {"action": "posEDTLMS"},
    ]
    candidates = []
    if hash_url:
        for p in base_params:
            q = dict(p); q["hashURL"] = hash_url
            candidates.append(q)
    candidates += base_params

    for i, params in enumerate(candidates, 1):
        dbg("GET week %s candidate %d params=%s", any_date_in_week, i, params)
        r = session.get(BASE_URL, params=params, allow_redirects=True, timeout=30)
        dump_resp(f"week_{any_date_in_week}_cand_{i}", r, f"week_{any_date_in_week}_cand_{i}.html")
        if r.status_code == 200 and looks_like_wigor(r.text):
            dbg("week %s OK with candidate %d (url=%s)", any_date_in_week, i, r.url)
            return r.text
        else:
            dbg("week %s cand %d NOT OK (status=%s, url=%s)", any_date_in_week, i, r.status_code, r.url)

    raise RuntimeError("Échec récupération semaine: aucune variante n’a abouti (session expirée ?)")

def collect_all(session: requests.Session, tel: str, date_min: dt.date, date_max: dt.date, hash_url: Optional[str]) -> List[Cours]:
    all_cours: List[Cours] = []
    seen = set()
    for monday in week_mondays(date_min, date_max):
        html = fetch_week_html(session, tel, monday, hash_url)
        week_courses = parse_cours_from_week(html)
        for c in week_courses:
            key = (c.date, c.start, c.end, c.title, c.location)
            if key not in seen:
                seen.add(key)
                all_cours.append(c)
    all_cours.sort(key=lambda c: (c.date, c.start, c.end, c.title))
    dbg("collect_all: %d cours", len(all_cours))
    return all_cours

# ============================
# ICS
# ============================
def build_ics(cours: List[Cours], prod_id: str = "-//EPSI Wigor → ICS//FR") -> Calendar:
    cal = Calendar()
    cal.add("prodid", prod_id)
    cal.add("version", "2.0")
    cal.add("calscale", "GREGORIAN")
    cal.add("method", "PUBLISH")

    organizer = vCalAddress("MAILTO:noreply@example.invalid")
    organizer.params["cn"] = vText("EPSI Wigor")

    for c in cours:
        ev = Event()
        start_dt = PARIS.localize(dt.datetime.combine(c.date, c.start))
        end_dt = PARIS.localize(dt.datetime.combine(c.date, c.end))

        ev.add("uid", safe_uid(c))
        ev.add("dtstart", start_dt)
        ev.add("dtend", end_dt)
        ev.add("summary", c.title)
        if c.location:
            ev.add("location", c.location)
        desc = []
        if c.teacher:
            desc.append(f"Intervenant: {c.teacher}")
        if c.group:
            desc.append(f"Groupe: {c.group}")
        if c.teams_url:
            desc.append(f"Teams: {c.teams_url}")
        if desc:
            ev.add("description", "\n".join(desc))
        ev.add("organizer", organizer)
        ev.add("transp", "OPAQUE")
        cal.add_component(ev)

    return cal

# ============================
# Range par défaut
# ============================
def default_two_weeks(today: dt.date) -> Tuple[dt.date, dt.date]:
    return today, today + dt.timedelta(days=30)

# ============================
# Login + génération
# ============================
def login_discover_and_collect(username: str, password: str, date_min: dt.date, date_max: dt.date) -> Calendar:
    tel = username  # adapter si besoin
    with requests.Session() as s:
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3",
        })
        dbg("initial cookies: %s", cookies_snapshot(s))

        # Service minimal pour le param 'service' CAS (Tel + date aident Wigor à se positionner)
        service_for_cas = f"{BASE_URL}?action=posEDTLMS&serverID=C&Tel={tel}&date={mmddyyyy(dt.date.today())}"
        dbg("service_for_cas: %s", service_for_cas)

        final, service_with_ticket, final_url = cas_login_and_get_service(
            s, CAS_LOGIN, service_for_cas, username, password
        )
        dbg("post-login cookies: %s", cookies_snapshot(s))

        # hashURL (facultatif) — on essaie de le deviner sinon on tentera sans
        hash_url = discover_hashurl(s, tel, service_with_ticket=service_with_ticket, final_url=final_url)
        dbg("hashURL resolved: %s", hash_url or "(none)")

        cours = collect_all(s, tel, date_min, date_max, hash_url)
        return build_ics(cours)

# ============================
# CLI
# ============================
def main():
    global DEBUG, DUMP_DIR
    ap = argparse.ArgumentParser(description="Export Wigor → ICS (par défaut 14 jours) + debug")
    ap.add_argument("--user", dest="user", help="Identifiant Wigor (ex: prenom.nom). Par défaut: $WIGOR_USER.")
    ap.add_argument("--password", dest="password", help="Mot de passe Wigor (sinon $WIGOR_PASS ou prompt).")
    ap.add_argument("--ics-out", default="epsi_wigor.ics", help="Fichier ICS de sortie.")
    ap.add_argument("--from", dest="date_from", help="Date début (YYYY-MM-DD). Par défaut: aujourd'hui.")
    ap.add_argument("--to", dest="date_to", help="Date fin (YYYY-MM-DD). Par défaut: +14 jours.")
    ap.add_argument("--debug", action="store_true", help="Activer le mode debug verbeux.")
    ap.add_argument("--dump-dir", help="Répertoire où sauver les HTML (debug).")
    args = ap.parse_args()

    DEBUG = args.debug or (os.getenv("WIGOR_DEBUG", "0") not in ("0", "", "false", "False"))
    DUMP_DIR = args.dump_dir

    user = args.user or os.environ.get("WIGOR_USER") or input("Identifiant Wigor: ").strip()

    # Mot de passe — priorité CLI > ENV > prompt interactif
    if args.password:
        dbg("Mot de passe: fourni via --password (masqué).")
        pwd = args.password
    elif os.environ.get("WIGOR_PASS"):
        dbg("Mot de passe: pris via variable d'environnement WIGOR_PASS (masqué).")
        pwd = os.environ["WIGOR_PASS"]
    else:
        dbg("Mot de passe: demande interactive (getpass).")
        pwd = prompt_password_interactif("Mot de passe Wigor: ")

    if args.date_from and args.date_to:
        dmin = dt.date.fromisoformat(args.date_from)
        dmax = dt.date.fromisoformat(args.date_to)
    else:
        dmin, dmax = default_two_weeks(dt.date.today())

    try:
        cal = login_discover_and_collect(user, pwd, dmin, dmax)
    except Exception as e:
        dbg("FATAL: %r", e)
        raise

    with open(args.ics_out, "wb") as f:
        f.write(cal.to_ical())
    print(f"ICS écrit → {args.ics_out}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrompu.", file=sys.stderr)
        sys.exit(130)
