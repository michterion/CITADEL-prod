import os
import calendar
import uuid
import json
import hashlib
import secrets
from urllib.parse import urlparse
from datetime import date, datetime, timedelta, timezone
from dateutil.relativedelta import relativedelta
from dateutil import tz
import pandas as pd
import streamlit as st
import plotly.graph_objects as go
import psycopg
from psycopg import errors
from psycopg_pool import ConnectionPool

pd.set_option('future.no_silent_downcasting', True)

# --- ARCHITEKTURA CZASU: ROZDZIAŁ ZAPISU (UTC) OD BIZNESU/UI (WARSZAWA) ---
WARSAW_TZ = tz.gettz("Europe/Warsaw")

def teraz_utc():
    return datetime.now(timezone.utc)

def dzis_pl():
    return datetime.now(WARSAW_TZ).date()

def formatuj_czas_pl(val):
    if val is None:
        return "b/d"
    try:
        if pd.isna(val):
            return "b/d"
    except (ValueError, TypeError):
        pass

    if isinstance(val, str):
        val_clean = val.strip().lower()
        if not val_clean or val_clean in ("none", "nat", "nan", "b/d", "null"):
            return "b/d"
        try:
            val = pd.to_datetime(val)
        except Exception:
            return str(val)

    if isinstance(val, (datetime, pd.Timestamp)):
        if pd.isna(val):
            return "b/d"
        if val.tzinfo is None:
            val = val.replace(tzinfo=timezone.utc)
        return val.astimezone(WARSAW_TZ).strftime("%Y-%m-%d %H:%M:%S")
    return str(val)

def parse_date(d):
    if isinstance(d, datetime):
        return d.date()
    if isinstance(d, date):
        return d
    return pd.to_datetime(d).date()

def waliduj_daty_czlonka(ur, wst):
    dzis = dzis_pl()
    if ur > dzis:
        return False, "Data urodzenia nie może być z przyszłości!"
    if wst > dzis:
        return False, "Data przystąpienia nie może być z przyszłości!"
    if wst < ur:
        return False, "Data przystąpienia nie może być wcześniejsza niż data urodzenia!"
    
    wiek_wstapienia = wst.year - ur.year - ((wst.month, wst.day) < (ur.month, ur.day))
    if wiek_wstapienia < 13:
        return False, f"Członek w momencie przystąpienia musi mieć ukończone co najmniej 13 lat (obliczono: {wiek_wstapienia} lat)!"
    return True, ""

# --- BEZPIECZEŃSTWO I HASZOWANIE HASEŁ (NIST PBKDF2-HMAC-SHA256) ---
def generuj_sol():
    return secrets.token_hex(16)

def hashuj_haslo(haslo: str, sol: str) -> str:
    h = hashlib.pbkdf2_hmac("sha256", haslo.encode("utf-8"), sol.encode("utf-8"), 200_000)
    return h.hex()

def weryfikuj_haslo(haslo: str, sol: str, oczekiwany_hash: str) -> bool:
    obliczony = hashuj_haslo(haslo, sol)
    return secrets.compare_digest(obliczony, oczekiwany_hash)

st.set_page_config(page_title="Citadel for NG", layout="wide", initial_sidebar_state="collapsed")

DATA_ODCIECIA = date(2026, 10, 1)

# --- PARAMETRY POŁĄCZENIA POSTGRESQL (NEON / CLOUD COMPLIANT) ---
def get_db_conninfo():
    if "DATABASE_URL" in st.secrets:
        return st.secrets["DATABASE_URL"]
    elif "postgres" in st.secrets:
        cfg = st.secrets["postgres"]
        ssl = f" sslmode={cfg.get('sslmode', 'require')}" if "sslmode" in cfg or "neon.tech" in str(cfg.get('host', '')) else ""
        return f"host={cfg['host']} port={cfg.get('port', 5432)} dbname={cfg['dbname']} user={cfg['user']} password='{cfg['password']}'" + ssl
    elif "DATABASE_URL" in os.environ:
        return os.environ["DATABASE_URL"]
    return None

@st.cache_resource
def get_db_pool():
    conninfo = get_db_conninfo()
    if not conninfo:
        st.error("⚠️ Brak konfiguracji bazy danych w secrets.toml lub zmiennej DATABASE_URL.")
        st.stop()
    return ConnectionPool(conninfo=conninfo, min_size=1, max_size=5, open=True)

pool = get_db_pool()

def db_query(sql: str, params=None) -> pd.DataFrame:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            if cur.description:
                cols = [desc[0] for desc in cur.description]
                rows = cur.fetchall()
                return pd.DataFrame(rows, columns=cols)
            return pd.DataFrame()

def db_execute(sql: str, params=None):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
        conn.commit()

def db_scalar(sql: str, params=None):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            row = cur.fetchone()
            return row[0] if row else None

# --- GENERATOR ZRZUTU BAZY DANYCH (.sql) ---
DDL_SCHEMA_EXPORT = """-- === DEFINICJE STRUKTURY DANYCH (DDL) ===
CREATE TABLE IF NOT EXISTS kraje (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    nazwa TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS regiony (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kraj_id BIGINT REFERENCES kraje(id) ON DELETE SET NULL,
    nazwa TEXT NOT NULL,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS kola (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kraj_id BIGINT REFERENCES kraje(id) ON DELETE RESTRICT DEFAULT 1,
    nazwa TEXT NOT NULL,
    region_id BIGINT REFERENCES regiony(id) ON DELETE SET NULL,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at TIMESTAMPTZ,
    deleted_by_region_id BIGINT REFERENCES regiony(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS uzytkownicy (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    login TEXT NOT NULL UNIQUE,
    haslo_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    imie_nazwisko TEXT NOT NULL,
    rola TEXT NOT NULL CHECK (rola IN ('ADMIN', 'SKARBNIK_KRAJOWY', 'SKARBNIK_REGIONU', 'SKARBNIK_KOLA')),
    kraj_id BIGINT REFERENCES kraje(id) ON DELETE SET NULL,
    region_id BIGINT REFERENCES regiony(id) ON DELETE SET NULL,
    kolo_id BIGINT REFERENCES kola(id) ON DELETE SET NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    wymus_zmiane_hasla BOOLEAN NOT NULL DEFAULT FALSE,
    ostatnie_logowanie TIMESTAMPTZ,
    utworzono_o TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS czlonkowie (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kolo_id BIGINT NOT NULL DEFAULT 1 REFERENCES kola(id) ON DELETE RESTRICT,
    imie_nazwisko TEXT NOT NULL,
    data_urodzenia DATE NOT NULL,
    data_przystapienia DATE NOT NULL,
    saldo_startowe_gr BIGINT DEFAULT 0,
    reczny_parametr TEXT DEFAULT 'AUTO'
);
CREATE TABLE IF NOT EXISTS wplaty (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kolo_id BIGINT NOT NULL REFERENCES kola(id) ON DELETE RESTRICT,
    czlonek_id BIGINT REFERENCES czlonkowie(id) ON DELETE SET NULL,
    kwota_gr BIGINT NOT NULL,
    data_wplaty DATE NOT NULL,
    notatka TEXT,
    data_wpisu TIMESTAMPTZ NOT NULL,
    idempotency_key TEXT UNIQUE
);
CREATE TABLE IF NOT EXISTS wplaty_oczekujace (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kolo_id BIGINT NOT NULL REFERENCES kola(id) ON DELETE RESTRICT,
    czlonek_id BIGINT REFERENCES czlonkowie(id) ON DELETE SET NULL,
    zglosil_uzytkownik_id BIGINT REFERENCES uzytkownicy(id) ON DELETE SET NULL,
    kwota_gr BIGINT NOT NULL CHECK (kwota_gr > 0),
    data_wplaty DATE NOT NULL CHECK (data_wplaty >= '2015-01-01'),
    notatka TEXT,
    oswiadczenie TEXT NOT NULL CHECK (oswiadczenie IN ('MAM_POTWIERDZENIE', 'BRAK_POTWIERDZENIA')),
    status TEXT NOT NULL DEFAULT 'OCZEKUJE' CHECK (status IN ('OCZEKUJE', 'ZAAKCEPTOWANA', 'ODRZUCONA')),
    data_zgloszenia TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rozpatrzyl_uzytkownik_id BIGINT REFERENCES uzytkownicy(id) ON DELETE SET NULL,
    data_rozpatrzenia TIMESTAMPTZ,
    powod_odrzucenia TEXT
);
CREATE TABLE IF NOT EXISTS naliczenia_reczne (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    czlonek_id BIGINT NOT NULL REFERENCES czlonkowie(id) ON DELETE CASCADE,
    kwota_gr BIGINT NOT NULL,
    data_naliczenia DATE NOT NULL,
    tytul TEXT NOT NULL,
    data_wpisu TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS korekty (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    czlonek_id BIGINT NOT NULL REFERENCES czlonkowie(id) ON DELETE CASCADE,
    delta_gr BIGINT NOT NULL,
    docelowe_saldo_gr BIGINT NOT NULL,
    data_korekty DATE NOT NULL,
    powod TEXT,
    data_wpisu TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS wydatki (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kolo_id BIGINT NOT NULL REFERENCES kola(id) ON DELETE RESTRICT,
    kwota_gr BIGINT NOT NULL,
    data_wydatku DATE NOT NULL,
    kategoria TEXT,
    opis TEXT,
    data_wpisu TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS korekty_kasy (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kolo_id BIGINT NOT NULL REFERENCES kola(id) ON DELETE RESTRICT,
    delta_gr BIGINT NOT NULL,
    docelowy_stan_gr BIGINT NOT NULL,
    data_korekty DATE NOT NULL,
    powod TEXT,
    data_wpisu TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tabela VARCHAR(50) NOT NULL,
    operacja VARCHAR(10) NOT NULL,
    rekord_id BIGINT,
    stare_dane JSONB,
    nowe_dane JSONB,
    zmieniono_o TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

def format_val_sql(v):
    if v is None:
        return "NULL"
    elif isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    elif isinstance(v, (int, float)):
        return str(v)
    elif isinstance(v, (dict, list)):
        s = json.dumps(v, ensure_ascii=False).replace("'", "''")
        return f"'{s}'"
    else:
        s = str(v).replace("'", "''")
        return f"'{s}'"

def generuj_zrzut_bazy_sql():
    os.makedirs("backups", exist_ok=True)
    timestamp_str = datetime.now(WARSAW_TZ).strftime("%Y%m%d_%H%M%S")
    filename = f"citadel_backup_{timestamp_str}.sql"
    filepath = os.path.join("backups", filename)
    
    tabele_parent_to_child = [
        "kraje", "regiony", "kola", "uzytkownicy", "czlonkowie", 
        "wplaty", "wplaty_oczekujace", "naliczenia_reczne", "korekty", "wydatki", "korekty_kasy", "audit_log"
    ]
    tabele_child_to_parent = tabele_parent_to_child[::-1]

    with open(filepath, "w", encoding="utf-8") as f_out:
        f_out.write("-- =========================================================================\n")
        f_out.write("-- CITADEL NG — PEŁNY ZRZUT BAZY DANYCH (POSTGRESQL)\n")
        f_out.write(f"-- Data wygenerowania: {datetime.now(WARSAW_TZ).strftime('%Y-%m-%d %H:%M:%S')} (Warszawa)\n")
        f_out.write("-- Silnik: Citadel Native Python Engine (Brak wymogu SUPERUSER)\n")
        f_out.write("-- =========================================================================\n\n")
        f_out.write("SET statement_timeout = 0;\n")
        f_out.write("SET client_encoding = 'UTF8';\n")
        f_out.write("SET standard_conforming_strings = on;\n")
        f_out.write("SET check_function_bodies = false;\n")
        f_out.write("SET client_min_messages = warning;\n")
        f_out.write("SET row_security = off;\n")
        f_out.write("SET session_replication_role = replica;\n\n")
        f_out.write("BEGIN;\n\n")
        f_out.write(DDL_SCHEMA_EXPORT)
        f_out.write("\n-- === CZYSZCZENIE DANYCH PRZED IMPORTEM ===\n")
        
        truncate_list = ", ".join([f'"{t}"' for t in tabele_child_to_parent])
        f_out.write(f"TRUNCATE TABLE {truncate_list} CASCADE;\n\n")

        with pool.connection() as conn:
            with conn.cursor() as cur:
                for tab in tabele_parent_to_child:
                    cur.execute("""
                        SELECT column_name, identity_generation
                        FROM information_schema.columns 
                        WHERE table_name = %s 
                        ORDER BY ordinal_position
                    """, (tab,))
                    cols_info = cur.fetchall()
                    if not cols_info:
                        continue
                    
                    col_names = [c[0] for c in cols_info]
                    has_always_identity = any(c[1] == 'ALWAYS' for c in cols_info)
                    overriding_clause = " OVERRIDING SYSTEM VALUE" if has_always_identity else ""
                    col_names_escaped = ", ".join([f'"{c}"' for c in col_names])

                    cur.execute(f'SELECT {col_names_escaped} FROM "{tab}" ORDER BY id ASC')
                    rows = cur.fetchall()

                    f_out.write(f"\n-- Tabela: {tab} ({len(rows)} rekordów)\n")
                    for r in rows:
                        vals = [format_val_sql(v) for v in r]
                        f_out.write(f'INSERT INTO "{tab}" ({col_names_escaped}){overriding_clause} VALUES ({", ".join(vals)});\n')
                    
                    if rows:
                        f_out.write(f'SELECT setval(pg_get_serial_sequence(\'"{tab}"\', \'id\'), COALESCE(max(id), 1)) FROM "{tab}";\n')

        f_out.write("\nCOMMIT;\n\n")
        f_out.write("SET session_replication_role = DEFAULT;\n")

    file_size_kb = os.path.getsize(filepath) / 1024.0
    return filepath, filename, file_size_kb, "Citadel Python Engine (FK-safe + RBAC)"

# --- ZARZĄDZANIE CYKLEM ŻYCIA DANYCH ---
def usun_czlonka_bezpiecznie(czlonek_id: int):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT imie_nazwisko FROM czlonkowie WHERE id = %s", (czlonek_id,))
            row = cur.fetchone()
            if not row:
                raise ValueError(f"Członek o ID #{czlonek_id} nie istnieje lub został już usunięty.")
            nazwa_czlonka = row[0]

            cur.execute("""
                UPDATE wplaty 
                SET czlonek_id = NULL,
                    notatka = COALESCE(notatka, '') || ' [Wpłata usuniętego członka: ' || %s || ']'
                WHERE czlonek_id = %s
            """, (nazwa_czlonka, czlonek_id))

            cur.execute("DELETE FROM naliczenia_reczne WHERE czlonek_id = %s", (czlonek_id,))
            cur.execute("DELETE FROM korekty WHERE czlonek_id = %s", (czlonek_id,))
            cur.execute("DELETE FROM czlonkowie WHERE id = %s", (czlonek_id,))
        conn.commit()
    st.cache_data.clear()

def przenies_kolo_do_kosza(kolo_id: int):
    teraz = teraz_utc()
    db_execute("""
        UPDATE kola 
        SET is_deleted = TRUE, deleted_at = %s, deleted_by_region_id = NULL 
        WHERE id = %s
    """, (teraz, kolo_id))
    st.cache_data.clear()

def przywroc_kolo_z_kosza(kolo_id: int):
    region_info = db_query("""
        SELECT r.nazwa, r.is_deleted 
        FROM kola k 
        JOIN regiony r ON k.region_id = r.id 
        WHERE k.id = %s
    """, (kolo_id,))
    
    if not region_info.empty and region_info.iloc[0]["is_deleted"]:
        nazwa_r = region_info.iloc[0]["nazwa"]
        raise ValueError(f"Nie można przywrócić koła: jego region nadrzędny ('{nazwa_r}') znajduje się w koszu!")
        
    db_execute("""
        UPDATE kola 
        SET is_deleted = FALSE, deleted_at = NULL, deleted_by_region_id = NULL 
        WHERE id = %s
    """, (kolo_id,))
    st.cache_data.clear()

def przenies_region_do_kosza(region_id: int):
    teraz = teraz_utc()
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE regiony SET is_deleted = TRUE, deleted_at = %s WHERE id = %s", (teraz, region_id))
            cur.execute("""
                UPDATE kola 
                SET is_deleted = TRUE, deleted_at = %s, deleted_by_region_id = %s 
                WHERE region_id = %s AND is_deleted = FALSE
            """, (teraz, region_id, region_id))
        conn.commit()
    st.cache_data.clear()

def przywroc_region_z_kosza(region_id: int):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE kola 
                SET is_deleted = FALSE, deleted_at = NULL, deleted_by_region_id = NULL 
                WHERE region_id = %s AND is_deleted = TRUE AND deleted_by_region_id = %s
            """, (region_id, region_id))
            cur.execute("UPDATE regiony SET is_deleted = FALSE, deleted_at = NULL WHERE id = %s", (region_id,))
        conn.commit()
    st.cache_data.clear()

def usun_kolo_trwale(kolo_id: int):
    is_del = db_scalar("SELECT is_deleted FROM kola WHERE id = %s", (kolo_id,))
    if is_del is not True:
        raise ValueError("Nie można trwale usunąć aktywnego koła! Przenieś je najpierw do kosza.")
        
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM wplaty WHERE kolo_id = %s OR czlonek_id IN (SELECT id FROM czlonkowie WHERE kolo_id = %s)", (kolo_id, kolo_id))
            cur.execute("DELETE FROM wplaty_oczekujace WHERE kolo_id = %s", (kolo_id,))
            cur.execute("DELETE FROM naliczenia_reczne WHERE czlonek_id IN (SELECT id FROM czlonkowie WHERE kolo_id = %s)", (kolo_id,))
            cur.execute("DELETE FROM korekty WHERE czlonek_id IN (SELECT id FROM czlonkowie WHERE kolo_id = %s)", (kolo_id,))
            cur.execute("DELETE FROM czlonkowie WHERE kolo_id = %s", (kolo_id,))
            cur.execute("DELETE FROM wydatki WHERE kolo_id = %s", (kolo_id,))
            cur.execute("DELETE FROM korekty_kasy WHERE kolo_id = %s", (kolo_id,))
            cur.execute("DELETE FROM kola WHERE id = %s", (kolo_id,))
        conn.commit()
    st.cache_data.clear()

def usun_region_trwale(region_id: int):
    is_del = db_scalar("SELECT is_deleted FROM regiony WHERE id = %s", (region_id,))
    if is_del is not True:
        raise ValueError("Nie można trwale usunąć aktywnego regionu! Przenieś go najpierw do kosza.")

    kolo_ids = db_query("SELECT id FROM kola WHERE region_id = %s", (region_id,))["id"].tolist()
    for k_id in kolo_ids:
        usun_kolo_trwale(k_id)

    db_execute("DELETE FROM regiony WHERE id = %s", (region_id,))
    st.cache_data.clear()

# --- SKALE KOLORÓW KDI I UPRAWNIEŃ ---
KDI_STOPS = [
    (0.1, (22, 130, 60)),
    (0.5, (74, 222, 128)),
    (1.0, (255, 255, 255)),
    (1.2, (250, 204, 21)),
    (2.0, (249, 115, 22)),
    (3.0, (239, 68, 68)),
    (5.0, (236, 72, 153)),
    (10.0, (59, 130, 246)),
    (20.0, (168, 85, 247)),
]

def pobierz_kolor_kdi(wartosc):
    if wartosc is None:
        return "#64748b"
    try:
        val = float(wartosc)
    except (ValueError, TypeError):
        return "#64748b"

    if val <= KDI_STOPS[0][0]:
        r, g, b = KDI_STOPS[0][1]
        return f"#{r:02x}{g:02x}{b:02x}"
    if val >= KDI_STOPS[-1][0]:
        r, g, b = KDI_STOPS[-1][1]
        return f"#{r:02x}{g:02x}{b:02x}"

    for i in range(len(KDI_STOPS) - 1):
        v1, c1 = KDI_STOPS[i]
        v2, c2 = KDI_STOPS[i + 1]
        if v1 <= val <= v2:
            t = (val - v1) / (v2 - v1)
            r = int(c1[0] + t * (c2[0] - c1[0]))
            g = int(c1[1] + t * (c2[1] - c1[1]))
            b = int(c1[2] + t * (c2[2] - c1[2]))
            return f"#{r:02x}{g:02x}{b:02x}"
    return "#ffffff"

UPRAWNIENI_STOPS = [
    (100.0, (22, 130, 60)),
    (90.0,  (74, 222, 128)),
    (80.0,  (255, 255, 255)),
    (70.0,  (250, 204, 21)),
    (55.0,  (249, 115, 22)),
    (40.0,  (239, 68, 68)),
    (25.0,  (236, 72, 153)),
    (10.0,  (59, 130, 246)),
    (0.0,   (168, 85, 247)),
]

def pobierz_kolor_uprawnionych(procent):
    if procent is None:
        return "#64748b"
    try:
        val = float(procent)
    except (ValueError, TypeError):
        return "#64748b"

    if val >= UPRAWNIENI_STOPS[0][0]:
        r, g, b = UPRAWNIENI_STOPS[0][1]
        return f"#{r:02x}{g:02x}{b:02x}"
    if val <= UPRAWNIENI_STOPS[-1][0]:
        r, g, b = UPRAWNIENI_STOPS[-1][1]
        return f"#{r:02x}{g:02x}{b:02x}"

    for i in range(len(UPRAWNIENI_STOPS) - 1):
        v1, c1 = UPRAWNIENI_STOPS[i]
        v2, c2 = UPRAWNIENI_STOPS[i + 1]
        if v2 <= val <= v1:
            t = (v1 - val) / (v1 - v2)
            r = int(c1[0] + t * (c2[0] - c1[0]))
            g = int(c1[1] + t * (c2[1] - c1[1]))
            b = int(c1[2] + t * (c2[2] - c1[2]))
            return f"#{r:02x}{g:02x}{b:02x}"
    return "#ffffff"

DARK_THEME_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
    .stApp { background-color: #0b0914; color: #f1f5f9; }
    
    .bento-card {
        background: #151226;
        border: 1px solid #262040;
        border-radius: 18px;
        padding: 20px;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
        margin-bottom: 20px;
    }
    .bento-card-header {
        font-size: 0.8rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #94a3b8;
        margin-bottom: 6px;
    }
    .bento-card-value { font-size: 1.8rem; font-weight: 700; color: #ffffff; }
    .bento-card-sub { font-size: 0.8rem; margin-top: 5px; color: #64748b; }
    
    .accent-purple { color: #a855f7; }
    .accent-cyan { color: #06b6d4; }
    .accent-green { color: #10b981; }
    .accent-rose { color: #f43f5e; }

    .user-pill {
        display: inline-flex;
        align-items: center;
        background: #191430;
        border: 1px solid #332658;
        border-radius: 12px;
        padding: 6px 14px;
        font-size: 0.88rem;
        color: #e2e8f0;
    }

    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: #120e20;
        padding: 6px;
        border-radius: 14px;
        border: 1px solid #231c38;
    }
    .stTabs [data-baseweb="tab"] {
        height: 40px;
        border-radius: 10px;
        color: #94a3b8;
        border: none;
        padding: 0 16px;
        font-weight: 500;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #7c3aed 0%, #4f46e5 100%) !important;
        color: #ffffff !important;
        box-shadow: 0 4px 12px rgba(124, 58, 237, 0.35);
    }
    .stTextInput > div > div, .stNumberInput > div > div, .stSelectbox > div > div, .stDateInput > div > div {
        background-color: #161226 !important;
        border: 1px solid #2b2347 !important;
        border-radius: 10px !important;
        color: #ffffff !important;
    }
    .stButton > button, div[data-testid="stFormSubmitButton"] > button {
        background: linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%) !important;
        color: white !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 9px 22px !important;
        font-weight: 600 !important;
        box-shadow: 0 4px 14px rgba(99, 102, 241, 0.4) !important;
    }
    div[data-testid="stRadio"] label, div[data-testid="stRadio"] label p {
        color: #f1f5f9 !important;
        font-weight: 600 !important;
    }
</style>
"""
st.markdown(DARK_THEME_CSS, unsafe_allow_html=True)

# --- INICJALIZACJA STRUKTURY (TYLKO RAZ NA START SERWERA DZIĘKI @st.cache_resource) ---
@st.cache_resource(show_spinner=False)
def init_db_once():
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS kraje (
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    nazwa TEXT NOT NULL UNIQUE
                );
            """)
            cur.execute("INSERT INTO kraje (nazwa) VALUES ('Polska') ON CONFLICT (nazwa) DO NOTHING;")

            cur.execute("""
                CREATE TABLE IF NOT EXISTS regiony (
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    kraj_id BIGINT REFERENCES kraje(id) ON DELETE SET NULL,
                    nazwa TEXT NOT NULL,
                    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
                    deleted_at TIMESTAMPTZ
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS kola (
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    kraj_id BIGINT REFERENCES kraje(id) ON DELETE RESTRICT DEFAULT 1,
                    nazwa TEXT NOT NULL,
                    region_id BIGINT REFERENCES regiony(id) ON DELETE SET NULL,
                    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
                    deleted_at TIMESTAMPTZ,
                    deleted_by_region_id BIGINT REFERENCES regiony(id) ON DELETE SET NULL
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS uzytkownicy (
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    login TEXT NOT NULL UNIQUE,
                    haslo_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    imie_nazwisko TEXT NOT NULL,
                    rola TEXT NOT NULL CHECK (rola IN ('ADMIN', 'SKARBNIK_KRAJOWY', 'SKARBNIK_REGIONU', 'SKARBNIK_KOLA')),
                    kraj_id BIGINT REFERENCES kraje(id) ON DELETE SET NULL,
                    region_id BIGINT REFERENCES regiony(id) ON DELETE SET NULL,
                    kolo_id BIGINT REFERENCES kola(id) ON DELETE SET NULL,
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    wymus_zmiane_hasla BOOLEAN NOT NULL DEFAULT FALSE,
                    ostatnie_logowanie TIMESTAMPTZ,
                    utworzono_o TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_uzytkownicy_login ON uzytkownicy(login);
            """)
            cur.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS uq_aktywne_kola_nazwa 
                ON kola (nazwa) WHERE (is_deleted = FALSE);
            """)
            cur.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS uq_aktywne_regiony_nazwa 
                ON regiony (kraj_id, nazwa) WHERE (is_deleted = FALSE);
            """)
            cur.execute("""
                CREATE OR REPLACE VIEW aktywne_regiony AS
                SELECT * FROM regiony WHERE is_deleted = FALSE;
            """)
            cur.execute("""
                CREATE OR REPLACE VIEW aktywne_kola AS
                SELECT * FROM kola WHERE is_deleted = FALSE;
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS czlonkowie (
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    kolo_id BIGINT NOT NULL DEFAULT 1 REFERENCES kola(id) ON DELETE RESTRICT,
                    imie_nazwisko TEXT NOT NULL,
                    data_urodzenia DATE NOT NULL,
                    data_przystapienia DATE NOT NULL,
                    saldo_startowe_gr BIGINT DEFAULT 0,
                    reczny_parametr TEXT DEFAULT 'AUTO'
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS wplaty (
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    kolo_id BIGINT NOT NULL REFERENCES kola(id) ON DELETE RESTRICT,
                    czlonek_id BIGINT REFERENCES czlonkowie(id) ON DELETE SET NULL,
                    kwota_gr BIGINT NOT NULL,
                    data_wplaty DATE NOT NULL,
                    notatka TEXT,
                    data_wpisu TIMESTAMPTZ NOT NULL,
                    idempotency_key TEXT UNIQUE
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS wplaty_oczekujace (
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    kolo_id BIGINT NOT NULL REFERENCES kola(id) ON DELETE RESTRICT,
                    czlonek_id BIGINT REFERENCES czlonkowie(id) ON DELETE SET NULL,
                    zglosil_uzytkownik_id BIGINT REFERENCES uzytkownicy(id) ON DELETE SET NULL,
                    kwota_gr BIGINT NOT NULL CHECK (kwota_gr > 0),
                    data_wplaty DATE NOT NULL CHECK (data_wplaty >= '2015-01-01'),
                    notatka TEXT,
                    oswiadczenie TEXT NOT NULL CHECK (oswiadczenie IN ('MAM_POTWIERDZENIE', 'BRAK_POTWIERDZENIA')),
                    status TEXT NOT NULL DEFAULT 'OCZEKUJE' CHECK (status IN ('OCZEKUJE', 'ZAAKCEPTOWANA', 'ODRZUCONA')),
                    data_zgloszenia TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    rozpatrzyl_uzytkownik_id BIGINT REFERENCES uzytkownicy(id) ON DELETE SET NULL,
                    data_rozpatrzenia TIMESTAMPTZ,
                    powod_odrzucenia TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_wplaty_oczekujace_status ON wplaty_oczekujace(status);
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS naliczenia_reczne (
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    czlonek_id BIGINT NOT NULL REFERENCES czlonkowie(id) ON DELETE CASCADE,
                    kwota_gr BIGINT NOT NULL,
                    data_naliczenia DATE NOT NULL,
                    tytul TEXT NOT NULL,
                    data_wpisu TIMESTAMPTZ NOT NULL
                );
                CREATE TABLE IF NOT EXISTS korekty (
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    czlonek_id BIGINT NOT NULL REFERENCES czlonkowie(id) ON DELETE CASCADE,
                    delta_gr BIGINT NOT NULL,
                    docelowe_saldo_gr BIGINT NOT NULL,
                    data_korekty DATE NOT NULL,
                    powod TEXT,
                    data_wpisu TIMESTAMPTZ NOT NULL
                );
                CREATE TABLE IF NOT EXISTS wydatki (
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    kolo_id BIGINT NOT NULL REFERENCES kola(id) ON DELETE RESTRICT,
                    kwota_gr BIGINT NOT NULL,
                    data_wydatku DATE NOT NULL,
                    kategoria TEXT,
                    opis TEXT,
                    data_wpisu TIMESTAMPTZ NOT NULL
                );
                CREATE TABLE IF NOT EXISTS korekty_kasy (
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    kolo_id BIGINT NOT NULL REFERENCES kola(id) ON DELETE RESTRICT,
                    delta_gr BIGINT NOT NULL,
                    docelowy_stan_gr BIGINT NOT NULL,
                    data_korekty DATE NOT NULL,
                    powod TEXT,
                    data_wpisu TIMESTAMPTZ NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    tabela VARCHAR(50) NOT NULL,
                    operacja VARCHAR(10) NOT NULL,
                    rekord_id BIGINT,
                    stare_dane JSONB,
                    nowe_dane JSONB,
                    zmieniono_o TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_audit_log_tabela_czas ON audit_log(tabela, zmieniono_o DESC);
            """)
            cur.execute("SELECT COUNT(*) FROM uzytkownicy WHERE rola = 'ADMIN';")
            if cur.fetchone()[0] == 0:
                s_salt = generuj_sol()
                s_pass_hash = hashuj_haslo("Centauri2026!", s_salt)
                cur.execute("""
                    INSERT INTO uzytkownicy (login, haslo_hash, salt, imie_nazwisko, rola, is_active, wymus_zmiane_hasla)
                    VALUES ('admin', %s, %s, 'Super Administrator', 'ADMIN', TRUE, TRUE);
                """, (s_pass_hash, s_salt))
        conn.commit()
    return True

init_db_once()

# Słowniki metadanych z pamięcią podręczną
@st.cache_data(ttl=60, show_spinner=False)
def pobierz_slownik_krajow():
    return db_query("SELECT id, nazwa FROM kraje ORDER BY id ASC")

@st.cache_data(ttl=60, show_spinner=False)
def pobierz_slownik_regionow(kraj_id):
    return db_query("SELECT id, nazwa FROM aktywne_regiony WHERE kraj_id = %s ORDER BY nazwa ASC", (kraj_id,))

@st.cache_data(ttl=60, show_spinner=False)
def pobierz_liczbe_kol_bez_regionu(kraj_id):
    return db_scalar("SELECT COUNT(*) FROM aktywne_kola WHERE region_id IS NULL AND kraj_id = %s", (kraj_id,)) or 0

@st.cache_data(ttl=60, show_spinner=False)
def pobierz_aktywne_kola_kraju(kraj_id):
    return db_query("""
        SELECT k.id, k.nazwa, k.region_id, r.nazwa as region_nazwa
        FROM aktywne_kola k
        LEFT JOIN aktywne_regiony r ON k.region_id = r.id
        WHERE k.kraj_id = %s
        ORDER BY k.nazwa ASC
    """, (kraj_id,))

# =========================================================================
# MODUŁ AUTORYZACJI I BRAMKA LOGOWANIA
# =========================================================================
if "auth_user" not in st.session_state:
    st.session_state["auth_user"] = None

def formularz_logowania():
    st.markdown("<br><br>", unsafe_allow_html=True)
    _, c_l2, _ = st.columns([1, 1.2, 1])
    with c_l2:
        st.markdown("""
            <div class="bento-card" style="text-align: center; border: 1px solid #4338ca; box-shadow: 0 15px 35px -5px rgba(99, 102, 241, 0.25);">
                <h2 style="font-weight: 800; margin-bottom: 4px; letter-spacing: -0.02em;">CITADEL FOR NG</h2>
                <div style="color: #94a3b8; font-size: 0.85rem; margin-bottom: 24px;">System Ewidencji Składek i Finansów</div>
            </div>
        """, unsafe_allow_html=True)
        with st.form("form_login"):
            log_login = st.text_input("Identyfikator użytkownika (Login)")
            log_haslo = st.text_input("Hasło dostępu", type="password")
            btn_loguj = st.form_submit_button("Zaloguj do systemu", use_container_width=True)
            if btn_loguj:
                u_df = db_query("SELECT * FROM uzytkownicy WHERE login = %s", (log_login.strip(),))
                if u_df.empty:
                    st.error("Nieprawidłowy login lub hasło.")
                else:
                    u_row = u_df.iloc[0]
                    if not u_row["is_active"]:
                        st.error("Dostęp do konta został zawieszony przez Administratora.")
                    elif weryfikuj_haslo(log_haslo, u_row["salt"], u_row["haslo_hash"]):
                        db_execute("UPDATE uzytkownicy SET ostatnie_logowanie = %s WHERE id = %s", (teraz_utc(), u_row["id"]))
                        st.session_state["auth_user"] = u_row.to_dict()
                        st.rerun()
                    else:
                        st.error("Nieprawidłowy login lub hasło.")

if st.session_state["auth_user"] is None:
    formularz_logowania()
    st.stop()

# Ciągła weryfikacja statusu konta przy każdym przeładowaniu
curr_user_id = st.session_state["auth_user"]["id"]
weryfikacja_df = db_query("SELECT id, login, imie_nazwisko, rola, kraj_id, region_id, kolo_id, is_active, wymus_zmiane_hasla FROM uzytkownicy WHERE id = %s", (curr_user_id,))
if weryfikacja_df.empty or not weryfikacja_df.iloc[0]["is_active"]:
    st.session_state["auth_user"] = None
    st.warning("Sesja zakończona lub konto zostało zawieszone przez Administratora.")
    st.rerun()

zalogowany_uzytkownik = weryfikacja_df.iloc[0].to_dict()
st.session_state["auth_user"] = zalogowany_uzytkownik

# WYMUSZENIE ZMIANY HASŁA STARTOWEGO
if zalogowany_uzytkownik["wymus_zmiane_hasla"]:
    st.markdown("<br><br>", unsafe_allow_html=True)
    _, col_zm, _ = st.columns([1, 1.2, 1])
    with col_zm:
        st.warning("⚠️ Twoje konto wymaga zmiany hasła przed uzyskaniem dostępu do panelu.")
        with st.form("form_wymus_haslo"):
            n_haslo1 = st.text_input("Nowe hasło (min. 8 znaków)", type="password")
            n_haslo2 = st.text_input("Powtórz nowe hasło", type="password")
            if st.form_submit_button("Zapisz nowe hasło i wejdź do Citadel"):
                if len(n_haslo1) < 8:
                    st.error("Hasło musi mieć co najmniej 8 znaków.")
                elif n_haslo1 != n_haslo2:
                    st.error("Wprowadzone hasła nie są identyczne.")
                else:
                    n_salt = generuj_sol()
                    n_hash = hashuj_haslo(n_haslo1, n_salt)
                    db_execute("""
                        UPDATE uzytkownicy 
                        SET haslo_hash = %s, salt = %s, wymus_zmiane_hasla = FALSE 
                        WHERE id = %s
                    """, (n_hash, n_salt, curr_user_id))
                    st.session_state["auth_user"]["wymus_zmiane_hasla"] = False
                    st.session_state["auth_user"]["haslo_hash"] = n_hash
                    st.session_state["auth_user"]["salt"] = n_salt
                    st.success("Hasło zostało zaktualizowane!")
                    st.rerun()
    st.stop()

# --- REGUŁY BIZNESOWE FINANSÓW I KDI ---
def pobierz_parametr(data_urodzenia_val, reczny_parametr, punkt_odniesienia):
    if reczny_parametr in ["B", "M", "S"]:
        stawki_gr = {"B": 600, "M": 900, "S": 1500}
        return reczny_parametr, stawki_gr[reczny_parametr]

    urodziny = parse_date(data_urodzenia_val)
    wiek = punkt_odniesienia.year - urodziny.year - ((punkt_odniesienia.month, punkt_odniesienia.day) < (urodziny.month, urodziny.day))

    if wiek < 19:
        return "B", 600
    elif wiek < 31:
        return "M", 900
    else:
        return "S", 1500

def oblicz_naliczenia_gr(data_wstapienia_val, data_urodzenia_val, reczny_parametr, punkt_odniesienia):
    wstapienie = parse_date(data_wstapienia_val)
    poczatek = max(wstapienie, DATA_ODCIECIA)
    suma_gr = 0
    licznik = 0
    kursor = date(poczatek.year, poczatek.month, 1)
    
    while kursor <= punkt_odniesienia:
        _, last_day = calendar.monthrange(kursor.year, kursor.month)
        ostatni_dzien_msc = date(kursor.year, kursor.month, last_day)
        
        if ostatni_dzien_msc <= punkt_odniesienia:
            _, stawka_gr = pobierz_parametr(data_urodzenia_val, reczny_parametr, ostatni_dzien_msc)
            suma_gr += stawka_gr
            licznik += 1
            
        kursor += relativedelta(months=1)

    return suma_gr, licznik

# PRZELICZANIE FINANSÓW Z PAMIĘCIĄ PODRĘCZNĄ
@st.cache_data(ttl=60, show_spinner=False)
def _przelicz_finanse_wielu_kol_cached(kolo_ids_tuple, punkt_odniesienia):
    if not kolo_ids_tuple:
        return {}

    aktywne_id_df = db_query("SELECT id FROM aktywne_kola WHERE id = ANY(%s)", (list(kolo_ids_tuple),))
    kolo_ids = aktywne_id_df["id"].tolist() if not aktywne_id_df.empty else []

    wyniki = {kid: ([], 0, 0, 0, 0, 0, 0) for kid in kolo_ids_tuple}
    if not kolo_ids:
        return wyniki

    wplaty_kola_df = db_query("""
        SELECT kolo_id, SUM(kwota_gr) as suma_wplat_kola_gr 
        FROM wplaty 
        WHERE kolo_id = ANY(%s) AND data_wplaty <= %s 
        GROUP BY kolo_id
    """, (kolo_ids, punkt_odniesienia))
    mapa_wplat_kola = dict(zip(wplaty_kola_df["kolo_id"], wplaty_kola_df["suma_wplat_kola_gr"])) if not wplaty_kola_df.empty else {}

    wydatki_kola_df = db_query("""
        SELECT kolo_id, SUM(kwota_gr) as suma_wydatkow_gr 
        FROM wydatki 
        WHERE kolo_id = ANY(%s) AND data_wydatku <= %s 
        GROUP BY kolo_id
    """, (kolo_ids, punkt_odniesienia))
    mapa_wydatkow_kola = dict(zip(wydatki_kola_df["kolo_id"], wydatki_kola_df["suma_wydatkow_gr"])) if not wydatki_kola_df.empty else {}

    korekty_kasy_df = db_query("""
        SELECT kolo_id, SUM(delta_gr) as suma_korekt_kasy_gr 
        FROM korekty_kasy 
        WHERE kolo_id = ANY(%s) AND data_korekty <= %s 
        GROUP BY kolo_id
    """, (kolo_ids, punkt_odniesienia))
    mapa_korekt_kasy = dict(zip(korekty_kasy_df["kolo_id"], korekty_kasy_df["suma_korekt_kasy_gr"])) if not korekty_kasy_df.empty else {}

    czlonkowie_df = db_query("""
        SELECT id, kolo_id, imie_nazwisko, data_urodzenia, data_przystapienia, saldo_startowe_gr, reczny_parametr 
        FROM czlonkowie 
        WHERE kolo_id = ANY(%s)
    """, (kolo_ids,))

    if czlonkowie_df.empty:
        for kid in kolo_ids:
            w_kasa = int(mapa_wplat_kola.get(kid, 0))
            wyd_kasa = int(mapa_wydatkow_kola.get(kid, 0))
            kor_kasa = int(mapa_korekt_kasy.get(kid, 0))
            f_kasa = w_kasa - wyd_kasa + kor_kasa
            wyniki[kid] = ([], w_kasa, f_kasa, wyd_kasa, kor_kasa, 0, 0)
        return wyniki

    czlonek_ids = czlonkowie_df["id"].tolist()

    wplaty_czlonkow_df = db_query("""
        SELECT czlonek_id, SUM(kwota_gr) as suma_wplat_gr 
        FROM wplaty 
        WHERE czlonek_id = ANY(%s) AND data_wplaty <= %s 
        GROUP BY czlonek_id
    """, (czlonek_ids, punkt_odniesienia))
    mapa_wplat_czl = dict(zip(wplaty_czlonkow_df["czlonek_id"], wplaty_czlonkow_df["suma_wplat_gr"])) if not wplaty_czlonkow_df.empty else {}

    reczne_df = db_query("""
        SELECT czlonek_id, SUM(kwota_gr) as suma_recznych_gr, COUNT(id) as liczba_recznych 
        FROM naliczenia_reczne 
        WHERE czlonek_id = ANY(%s) AND data_naliczenia <= %s 
        GROUP BY czlonek_id
    """, (czlonek_ids, punkt_odniesienia))
    mapa_reczne = {r["czlonek_id"]: (int(r["suma_recznych_gr"]), int(r["liczba_recznych"])) for _, r in reczne_df.iterrows()} if not reczne_df.empty else {}

    korekty_df = db_query("""
        SELECT czlonek_id, SUM(delta_gr) as suma_delt_gr 
        FROM korekty 
        WHERE czlonek_id = ANY(%s) AND data_korekty <= %s 
        GROUP BY czlonek_id
    """, (czlonek_ids, punkt_odniesienia))
    mapa_korekt_czl = dict(zip(korekty_df["czlonek_id"], korekty_df["suma_delt_gr"])) if not korekty_df.empty else {}

    for kid in kolo_ids:
        w_kasa = int(mapa_wplat_kola.get(kid, 0))
        wyd_kasa = int(mapa_wydatkow_kola.get(kid, 0))
        kor_kasa = int(mapa_korekt_kasy.get(kid, 0))
        f_kasa = w_kasa - wyd_kasa + kor_kasa

        czlonkowie_tego_kola = czlonkowie_df[czlonkowie_df["kolo_id"] == kid]
        if czlonkowie_tego_kola.empty:
            wyniki[kid] = ([], w_kasa, f_kasa, wyd_kasa, kor_kasa, 0, 0)
            continue

        dane_kolo = []
        tot_z_gr = 0
        tot_s_gr = 0

        for _, row in czlonkowie_tego_kola.iterrows():
            cid = row["id"]
            wpl_gr = int(mapa_wplat_czl.get(cid, 0))
            rec_gr, rec_cnt = mapa_reczne.get(cid, (0, 0))
            kor_gr = int(mapa_korekt_czl.get(cid, 0))
            s_start_gr = int(row["saldo_startowe_gr"])

            nal_auto_gr, msc = oblicz_naliczenia_gr(row["data_przystapienia"], row["data_urodzenia"], row["reczny_parametr"], punkt_odniesienia)
            param_kod, stawka_biezaca_gr = pobierz_parametr(row["data_urodzenia"], row["reczny_parametr"], punkt_odniesienia)

            nal_tot_gr = nal_auto_gr + rec_gr
            sal_akt_gr = s_start_gr + wpl_gr + kor_gr - nal_tot_gr

            s_i_gr = max(0, s_start_gr) + wpl_gr
            z_i_gr = max(0, s_i_gr - sal_akt_gr)
            tot_z_gr += z_i_gr
            tot_s_gr += s_i_gr

            kdi_val = round(z_i_gr / s_i_gr, 2) if s_i_gr > 0 else None
            kdi_str = f"{kdi_val:.2f}" if kdi_val is not None else "Brak danych"

            if sal_akt_gr >= 0:
                moze_glosowac = True
                glosowanie_str = "TAK"
            else:
                miesiace_zadluzenia = abs(sal_akt_gr) / stawka_biezaca_gr
                moze_glosowac = (miesiace_zadluzenia <= 6.0)
                glosowanie_str = "TAK" if moze_glosowac else "NIE"

            dane_kolo.append({
                "id": cid,
                "imie_nazwisko": row["imie_nazwisko"],
                "data_ur": row["data_urodzenia"],
                "data_wst": row["data_przystapienia"],
                "parametr": param_kod,
                "reczny_parametr": row["reczny_parametr"],
                "saldo_start_gr": s_start_gr,
                "naliczone_gr": nal_tot_gr,
                "naliczone_auto_gr": nal_auto_gr,
                "reczne_gr": rec_gr,
                "liczba_recznych": rec_cnt,
                "msc": msc,
                "wplaty_gr": wpl_gr,
                "korekty_gr": kor_gr,
                "saldo_akt_gr": sal_akt_gr,
                "saldo_akt_pln": sal_akt_gr / 100.0,
                "kdi_val": kdi_val,
                "kdi_str": kdi_str,
                "moze_glosowac": moze_glosowac,
                "glosowanie_str": glosowanie_str
            })

        wyniki[kid] = (dane_kolo, w_kasa, f_kasa, wyd_kasa, kor_kasa, tot_z_gr, tot_s_gr)

    return wyniki

def przelicz_finanse_wielu_kol(kolo_ids_input, punkt_odniesienia):
    if not kolo_ids_input:
        return {}
    k_tuple = tuple(sorted(list(kolo_ids_input)))
    return _przelicz_finanse_wielu_kol_cached(k_tuple, punkt_odniesienia)

def przelicz_finanse_dla_kola(kolo_id, punkt_odniesienia):
    res = przelicz_finanse_wielu_kol([kolo_id], punkt_odniesienia)
    return res.get(kolo_id, ([], 0, 0, 0, 0, 0, 0))

def filtruj_interwal(records, interwal_kod):
    if not records:
        return []
    if interwal_kod == "D1":
        return records
    wybrane = []
    n = len(records)
    for idx, r in enumerate(records):
        d = r["date"]
        if idx == 0 or idx == n - 1:
            wybrane.append(r)
            continue
        if interwal_kod == "T1" and d.weekday() == 6:
            wybrane.append(r)
        elif interwal_kod == "M1":
            _, last_d = calendar.monthrange(d.year, d.month)
            if d.day == last_d:
                wybrane.append(r)
        elif interwal_kod == "Q1":
            _, last_d = calendar.monthrange(d.year, d.month)
            if d.month in [3, 6, 9, 12] and d.day == last_d:
                wybrane.append(r)
        elif interwal_kod == "Q2":
            _, last_d = calendar.monthrange(d.year, d.month)
            if d.month in [6, 12] and d.day == last_d:
                wybrane.append(r)
        elif interwal_kod == "Y1" and d.month == 12 and d.day == 31:
            wybrane.append(r)
    unikalne = []
    widziane = set()
    for r in wybrane:
        if r["date"] not in widziane:
            widziane.add(r["date"])
            unikalne.append(r)
    return unikalne

# =========================================================================
# GŁÓWNA NAWIGACJA HIERARCHICZNA
# =========================================================================
kraje_df = pobierz_slownik_krajow()
mapa_krajow = dict(zip(kraje_df["id"], kraje_df["nazwa"]))
rola_uzytkownika = zalogowany_uzytkownik["rola"]

col_h1, col_h2, col_h3, col_h4, col_h5 = st.columns([1.8, 0.8, 1.2, 1.4, 0.9])
with col_h1:
    st.markdown("<h1 style='font-size: 1.6rem; font-weight: 700; margin: 0;'>Citadel for NG</h1>", unsafe_allow_html=True)

# 1. SCOPING KRAJU
with col_h2:
    if rola_uzytkownika in ("ADMIN", "SKARBNIK_KRAJOWY"):
        wybrany_kraj_id = st.selectbox("Kraj", options=list(mapa_krajow.keys()), format_func=lambda x: mapa_krajow[x])
    else:
        wybrany_kraj_id = zalogowany_uzytkownik["kraj_id"] or list(mapa_krajow.keys())[0]
        st.selectbox("Kraj", options=[wybrany_kraj_id], format_func=lambda x: mapa_krajow.get(x, "Polska"), disabled=True)

# 2. SCOPING REGIONU
regiony_df = pobierz_slownik_regionow(wybrany_kraj_id)
mapa_regionow = dict(zip(regiony_df["id"], regiony_df["nazwa"])) if not regiony_df.empty else {}
liczba_kol_bez_regionu = pobierz_liczbe_kol_bez_regionu(wybrany_kraj_id)

opcje_regionow = list(mapa_regionow.keys())
if liczba_kol_bez_regionu > 0 and rola_uzytkownika in ("ADMIN", "SKARBNIK_KRAJOWY"):
    opcje_regionow.append(-1)

def formatuj_nazwe_regionu(reg_id):
    if reg_id == -1:
        return f"⚠️ Bez regionu ({liczba_kol_bez_regionu})"
    return mapa_regionow.get(reg_id, "Nieznany region")

with col_h3:
    if rola_uzytkownika in ("ADMIN", "SKARBNIK_KRAJOWY"):
        if opcje_regionow:
            wybrany_region_id = st.selectbox("Aktywny Region:", options=opcje_regionow, format_func=formatuj_nazwe_regionu)
            nazwa_wybranego_regionu = "Nieprzypisane do regionu" if wybrany_region_id == -1 else mapa_regionow[wybrany_region_id]
        else:
            wybrany_region_id = None
            nazwa_wybranego_regionu = "Brak aktywnych regionów"
            st.selectbox("Aktywny Region:", options=[0], format_func=lambda x: "Brak regionów w bazie")
    elif rola_uzytkownika == "SKARBNIK_REGIONU":
        wybrany_region_id = zalogowany_uzytkownik["region_id"]
        nazwa_wybranego_regionu = mapa_regionow.get(wybrany_region_id, "Twój Region")
        st.selectbox("Aktywny Region:", options=[wybrany_region_id] if wybrany_region_id else [0], format_func=lambda x: nazwa_wybranego_regionu, disabled=True)
    else:  # SKARBNIK_KOLA
        kolo_reg_id = db_scalar("SELECT region_id FROM kola WHERE id = %s", (zalogowany_uzytkownik["kolo_id"],))
        wybrany_region_id = kolo_reg_id
        nazwa_wybranego_regionu = mapa_regionow.get(wybrany_region_id, "Region Koła")
        st.selectbox("Region:", options=[wybrany_region_id or 0], format_func=lambda x: nazwa_wybranego_regionu, disabled=True)

# 3. SCOPING POZIOMU WIDOKU
with col_h4:
    if rola_uzytkownika in ("ADMIN", "SKARBNIK_KRAJOWY"):
        tryb_widoku = st.radio("Poziom analityczny:", ["🏢 Koło", "📊 Statystyki Regionu", "🇵🇱 Statystyki Kraju"], horizontal=True)
    elif rola_uzytkownika == "SKARBNIK_REGIONU":
        tryb_widoku = st.radio("Poziom analityczny:", ["🏢 Koło", "📊 Statystyki Regionu"], horizontal=True)
    else:
        tryb_widoku = "🏢 Koło"
        st.caption("🔒 Dostęp do własnego Koła")

# 4. PASEK UŻYTKOWNIKA I WYLOGOWANIE
with col_h5:
    badge_rola = {
        "ADMIN": "👑 Admin",
        "SKARBNIK_KRAJOWY": "🇵🇱 Krajowy",
        "SKARBNIK_REGIONU": "📊 Region",
        "SKARBNIK_KOLA": "🏢 Koło"
    }.get(rola_uzytkownika, rola_uzytkownika)
    
    st.markdown(f"<div style='font-size: 0.8rem; font-weight: 600; color: #94a3b8;'>{zalogowany_uzytkownik['imie_nazwisko']}</div>", unsafe_allow_html=True)
    st.markdown(f"<span class='user-pill'>{badge_rola}</span>", unsafe_allow_html=True)
    if st.button("Wyloguj", key="btn_logout", use_container_width=True):
        st.session_state["auth_user"] = None
        st.rerun()

# --- GLOBALNY BANNER POWIADOMIENIA O OCZEKUJĄCYCH WPŁATACH ---
if rola_uzytkownika in ("ADMIN", "SKARBNIK_KRAJOWY"):
    liczba_oczekujacych_global = db_scalar("SELECT COUNT(*) FROM wplaty_oczekujace WHERE status = 'OCZEKUJE';") or 0
    if liczba_oczekujacych_global > 0:
        st.warning(f"🔔 **Kolejka Weryfikacji:** Wpłaty czekające na Twoją akceptację: **{liczba_oczekujacych_global}**. Przejdź do widoku **🏢 Koło $\\rightarrow$ 📥 Wpłaty do zaakceptowania**, aby je zatwierdzić.")

nazwa_kraju = mapa_krajow.get(wybrany_kraj_id, "Polska")
dzis = dzis_pl()

# =========================================================================
# WIDOK 1: STATYSTYKI KRAJU (ADMIN & SKARBNIK KRAJOWY)
# =========================================================================
if tryb_widoku == "🇵🇱 Statystyki Kraju":
    if rola_uzytkownika not in ("ADMIN", "SKARBNIK_KRAJOWY"):
        st.error("Brak uprawnień do przeglądania statystyk ogólnokrajowych.")
        st.stop()

    st.markdown(f"## 🇵🇱 Statystyki Ogólnokrajowe: {nazwa_kraju}")
    st.caption("Zagregowany bilans wszystkich aktywnych regionów i kół podległych jednostce centralnej | Czas biznesowy: **Warszawa**")

    wszystkie_aktywne_kola_kraju = pobierz_aktywne_kola_kraju(wybrany_kraj_id)

    kola_bez_regionu = wszystkie_aktywne_kola_kraju[wszystkie_aktywne_kola_kraju["region_id"].isna()]
    if not kola_bez_regionu.empty:
        nazwy_brak = ", ".join(kola_bez_regionu["nazwa"].tolist())
        st.warning(f"⚠️ **Wykryto {len(kola_bez_regionu)} koła bez przypisanego regionu:** {nazwy_brak}. Zostały ujęte w wierszu 'Bez regionu' poniżej.")

    if wszystkie_aktywne_kola_kraju.empty:
        st.info("Brak aktywnych kół w tym kraju.")
    else:
        lista_kol_kraj = wszystkie_aktywne_kola_kraju["id"].tolist()
        finanse_hurt_kraj = przelicz_finanse_wielu_kol(lista_kol_kraj, dzis)

        kraj_kasa_gr = 0
        kraj_wplaty_gr = 0
        kraj_wydatki_gr = 0
        kraj_total_z_gr = 0
        kraj_total_s_gr = 0
        kraj_czlonkowie_count = 0
        kraj_uprawnieni_count = 0

        statystyki_per_region = {}
        for reg_id, reg_nazwa in mapa_regionow.items():
            statystyki_per_region[reg_id] = {
                "Region": reg_nazwa, "Liczba Kół": 0, "Członkowie": 0, "Kasa": 0, 
                "Wpłaty": 0, "Wydatki": 0, "total_z": 0, "total_s": 0, "uprawnieni": 0
            }

        bez_regionu_stat = {
            "Region": "⚠️ Bez regionu (nieprzypisane)", "Liczba Kół": 0, "Członkowie": 0, "Kasa": 0,
            "Wpłaty": 0, "Wydatki": 0, "total_z": 0, "total_s": 0, "uprawnieni": 0
        }

        for _, row in wszystkie_aktywne_kola_kraju.iterrows():
            k_id = row["id"]
            r_id = row["region_id"]
            dane, wplaty_kasa, kasa, wydatki, _, z_gr, s_gr = finanse_hurt_kraj.get(k_id, ([], 0, 0, 0, 0, 0, 0))
            
            kraj_kasa_gr += kasa
            kraj_wplaty_gr += wplaty_kasa
            kraj_wydatki_gr += wydatki
            kraj_total_z_gr += z_gr
            kraj_total_s_gr += s_gr
            
            czl_cnt = len(dane)
            upr_cnt = sum(1 for d in dane if d["moze_glosowac"])
            kraj_czlonkowie_count += czl_cnt
            kraj_uprawnieni_count += upr_cnt

            target_bucket = statystyki_per_region[r_id] if pd.notna(r_id) and r_id in statystyki_per_region else bez_regionu_stat
            target_bucket["Liczba Kół"] += 1
            target_bucket["Członkowie"] += czl_cnt
            target_bucket["Kasa"] += kasa
            target_bucket["Wpłaty"] += wplaty_kasa
            target_bucket["Wydatki"] += wydatki
            target_bucket["total_z"] += z_gr
            target_bucket["total_s"] += s_gr
            target_bucket["uprawnieni"] += upr_cnt

        kraj_kdi_val = round(kraj_total_z_gr / kraj_total_s_gr, 2) if kraj_total_s_gr > 0 else None
        kraj_kdi_str = f"{kraj_kdi_val:.2f}" if kraj_kdi_val is not None else "Brak danych"
        kolor_kraj_kdi = pobierz_kolor_kdi(kraj_kdi_val)

        kraj_pct_upr = (kraj_uprawnieni_count / kraj_czlonkowie_count * 100.0) if kraj_czlonkowie_count > 0 else 0.0
        kolor_kraj_upr = pobierz_kolor_uprawnionych(kraj_pct_upr if kraj_czlonkowie_count > 0 else None)
        kraj_kasa_color = "accent-green" if kraj_kasa_gr >= 0 else "accent-rose"

        kc1, kc2, kc3, kc4 = st.columns(4)
        with kc1:
            st.markdown(f"""
                <div class="bento-card">
                    <div class="bento-card-header">Kasa Całego Kraju</div>
                    <div class="bento-card-value {kraj_kasa_color}">{(kraj_kasa_gr / 100.0):,.2f} PLN</div>
                    <div class="bento-card-sub">Wpłaty - Wydatki + Korekty</div>
                </div>
            """, unsafe_allow_html=True)
        with kc2:
            st.markdown(f"""
                <div class="bento-card">
                    <div class="bento-card-header">Suma Składek (Kraj)</div>
                    <div class="bento-card-value accent-cyan">{(kraj_wplaty_gr / 100.0):,.2f} PLN</div>
                    <div class="bento-card-sub">Wydatki krajowe: {(kraj_wydatki_gr / 100.0):,.2f} PLN</div>
                </div>
            """, unsafe_allow_html=True)
        with kc3:
            st.markdown(f"""
                <div class="bento-card">
                    <div class="bento-card-header">Zagregowany KDI Kraju</div>
                    <div class="bento-card-value" style="color: {kolor_kraj_kdi}; text-shadow: 0 0 16px {kolor_kraj_kdi}55;">{kraj_kdi_str}</div>
                    <div class="bento-card-sub">Rekomendowane: ≤ 1.20</div>
                </div>
            """, unsafe_allow_html=True)
        with kc4:
            st.markdown(f"""
                <div class="bento-card">
                    <div class="bento-card-header">Uprawnieni do Głosu (Kraj)</div>
                    <div class="bento-card-value" style="color: {kolor_kraj_upr}; text-shadow: 0 0 16px {kolor_kraj_upr}55;">{kraj_uprawnieni_count} / {kraj_czlonkowie_count}</div>
                    <div class="bento-card-sub">{kraj_pct_upr:.1f}% uprawnionych w kraju (karencja ≤ 6 msc)</div>
                </div>
            """, unsafe_allow_html=True)

        st.markdown("### 🗺️ Zestawienie Regionów w Polsce")
        tabela_zbiorcza_reg = []
        for r_id, s in statystyki_per_region.items():
            r_kdi = round(s["total_z"] / s["total_s"], 2) if s["total_s"] > 0 else None
            r_pct = (s["uprawnieni"] / s["Członkowie"] * 100.0) if s["Członkowie"] > 0 else 0.0
            tabela_zbiorcza_reg.append({
                "Region": s["Region"],
                "Liczba Kół": s["Liczba Kół"],
                "Członkowie": s["Członkowie"],
                "Kasa Regionu": f"{(s['Kasa'] / 100.0):,.2f} zł",
                "Wpłaty": f"{(s['Wpłaty'] / 100.0):,.2f} zł",
                "Wydatki": f"{(s['Wydatki'] / 100.0):,.2f} zł",
                "KDI Regionu": f"{r_kdi:.2f}" if r_kdi is not None else "Brak danych",
                "Uprawnieni": f"{s['uprawnieni']}/{s['Członkowie']} ({r_pct:.1f}%)"
            })
        
        if bez_regionu_stat["Liczba Kół"] > 0:
            br_kdi = round(bez_regionu_stat["total_z"] / bez_regionu_stat["total_s"], 2) if bez_regionu_stat["total_s"] > 0 else None
            br_pct = (bez_regionu_stat["uprawnieni"] / bez_regionu_stat["Członkowie"] * 100.0) if bez_regionu_stat["Członkowie"] > 0 else 0.0
            tabela_zbiorcza_reg.append({
                "Region": bez_regionu_stat["Region"],
                "Liczba Kół": bez_regionu_stat["Liczba Kół"],
                "Członkowie": bez_regionu_stat["Członkowie"],
                "Kasa Regionu": f"{(bez_regionu_stat['Kasa'] / 100.0):,.2f} zł",
                "Wpłaty": f"{(bez_regionu_stat['Wpłaty'] / 100.0):,.2f} zł",
                "Wydatki": f"{(bez_regionu_stat['Wydatki'] / 100.0):,.2f} zł",
                "KDI Regionu": f"{br_kdi:.2f}" if br_kdi is not None else "Brak danych",
                "Uprawnieni": f"{bez_regionu_stat['uprawnieni']}/{bez_regionu_stat['Członkowie']} ({br_pct:.1f}%)"
            })

        st.dataframe(pd.DataFrame(tabela_zbiorcza_reg), width="stretch", hide_index=True)

# =========================================================================
# WIDOK 2: STATYSTYKI REGIONU (ADMIN, SKARBNIK KRAJOWY I SKARBNIK TEGO REGIONU)
# =========================================================================
elif tryb_widoku == "📊 Statystyki Regionu":
    if rola_uzytkownika == "SKARBNIK_KOLA":
        st.error("Brak uprawnień do przeglądania statystyk regionu.")
        st.stop()

    if not mapa_regionow and rola_uzytkownika in ("ADMIN", "SKARBNIK_KRAJOWY"):
        st.warning("W systemie nie ma jeszcze żadnych aktywnych regionów.")
        st.stop()

    if rola_uzytkownika == "SKARBNIK_REGIONU" and not wybrany_region_id:
        st.error("Twoje konto nie ma przypisanego aktywnego regionu. Skontaktuj się z Administratorem.")
        st.stop()

    st.markdown(f"## 📊 Pulpit Analityczny: {nazwa_wybranego_regionu}")
    st.caption(f"Kraj: **{nazwa_kraju}** | Strefa biznesowa: **Warszawa**")

    if wybrany_region_id == -1:
        kola_w_tym_regionie = db_query("""
            SELECT id, nazwa FROM aktywne_kola 
            WHERE region_id IS NULL AND kraj_id = %s 
            ORDER BY nazwa ASC
        """, (wybrany_kraj_id,))
    else:
        kola_w_tym_regionie = db_query("""
            SELECT id, nazwa FROM aktywne_kola 
            WHERE region_id = %s 
            ORDER BY nazwa ASC
        """, (wybrany_region_id,))

    if kola_w_tym_regionie.empty:
        st.info(f"Region '{nazwa_wybranego_regionu}' nie posiada aktualnie przypisanych aktywnych kół.")
    else:
        lista_kol_reg = kola_w_tym_regionie["id"].tolist()
        finanse_hurt_reg = przelicz_finanse_wielu_kol(lista_kol_reg, dzis)

        reg_kasa_gr = 0
        reg_wplaty_gr = 0
        reg_wydatki_gr = 0
        reg_total_z_gr = 0
        reg_total_s_gr = 0
        reg_lacznie_czlonkow = 0
        reg_uprawnieni_count = 0
        
        tabela_kol = []
        for _, k_row in kola_w_tym_regionie.iterrows():
            k_id = k_row["id"]
            k_nazwa = k_row["nazwa"]
            dane, wplaty_kasa, kasa, wydatki, _, z_gr, s_gr = finanse_hurt_reg.get(k_id, ([], 0, 0, 0, 0, 0, 0))
            
            reg_kasa_gr += kasa
            reg_wplaty_gr += wplaty_kasa
            reg_wydatki_gr += wydatki
            reg_total_z_gr += z_gr
            reg_total_s_gr += s_gr
            
            czl_count = len(dane)
            upr_count = sum(1 for d in dane if d["moze_glosowac"])
            reg_lacznie_czlonkow += czl_count
            reg_uprawnieni_count += upr_count
            
            k_kdi_val = round(z_gr / s_gr, 2) if s_gr > 0 else None
            k_pct_upr = (upr_count / czl_count * 100.0) if czl_count > 0 else 0.0
            
            tabela_kol.append({
                "ID": k_id,
                "Koło": k_nazwa,
                "Liczba Członków": czl_count,
                "Kasa Koła": f"{(kasa / 100.0):,.2f} zł",
                "Wpłacone Składki": f"{(wplaty_kasa / 100.0):,.2f} zł",
                "Wydatki": f"{(wydatki / 100.0):,.2f} zł",
                "KDI Koła": f"{k_kdi_val:.2f}" if k_kdi_val is not None else "Brak danych",
                "Uprawnieni": f"{upr_count}/{czl_count} ({k_pct_upr:.1f}%)"
            })

        reg_kdi_val = round(reg_total_z_gr / reg_total_s_gr, 2) if reg_total_s_gr > 0 else None
        reg_kdi_str = f"{reg_kdi_val:.2f}" if reg_kdi_val is not None else "Brak danych"
        kolor_reg_kdi = pobierz_kolor_kdi(reg_kdi_val)
        
        reg_pct_upr = (reg_uprawnieni_count / reg_lacznie_czlonkow * 100.0) if reg_lacznie_czlonkow > 0 else 0.0
        kolor_reg_upr = pobierz_kolor_uprawnionych(reg_pct_upr if reg_lacznie_czlonkow > 0 else None)
        kasa_color = "accent-green" if reg_kasa_gr >= 0 else "accent-rose"

        rc1, rc2, rc3, rc4 = st.columns(4)
        with rc1:
            st.markdown(f"""
                <div class="bento-card">
                    <div class="bento-card-header">Kasa Całego Regionu</div>
                    <div class="bento-card-value {kasa_color}">{(reg_kasa_gr / 100.0):,.2f} PLN</div>
                    <div class="bento-card-sub">Zagregowane saldo środków płynnych</div>
                </div>
            """, unsafe_allow_html=True)
        with rc2:
            st.markdown(f"""
                <div class="bento-card">
                    <div class="bento-card-header">Suma Składek Regionu</div>
                    <div class="bento-card-value accent-cyan">{(reg_wplaty_gr / 100.0):,.2f} PLN</div>
                    <div class="bento-card-sub">Wydatki: {(reg_wydatki_gr / 100.0):,.2f} PLN</div>
                </div>
            """, unsafe_allow_html=True)
        with rc3:
            st.markdown(f"""
                <div class="bento-card">
                    <div class="bento-card-header">Zagregowany KDI Regionu</div>
                    <div class="bento-card-value" style="color: {kolor_reg_kdi}; text-shadow: 0 0 16px {kolor_reg_kdi}55;">{reg_kdi_str}</div>
                    <div class="bento-card-sub">Rekomendowane: ≤ 1.20</div>
                </div>
            """, unsafe_allow_html=True)
        with rc4:
            st.markdown(f"""
                <div class="bento-card">
                    <div class="bento-card-header">Uprawnieni do Głosu (Region)</div>
                    <div class="bento-card-value" style="color: {kolor_reg_upr}; text-shadow: 0 0 16px {kolor_reg_upr}55;">{reg_uprawnieni_count} / {reg_lacznie_czlonkow}</div>
                    <div class="bento-card-sub">{reg_pct_upr:.1f}% uprawnionych w regionie (karencja ≤ 6 msc)</div>
                </div>
            """, unsafe_allow_html=True)

        st.markdown(f"### 🏛️ Koła podległe pod {nazwa_wybranego_regionu}")
        df_podsumowanie_kol = pd.DataFrame(tabela_kol)
        st.dataframe(df_podsumowanie_kol, width="stretch", hide_index=True)

# =========================================================================
# WIDOK 3: OPERACJE KOŁA
# =========================================================================
else:
    if rola_uzytkownika == "SKARBNIK_KOLA":
        kola_w_wybranym_regionie_df = db_query("""
            SELECT id, nazwa, region_id, NULL as region_nazwa
            FROM aktywne_kola WHERE id = %s
        """, (zalogowany_uzytkownik["kolo_id"],))
    elif rola_uzytkownika == "SKARBNIK_REGIONU":
        kola_w_wybranym_regionie_df = db_query("""
            SELECT k.id, k.nazwa, k.region_id, r.nazwa as region_nazwa
            FROM aktywne_kola k
            LEFT JOIN aktywne_regiony r ON k.region_id = r.id
            WHERE k.region_id = %s
            ORDER BY k.nazwa ASC
        """, (zalogowany_uzytkownik["region_id"],))
    else:  # ADMIN / SKARBNIK KRAJOWY
        if wybrany_region_id == -1:
            kola_w_wybranym_regionie_df = db_query("""
                SELECT id, nazwa, region_id, NULL as region_nazwa
                FROM aktywne_kola
                WHERE region_id IS NULL AND kraj_id = %s
                ORDER BY nazwa ASC
            """, (wybrany_kraj_id,))
        elif wybrany_region_id is not None:
            kola_w_wybranym_regionie_df = db_query("""
                SELECT k.id, k.nazwa, k.region_id, r.nazwa as region_nazwa
                FROM aktywne_kola k
                JOIN aktywne_regiony r ON k.region_id = r.id
                WHERE k.region_id = %s
                ORDER BY k.nazwa ASC
            """, (wybrany_region_id,))
        else:
            kola_w_wybranym_regionie_df = pd.DataFrame()

    if kola_w_wybranym_regionie_df.empty:
        st.warning(f"Brak dostępnych aktywnych kół w tym widoku.")
        st.stop()

    mapa_kol_regionu = dict(zip(kola_w_wybranym_regionie_df["id"], kola_w_wybranym_regionie_df["nazwa"]))

    c_kolo_sel, _ = st.columns([2, 2])
    with c_kolo_sel:
        if rola_uzytkownika == "SKARBNIK_KOLA":
            wybrane_kolo_id = zalogowany_uzytkownik["kolo_id"]
            st.selectbox("Koło:", options=[wybrane_kolo_id], format_func=lambda x: mapa_kol_regionu.get(x, "Twoje Koło"), disabled=True)
        else:
            wybrane_kolo_id = st.selectbox(
                f"Wybierz Koło z regionu: {nazwa_wybranego_regionu}", 
                options=list(mapa_kol_regionu.keys()), 
                format_func=lambda x: mapa_kol_regionu[x]
            )

    nazwa_aktywnego_kola = mapa_kol_regionu[wybrane_kolo_id]
    st.caption(f"Aktywna jednostka: **{nazwa_aktywnego_kola}** | Rola: **{badge_rola}** | Czas: **Europe/Warsaw**")

    dane_przeliczone, suma_wplat_kola_gr, faktyczna_kasa_kola_gr, suma_wydatkow_gr, suma_korekt_kasy_gr, total_z_gr, total_s_gr = przelicz_finanse_dla_kola(wybrane_kolo_id, dzis)

    kdi_global_val = round(total_z_gr / total_s_gr, 2) if total_s_gr > 0 else None
    kdi_global_str = f"{kdi_global_val:.2f}" if kdi_global_val is not None else "Brak danych"
    kolor_kdi_global = pobierz_kolor_kdi(kdi_global_val)

    # --- BENTO CARDS (KPI KOŁA) ---
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        kasa_color = "accent-green" if faktyczna_kasa_kola_gr >= 0 else "accent-rose"
        st.markdown(f"""
            <div class="bento-card">
                <div class="bento-card-header">Faktyczna Kasa Koła</div>
                <div class="bento-card-value {kasa_color}">{(faktyczna_kasa_kola_gr / 100.0):,.2f} PLN</div>
                <div class="bento-card-sub">Wpłaty - Wydatki + Korekty</div>
            </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
            <div class="bento-card">
                <div class="bento-card-header">Suma Wpłaconych Składek</div>
                <div class="bento-card-value accent-cyan">{(suma_wplat_kola_gr / 100.0):,.2f} PLN</div>
                <div class="bento-card-sub">Wpłacone do kasy tego koła</div>
            </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
            <div class="bento-card">
                <div class="bento-card-header">KDI Koła ({nazwa_aktywnego_kola})</div>
                <div class="bento-card-value" style="color: {kolor_kdi_global}; text-shadow: 0 0 16px {kolor_kdi_global}55;">{kdi_global_str}</div>
                <div class="bento-card-sub">Rekomendowane: ≤ 1.20</div>
            </div>
        """, unsafe_allow_html=True)
    with c4:
        uprawnieni_count = sum(1 for d in dane_przeliczone if d["moze_glosowac"])
        lacznie_czlonkow = len(dane_przeliczone)
        pct_uprawnieni = (uprawnieni_count / lacznie_czlonkow * 100.0) if lacznie_czlonkow > 0 else 0.0
        kolor_uprawnieni = pobierz_kolor_uprawnionych(pct_uprawnieni if lacznie_czlonkow > 0 else None)
        
        st.markdown(f"""
            <div class="bento-card">
                <div class="bento-card-header">Uprawnieni do Głosowania</div>
                <div class="bento-card-value" style="color: {kolor_uprawnieni}; text-shadow: 0 0 16px {kolor_uprawnieni}55;">{uprawnieni_count} / {lacznie_czlonkow}</div>
                <div class="bento-card-sub">{pct_uprawnieni:.1f}% uprawnionych (karencja ≤ 6 msc)</div>
            </div>
        """, unsafe_allow_html=True)

    # --- DYNAMICZNY ZESTAW ZAKŁADEK ---
    zakladki_nazwy = ["📊 Tabela Zbiorcza", "📈 Profile & Wykresy", "💰 Wpłaty Członków"]

    if rola_uzytkownika in ("ADMIN", "SKARBNIK_KRAJOWY"):
        zakladki_nazwy.append("📝 Ręczne Naliczenia")

    zakladki_nazwy.append("💳 Kasa Koła & Wydatki")

    if rola_uzytkownika in ("ADMIN", "SKARBNIK_KRAJOWY"):
        zakladki_nazwy.append("🛠️ Korekta Salda Osoby")

    zakladki_nazwy.append("👤 Zarządzaj Członkami")
    zakladki_nazwy.append("🧮 Kalkulator")

    if rola_uzytkownika in ("ADMIN", "SKARBNIK_KRAJOWY"):
        cnt_pending = db_scalar("SELECT COUNT(*) FROM wplaty_oczekujace WHERE status = 'OCZEKUJE';") or 0
        tag_pending = f" ({cnt_pending})" if cnt_pending > 0 else ""
        zakladki_nazwy.append(f"📥 Wpłaty do zaakceptowania{tag_pending}")

    if rola_uzytkownika in ("ADMIN", "SKARBNIK_KRAJOWY"):
        zakladki_nazwy.append("🏛️ Zarządzaj Strukturą")

    if rola_uzytkownika == "ADMIN":
        zakladki_nazwy.append("📜 Logi Audytowe")
        zakladki_nazwy.append("🏛️ Panel Centauri")

    st_tabs_obiekty = st.tabs(zakladki_nazwy)
    tab_map = dict(zip(zakladki_nazwy, st_tabs_obiekty))

    # 1. TABELA ZBIORCZA
    with tab_map["📊 Tabela Zbiorcza"]:
        if not dane_przeliczone:
            st.info(f"Baza dla koła '{nazwa_aktywnego_kola}' jest pusta. Dodaj pierwszego członka.")
        else:
            df_wyswietl = pd.DataFrame([
                {
                    "ID": d["id"],
                    "Członek": d["imie_nazwisko"],
                    "Próg": f"Parametr {d['parametr']}",
                    "Saldo Start": f"{(d['saldo_start_gr'] / 100.0):.2f} zł",
                    "Korekty": f"{(d['korekty_gr'] / 100.0):.2f} zł",
                    "Naliczone": f"{(d['naliczone_gr'] / 100.0):.2f} zł ({d['msc']} msc" + (f" + {d['liczba_recznych']} ręczne)" if d['liczba_recznych'] > 0 else ")"),
                    "Wpłacone": f"{(d['wplaty_gr'] / 100.0):.2f} zł",
                    "Saldo Aktualne": f"{d['saldo_akt_pln']:.2f} zł",
                    "Wskaźnik KDI": d["kdi_str"],
                    "Możliwość głosowania": d["glosowanie_str"]
                }
                for d in dane_przeliczone
            ])

            def stylizuj_kdi_komorke(wartosc):
                kolor = pobierz_kolor_kdi(wartosc)
                if wartosc == "Brak danych":
                    return f"color: {kolor}; font-style: italic;"
                return f"color: {kolor}; font-weight: 700; text-shadow: 0 0 8px {kolor}40;"

            def stylizuj_glosowanie(wartosc):
                if wartosc == "TAK":
                    return "color: #10b981; font-weight: 800;"
                elif wartosc == "NIE":
                    return "color: #f43f5e; font-weight: 800;"
                return ""

            styler = df_wyswietl.style.map(stylizuj_kdi_komorke, subset=["Wskaźnik KDI"]).map(stylizuj_glosowanie, subset=["Możliwość głosowania"])
            st.dataframe(styler, width="stretch", hide_index=True)

    # 2. PROFIL I WYKRESY
    with tab_map["📈 Profile & Wykresy"]:
        if not dane_przeliczone:
            st.info("Brak danych do wygenerowania wykresów.")
        else:
            mapa_osob = {d["id"]: f"{d['imie_nazwisko']} (Saldo: {d['saldo_akt_pln']:.2f} zł, KDI: {d['kdi_str']})" for d in dane_przeliczone}
            wybrany_id = st.selectbox("Wybierz członka do analizy wskaźników", options=list(mapa_osob.keys()), format_func=lambda x: mapa_osob[x])
            osoba = next(item for item in dane_przeliczone if item["id"] == wybrany_id)
            
            kolor_kdi_osoby = pobierz_kolor_kdi(osoba["kdi_val"])
            kolor_glos = "#10b981" if osoba["moze_glosowac"] else "#f43f5e"
            
            st.markdown(f"""
                <div style="background: #161228; border: 1px solid #282046; border-radius: 12px; padding: 12px 18px; margin-bottom: 18px; display: flex; gap: 24px; align-items: center; flex-wrap: wrap;">
                    <div><span style="color: #94a3b8; font-size: 0.85rem;">CZŁONEK:</span> <strong style="color: #ffffff; font-size: 1rem;">{osoba['imie_nazwisko']}</strong></div>
                    <div><span style="color: #94a3b8; font-size: 0.85rem;">AKTUALNY KDI:</span> <strong style="color: {kolor_kdi_osoby}; font-size: 1.15rem; text-shadow: 0 0 10px {kolor_kdi_osoby}66;">{osoba['kdi_str']}</strong></div>
                    <div><span style="color: #94a3b8; font-size: 0.85rem;">SALDO:</span> <strong style="color: {'#10b981' if osoba['saldo_akt_pln'] >= 0 else '#f43f5e'}; font-size: 1rem;">{osoba['saldo_akt_pln']:.2f} zł</strong></div>
                    <div><span style="color: #94a3b8; font-size: 0.85rem;">GŁOSOWANIE:</span> <strong style="color: {kolor_glos}; font-size: 1.05rem; font-weight: 800;">{osoba['glosowanie_str']}</strong></div>
                </div>
            """, unsafe_allow_html=True)

            hist_wplaty = db_query("SELECT id, kwota_gr, data_wplaty, notatka FROM wplaty WHERE czlonek_id = %s ORDER BY data_wplaty ASC", (wybrany_id,))
            hist_naliczenia_reczne = db_query("SELECT id, kwota_gr, data_naliczenia, tytul FROM naliczenia_reczne WHERE czlonek_id = %s ORDER BY data_naliczenia ASC", (wybrany_id,))
            hist_korekty = db_query("SELECT id, delta_gr, docelowe_saldo_gr, data_korekty, powod FROM korekty WHERE czlonek_id = %s ORDER BY data_korekty ASC", (wybrany_id,))

            wplaty_map = {parse_date(r["data_wplaty"]): int(r["kwota_gr"]) for _, r in hist_wplaty.iterrows()}
            reczne_nal_map = {parse_date(r["data_naliczenia"]): int(r["kwota_gr"]) for _, r in hist_naliczenia_reczne.iterrows()}
            korekty_map = {}
            for _, r in hist_korekty.iterrows():
                korekty_map.setdefault(parse_date(r["data_korekty"]), []).append(int(r["delta_gr"]))

            start_date = max(parse_date(osoba["data_wst"]), DATA_ODCIECIA)
            if start_date > dzis:
                start_date = dzis

            daily_records = []
            cur_date = start_date
            running_wplaty_gr = 0
            running_reczne_nal_gr = 0
            running_kor_netto_gr = 0

            while cur_date <= dzis:
                if cur_date in wplaty_map:
                    running_wplaty_gr += wplaty_map[cur_date]
                if cur_date in reczne_nal_map:
                    running_reczne_nal_gr += reczne_nal_map[cur_date]
                if cur_date in korekty_map:
                    for dlt in korekty_map[cur_date]:
                        running_kor_netto_gr += dlt

                nal_auto_gr, _ = oblicz_naliczenia_gr(osoba["data_wst"], osoba["data_ur"], osoba["reczny_parametr"], cur_date)
                nal_total_pt = nal_auto_gr + running_reczne_nal_gr
                
                saldo_pt_gr = osoba["saldo_start_gr"] + running_wplaty_gr + running_kor_netto_gr - nal_total_pt
                saldo_pt = saldo_pt_gr / 100.0

                s_pt = max(0, osoba["saldo_start_gr"]) + running_wplaty_gr
                z_pt = max(0, s_pt - saldo_pt_gr)
                kdi_pt = round(z_pt / s_pt, 2) if s_pt > 0 else None

                daily_records.append({
                    "date": cur_date,
                    "date_str": cur_date.strftime("%Y-%m-%d"),
                    "saldo": saldo_pt,
                    "kdi": kdi_pt
                })
                cur_date += timedelta(days=1)

            wybrany_interwal = st.radio("Interwał wykresu", ["D1", "T1", "M1", "Q1", "Q2", "Y1", "Cały okres"], horizontal=True)
            rekordy_do_wykresu = filtruj_interwal(daily_records, wybrany_interwal)
            punkty_x = [r["date_str"] for r in rekordy_do_wykresu]
            punkty_saldo = [r["saldo"] for r in rekordy_do_wykresu]
            punkty_kdi = [r["kdi"] for r in rekordy_do_wykresu]
                
            subtab_saldo, subtab_kdi = st.tabs(["📉 Oś Czasu Salda (PLN)", "🎯 Dynamika Wskaźnika KDI"])
            with subtab_saldo:
                fig_saldo = go.Figure()
                fig_saldo.add_trace(go.Scatter(
                    x=punkty_x, y=punkty_saldo, mode='lines+markers', name='Saldo',
                    line=dict(color='#a855f7', width=3, shape='spline'),
                    marker=dict(size=7, color='#c084fc', line=dict(color='#ffffff', width=1.5)),
                    hovertemplate='Data: %{x}<br>Saldo: %{y:.2f} zł<extra></extra>'
                ))
                fig_saldo.add_hline(y=0, line_dash="solid", line_color="#ffffff", line_width=2,
                                    annotation_text="0.00 zł (RÓWNOWAGA)", annotation_position="top left",
                                    annotation_font_color="#ffffff", annotation_font_size=11)
                fig_saldo.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(21, 18, 38, 0.9)',
                    margin=dict(l=20, r=20, t=30, b=20), height=360,
                    xaxis=dict(showgrid=True, gridcolor='#262040', color='#94a3b8'),
                    yaxis=dict(showgrid=True, gridcolor='#262040', color='#94a3b8'), hovermode="x unified"
                )
                st.plotly_chart(fig_saldo, width="stretch")

            with subtab_kdi:
                kolory_markerow_kdi = [pobierz_kolor_kdi(v) for v in punkty_kdi]
                fig_kdi = go.Figure()
                fig_kdi.add_trace(go.Scatter(
                    x=punkty_x, y=punkty_kdi, mode='lines+markers', name='KDI',
                    line=dict(color='#64748b', width=2.5, shape='spline'),
                    marker=dict(size=8, color=kolory_markerow_kdi, line=dict(color='#ffffff', width=1.5)),
                    connectgaps=False, hovertemplate='Data: %{x}<br>KDI: %{y:.2f}<extra></extra>'
                ))
                fig_kdi.add_hline(y=1.0, line_dash="solid", line_color="#ffffff", line_width=2,
                                  annotation_text="1.00 (Cel 100%)", annotation_position="bottom left",
                                  annotation_font_color="#ffffff", annotation_font_size=11)
                fig_kdi.add_hline(y=1.2, line_dash="dash", line_color="#facc15", line_width=2,
                                  annotation_text="1.20 (Granica)", annotation_position="top left",
                                  annotation_font_color="#facc15", annotation_font_size=11)
                valid_kdi = [v for v in punkty_kdi if v is not None]
                max_kdi = max(valid_kdi) if valid_kdi else 2.0
                fig_kdi.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(21, 18, 38, 0.9)',
                    margin=dict(l=20, r=20, t=30, b=20), height=360,
                    xaxis=dict(showgrid=True, gridcolor='#262040', color='#94a3b8'),
                    yaxis=dict(showgrid=True, gridcolor='#262040', color='#94a3b8', range=[0.5, max(max_kdi + 0.5, 2.0)]),
                    hovermode="x unified"
                )
                st.plotly_chart(fig_kdi, width="stretch")

            col_w, col_r, col_k = st.columns(3)
            with col_w:
                st.markdown("**Historia Wpłat**")
                if not hist_wplaty.empty:
                    hw = hist_wplaty.copy()
                    hw["Kwota"] = (hw["kwota_gr"] / 100.0).map("{:.2f} zł".format)
                    st.dataframe(hw[["id", "data_wplaty", "Kwota", "notatka"]], width="stretch", hide_index=True)
                else:
                    st.caption("Brak wpłat.")
            with col_r:
                st.markdown("**Ręczne Naliczenia**")
                if not hist_naliczenia_reczne.empty:
                    hr = hist_naliczenia_reczne.copy()
                    hr["Kwota"] = (hr["kwota_gr"] / 100.0).map("{:.2f} zł".format)
                    st.dataframe(hr[["data_naliczenia", "Kwota", "tytul"]], width="stretch", hide_index=True)
                else:
                    st.caption("Brak ręcznych naliczeń.")
            with col_k:
                st.markdown("**Historia Korekt Salda**")
                if not hist_korekty.empty:
                    hk = hist_korekty.copy()
                    hk["Delta"] = (hk["delta_gr"] / 100.0).map("{:+.2f} zł".format)
                    hk["Docelowe"] = (hk["docelowe_saldo_gr"] / 100.0).map("{:.2f} zł".format)
                    st.dataframe(hk[["data_korekty", "Delta", "Docelowe", "powod"]], width="stretch", hide_index=True)
                else:
                    st.caption("Brak korekt.")

    # 3. ZARZĄDZANIE WPŁATAMI
    with tab_map["💰 Wpłaty Członków"]:
        st.markdown("<div style='max-width: 650px;'>", unsafe_allow_html=True)
        if not dane_przeliczone:
            st.warning("Najpierw wprowadź członków do bazy tego koła.")
        else:
            opcje_w = {d["id"]: f"{d['imie_nazwisko']} (Saldo: {d['saldo_akt_pln']:.2f} zł)" for d in dane_przeliczone}
            
            # WIDOK WPŁAT: ADMIN / SKARBNIK KRAJOWY
            if rola_uzytkownika in ("ADMIN", "SKARBNIK_KRAJOWY"):
                tryb_operacji = st.radio(
                    "Wybierz czynność:", 
                    ["➕ Nowa wpłata (Księgowanie bezpośrednie)", "📥 Zgłoś do kolejki akceptacji (Test procedury)", "✏️ Popraw / Usuń wpłatę"], 
                    horizontal=True
                )

                if tryb_operacji in ("➕ Nowa wpłata (Księgowanie bezpośrednie)", "📥 Zgłoś do kolejki akceptacji (Test procedury)"):
                    if "wplata_token" not in st.session_state:
                        st.session_state["wplata_token"] = str(uuid.uuid4())
                    with st.form("form_wplata_nowa_admin", clear_on_submit=False):
                        wybrany = st.selectbox("Wybierz członka", options=list(opcje_w.keys()), format_func=lambda x: opcje_w[x])
                        kwota_pln = st.number_input("Kwota wpłaty (PLN)", min_value=0.01, value=9.0, step=1.0)
                        data_w = st.date_input("Data wpływu środków", value=dzis_pl(), min_value=date(2015, 1, 1), max_value=dzis_pl())
                        notatka = st.text_input("Tytuł / Notatka", value="Składka członkowska")
                        
                        osw_test = "MAM_POTWIERDZENIE"
                        if tryb_operacji == "📥 Zgłoś do kolejki akceptacji (Test procedury)":
                            osw_test = st.selectbox("Oświadczenie testowe:", ["MAM_POTWIERDZENIE", "BRAK_POTWIERDZENIA"])

                        wymus_duplikat = st.checkbox("Potwierdzam celowe dodanie kolejnej identycznej wpłaty (w ciągu 60s)")
                        
                        btn_txt = "Zaksięguj nową wpłatę bezpośrednio" if "Księgowanie" in tryb_operacji else "Wyślij wpłatę do kolejki weryfikacji"
                        if st.form_submit_button(btn_txt):
                            kwota_gr = int(round(kwota_pln * 100))
                            teraz = teraz_utc()
                            czl_kolo_id = db_scalar("SELECT kolo_id FROM czlonkowie WHERE id = %s", (wybrany,)) or wybrane_kolo_id

                            if tryb_operacji == "➕ Nowa wpłata (Księgowanie bezpośrednie)":
                                granica_czasu = teraz - timedelta(seconds=60)
                                liczba_ostatnich = db_scalar("""
                                    SELECT COUNT(*) FROM wplaty 
                                    WHERE czlonek_id = %s AND kwota_gr = %s AND data_wpisu >= %s
                                """, (wybrany, kwota_gr, granica_czasu))
                                
                                if liczba_ostatnich and liczba_ostatnich > 0 and not wymus_duplikat:
                                    st.error("⚠️ Wykryto identyczną wpłatę w ciągu ostatnich 60 sekund. Zaznacz checkbox, aby potwierdzić.")
                                else:
                                    try:
                                        db_execute("""
                                            INSERT INTO wplaty (kolo_id, czlonek_id, kwota_gr, data_wplaty, notatka, data_wpisu, idempotency_key)
                                            VALUES (%s, %s, %s, %s, %s, %s, %s)
                                        """, (czl_kolo_id, wybrany, kwota_gr, data_w, notatka, teraz, st.session_state["wplata_token"]))
                                        st.session_state["wplata_token"] = str(uuid.uuid4())
                                        st.cache_data.clear()
                                        st.success("Wpłata zarejestrowana bezpośrednio w księdze.")
                                        st.rerun()
                                    except (psycopg.IntegrityError, errors.UniqueViolation):
                                        st.warning("Ta transakcja została już przetworzona w tle.")
                            else:
                                db_execute("""
                                    INSERT INTO wplaty_oczekujace (kolo_id, czlonek_id, zglosil_uzytkownik_id, kwota_gr, data_wplaty, notatka, oswiadczenie, status)
                                    VALUES (%s, %s, %s, %s, %s, %s, %s, 'OCZEKUJE')
                                """, (czl_kolo_id, wybrany, curr_user_id, kwota_gr, data_w, notatka, osw_test))
                                st.cache_data.clear()
                                st.success("✅ Wpłata trafiła do kolejki weryfikacji! Możesz ją zatwierdzić w zakładce '📥 Wpłaty do zaakceptowania'.")
                                st.rerun()

                else:
                    wplaty_lista = db_query("""
                        SELECT w.id, w.czlonek_id, w.kwota_gr, w.data_wplaty, w.notatka, c.imie_nazwisko 
                        FROM wplaty w 
                        LEFT JOIN czlonkowie c ON w.czlonek_id = c.id 
                        WHERE w.kolo_id = %s ORDER BY w.id DESC
                    """, (wybrane_kolo_id,))
                    if wplaty_lista.empty:
                        st.info("Brak wpłat do modyfikacji w tym kole.")
                    else:
                        opcje_edycji = {
                            row["id"]: f"ID #{row['id']} | {row['data_wplaty']} | {row['imie_nazwisko'] or 'Były członek'} | {row['kwota_gr']/100:.2f} zł ({row['notatka']})"
                            for _, row in wplaty_lista.iterrows()
                        }
                        wybrane_id = st.selectbox("Wybierz transakcję do modyfikacji", options=list(opcje_edycji.keys()), format_func=lambda x: opcje_edycji[x])
                        wpis_do_edycji = wplaty_lista[wplaty_lista["id"] == wybrane_id].iloc[0]
                        with st.form("form_wplata_edycja"):
                            mapa_czlonkow = {d["id"]: d["imie_nazwisko"] for d in dane_przeliczone}
                            domyslny_idx = list(mapa_czlonkow.keys()).index(int(wpis_do_edycji["czlonek_id"])) if pd.notna(wpis_do_edycji["czlonek_id"]) and int(wpis_do_edycji["czlonek_id"]) in mapa_czlonkow else 0
                            nowy_czlonek_id = st.selectbox(
                                "Przypisana osoba", options=list(mapa_czlonkow.keys()), 
                                index=domyslny_idx,
                                format_func=lambda x: mapa_czlonkow[x]
                            )
                            nowa_kwota_pln = st.number_input("Poprawna kwota (PLN)", min_value=0.01, value=float(wpis_do_edycji["kwota_gr"] / 100.0), step=1.0)
                            nowa_data_w = st.date_input("Poprawna data wpłaty", value=parse_date(wpis_do_edycji["data_wplaty"]), min_value=date(2015, 1, 1), max_value=dzis_pl())
                            nowa_notatka = st.text_input("Tytuł / Notatka", value=str(wpis_do_edycji["notatka"]))
                            st.markdown("---")
                            usun_checkbox = st.checkbox("🔥 Całkowicie usuń tę wpłatę z rejestru")
                            if st.form_submit_button("Zastosuj operację"):
                                if usun_checkbox:
                                    db_execute("DELETE FROM wplaty WHERE id = %s", (wybrane_id,))
                                    st.cache_data.clear()
                                    st.success("Wpłata usunięta.")
                                else:
                                    db_execute("""
                                        UPDATE wplaty 
                                        SET czlonek_id = %s, kwota_gr = %s, data_wplaty = %s, notatka = %s 
                                        WHERE id = %s
                                    """, (nowy_czlonek_id, int(round(nowa_kwota_pln * 100)), nowa_data_w, nowa_notatka, wybrane_id))
                                    st.cache_data.clear()
                                    st.success("Wpłata zaktualizowana.")
                                st.rerun()

            # WIDOK WPŁAT: SKARBNIK KOŁA / REGIONU
            else:
                st.markdown("#### 📥 Zadeklaruj Wpłatę Członka")
                st.info("ℹ️ Jako Skarbnik Koła/Regionu deklarujesz wpłatę. Zostanie zaksięgowana w kasie po zatwierdzeniu przez Skarbnika Krajowego lub Administratora.")
                
                with st.form("form_deklaracja_wplaty", clear_on_submit=True):
                    wybrany_czl = st.selectbox("Wybierz członka", options=list(opcje_w.keys()), format_func=lambda x: opcje_w[x])
                    deklarowana_kwota_pln = st.number_input("Kwota deklarowanej wpłaty (PLN)", min_value=0.01, value=9.0, step=1.0)
                    deklarowana_data = st.date_input("Data wpływu na konto", value=dzis_pl(), min_value=date(2015, 1, 1), max_value=dzis_pl())
                    deklarowana_notatka = st.text_input("Tytuł przelewu / Notatka", value="Składka członkowska")
                    
                    st.markdown("**Wymagane oświadczenie weryfikacyjne:**")
                    oswiadczenie_wybor = st.radio(
                        "Status potwierdzenia przelewu:",
                        [
                            "📄 Dysponuję potwierdzeniem przelewu i jestem świadomy że mogę zostać o nie poproszony przez Skarbnika Krajowego lub Administratora",
                            "⚠️ Nie dysponuję potwierdzeniem Skarbnik krajowy lub administrator musi potwierdzić dane"
                        ]
                    )
                    
                    if st.form_submit_button("Wyślij wpłatę do zaakceptowania"):
                        kod_oswiadczenia = "MAM_POTWIERDZENIE" if "Dysponuję" in oswiadczenie_wybor else "BRAK_POTWIERDZENIA"
                        kwota_gr_deklarowana = int(round(deklarowana_kwota_pln * 100))
                        czl_kolo_id = db_scalar("SELECT kolo_id FROM czlonkowie WHERE id = %s", (wybrany_czl,)) or wybrane_kolo_id
                        
                        db_execute("""
                            INSERT INTO wplaty_oczekujace (kolo_id, czlonek_id, zglosil_uzytkownik_id, kwota_gr, data_wplaty, notatka, oswiadczenie, status)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, 'OCZEKUJE')
                        """, (czl_kolo_id, wybrany_czl, curr_user_id, kwota_gr_deklarowana, deklarowana_data, deklarowana_notatka, kod_oswiadczenia))
                        st.cache_data.clear()
                        st.success("✅ Wpłata została zgłoszona! Trafiła do kolejki akceptacji.")
                        st.rerun()

                st.markdown("---")
                st.markdown("#### ⏳ Ostatnie wpłaty zgłoszone w tym kole")
                ostatnie_deklaracje_df = db_query("""
                    SELECT wo.id as "ID", wo.data_wplaty as "Data Przelewu", c.imie_nazwisko as "Członek", 
                           (wo.kwota_gr / 100.0) as "Kwota (PLN)", wo.status as "Status", wo.oswiadczenie as "Oświadczenie"
                    FROM wplaty_oczekujace wo
                    JOIN czlonkowie c ON wo.czlonek_id = c.id
                    WHERE wo.kolo_id = %s
                    ORDER BY wo.id DESC LIMIT 15
                """, (wybrane_kolo_id,))
                if not ostatnie_deklaracje_df.empty:
                    st.dataframe(ostatnie_deklaracje_df, width="stretch", hide_index=True)
                else:
                    st.caption("Brak zgłoszonych oczekujących wpłat.")
        st.markdown("</div>", unsafe_allow_html=True)

    # 4. RĘCZNE NALICZENIA (ADMIN & SKARBNIK KRAJOWY)
    if "📝 Ręczne Naliczenia" in tab_map:
        with tab_map["📝 Ręczne Naliczenia"]:
            st.markdown("<div style='max-width: 650px;'>", unsafe_allow_html=True)
            tryb_naliczenia = st.radio("Wybierz czynność:", ["➕ Nowe naliczenie", "📋 Przeglądaj / Usuń naliczenie"], horizontal=True)
            if not dane_przeliczone:
                st.warning("Najpierw wprowadź członków do bazy tego koła.")
            else:
                if tryb_naliczenia == "➕ Nowe naliczenie":
                    opcje_nal = {d["id"]: f"{d['imie_nazwisko']} (Saldo: {d['saldo_akt_pln']:.2f} zł)" for d in dane_przeliczone}
                    with st.form("form_nowe_naliczenie", clear_on_submit=True):
                        wybrany_nal = st.selectbox("Wybierz członka do obciążenia", options=list(opcje_nal.keys()), format_func=lambda x: opcje_nal[x])
                        kwota_nal_pln = st.number_input("Kwota naliczenia (PLN)", min_value=0.01, value=9.0, step=1.0)
                        data_nal = st.date_input("Data naliczenia", value=dzis_pl(), min_value=date(2015, 1, 1), max_value=dzis_pl())
                        tytul_nal = st.text_input("Tytuł obciążenia", value="Składka statutowa")
                        if st.form_submit_button("Zaksięguj naliczenie na koncie"):
                            if tytul_nal.strip():
                                db_execute("""
                                    INSERT INTO naliczenia_reczne (czlonek_id, kwota_gr, data_naliczenia, tytul, data_wpisu)
                                    VALUES (%s, %s, %s, %s, %s)
                                """, (wybrany_nal, int(round(kwota_nal_pln * 100)), data_nal, tytul_nal.strip(), teraz_utc()))
                                st.cache_data.clear()
                                st.success("Zaksięgowano ręczne obciążenie.")
                                st.rerun()
                            else:
                                st.error("Tytuł obciążenia nie może być pusty.")
                else:
                    lista_recznych = db_query("""
                        SELECT nr.id, nr.czlonek_id, nr.kwota_gr, nr.data_naliczenia, nr.tytul, c.imie_nazwisko 
                        FROM naliczenia_reczne nr JOIN czlonkowie c ON nr.czlonek_id = c.id 
                        WHERE c.kolo_id = %s ORDER BY nr.id DESC
                    """, (wybrane_kolo_id,))
                    if lista_recznych.empty:
                        st.info("Brak ręcznych naliczeń.")
                    else:
                        opcje_usun_nal = {
                            row["id"]: f"ID #{row['id']} | {row['data_naliczenia']} | {row['imie_nazwisko']} | {row['kwota_gr']/100:.2f} zł ({row['tytul']})"
                            for _, row in lista_recznych.iterrows()
                        }
                        wybrane_nal_id = st.selectbox("Wybierz wpis do usunięcia", options=list(opcje_usun_nal.keys()), format_func=lambda x: opcje_usun_nal[x])
                        if st.button("🔥 Usuń to naliczenie z konta"):
                            db_execute("DELETE FROM naliczenia_reczne WHERE id = %s", (wybrane_nal_id,))
                            st.cache_data.clear()
                            st.success("Naliczenie skasowane.")
                            st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)

    # 5. KASA KOŁA & WYDATKI
    with tab_map["💳 Kasa Koła & Wydatki"]:
        st.markdown(f"### 💳 Kasa i Płynność: {nazwa_aktywnego_kola}")
        
        kasa_kolor_netto = "accent-green" if faktyczna_kasa_kola_gr >= 0 else "accent-rose"
        col_k1, col_k2, col_k3 = st.columns(3)
        with col_k1:
            st.markdown(f"""
                <div class="bento-card">
                    <div class="bento-card-header">Suma Wpłaconych Pieniędzy</div>
                    <div class="bento-card-value accent-cyan">{(suma_wplat_kola_gr / 100.0):,.2f} PLN</div>
                    <div class="bento-card-sub">Wszystkie wpłaty na rachunek tego koła</div>
                </div>
            """, unsafe_allow_html=True)
        with col_k2:
            st.markdown(f"""
                <div class="bento-card">
                    <div class="bento-card-header">Suma Wydatków Koła</div>
                    <div class="bento-card-value accent-rose">{(suma_wydatkow_gr / 100.0):,.2f} PLN</div>
                    <div class="bento-card-sub">Zarejestrowane koszty operacyjne</div>
                </div>
            """, unsafe_allow_html=True)
        with col_k3:
            st.markdown(f"""
                <div class="bento-card">
                    <div class="bento-card-header">Pozostałe Środki (Kasa Netto)</div>
                    <div class="bento-card-value {kasa_kolor_netto}">{(faktyczna_kasa_kola_gr / 100.0):,.2f} PLN</div>
                    <div class="bento-card-sub">Wpłaty - Wydatki + Korekty ({(suma_korekt_kasy_gr / 100.0):+,.2f} PLN)</div>
                </div>
            """, unsafe_allow_html=True)

        st.markdown("---")

        col_wyd, col_kor_kasa = st.columns(2)
        with col_wyd:
            st.markdown("#### 📤 Zarejestruj Wydatek")
            with st.form("form_dodaj_wydatek", clear_on_submit=True):
                kwota_wyd_pln = st.number_input("Kwota wydatku (PLN)", min_value=0.01, value=50.0, step=1.0)
                data_wyd = st.date_input("Data poniesienia kosztu", value=dzis_pl(), min_value=date(2015, 1, 1), max_value=dzis_pl())
                kat_wyd = st.selectbox("Kategoria", ["Integracja", "Materiały biurowe / Druki", "Wydarzenia / Prelekcje", "Sprzęt", "Inne"])
                opis_wyd = st.text_input("Opis wydatku / Nr faktury", value="")
                if st.form_submit_button("Zaksięguj wydatek"):
                    db_execute("""
                        INSERT INTO wydatki (kolo_id, kwota_gr, data_wydatku, kategoria, opis, data_wpisu)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (wybrane_kolo_id, int(round(kwota_wyd_pln * 100)), data_wyd, kat_wyd, opis_wyd, teraz_utc()))
                    st.cache_data.clear()
                    st.success("Wydatek zaksięgowany. Stan kasy został przeliczony.")
                    st.rerun()

        with col_kor_kasa:
            st.markdown("#### 🛠️ Wyrównaj Stan Kasy z Wyciągiem ('z palca')")
            st.caption("Ustawia kwotę gotówki w kasie (wyrównanie ze stanem wyciągu bankowego na wskazaną datę).")
            with st.form("form_korekta_kasy", clear_on_submit=True):
                docelowy_stan_pln = st.number_input("Docelowy stan kasy (PLN)", value=float(faktyczna_kasa_kola_gr / 100.0), step=10.0)
                data_kor_kasa = st.date_input("Data wyciągu bankowego", value=dzis_pl(), min_value=date(2015, 1, 1), max_value=dzis_pl())
                powod_kasa = st.text_input("Powód korekty", value="Wyrównanie ze stanem wyciągu bankowego")
                if st.form_submit_button("Zastosuj korektę kasy"):
                    docelowy_gr = int(round(docelowy_stan_pln * 100))
                    _, _, kasa_wtedy_gr, _, _, _, _ = przelicz_finanse_dla_kola(wybrane_kolo_id, data_kor_kasa)
                    delta_kasy_gr = docelowy_gr - kasa_wtedy_gr
                    
                    db_execute("""
                        INSERT INTO korekty_kasy (kolo_id, delta_gr, docelowy_stan_gr, data_korekty, powod, data_wpisu)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (wybrane_kolo_id, delta_kasy_gr, docelowy_gr, data_kor_kasa, powod_kasa, teraz_utc()))
                    st.cache_data.clear()
                    st.success(f"Stan kasy zaktualizowany na dzień {data_kor_kasa} (zastosowano deltę: {delta_kasy_gr/100:+.2f} PLN).")
                    st.rerun()

        st.markdown("---")
        
        col_hist_w, col_hist_k = st.columns(2)
        with col_hist_w:
            st.markdown("#### 📋 Ostatnie Wydatki Koła")
            wydatki_df = db_query("""
                SELECT id as "ID", data_wydatku as "Data", (kwota_gr / 100.0) as "Kwota (PLN)", kategoria as "Kategoria", opis as "Opis / Faktura"
                FROM wydatki WHERE kolo_id = %s ORDER BY id DESC
            """, (wybrane_kolo_id,))
            if not wydatki_df.empty:
                st.dataframe(wydatki_df, width="stretch", hide_index=True)
            else:
                st.caption("Brak zarejestrowanych wydatków w historii koła.")

        with col_hist_k:
            st.markdown("#### ⚖️ Historia Ręcznych Korekt Kasy")
            korekty_kasy_df = db_query("""
                SELECT id as "ID", data_korekty as "Data", (delta_gr / 100.0) as "Delta (PLN)", (docelowy_stan_gr / 100.0) as "Nowy Stan (PLN)", powod as "Powód"
                FROM korekty_kasy WHERE kolo_id = %s ORDER BY id DESC
            """, (wybrane_kolo_id,))
            if not korekty_kasy_df.empty:
                st.dataframe(korekty_kasy_df, width="stretch", hide_index=True)
            else:
                st.caption("Brak ręcznych korekt stanu kasy.")

    # 6. KOREKTA SALDA OSOBY (ADMIN & SKARBNIK KRAJOWY)
    if "🛠️ Korekta Salda Osoby" in tab_map:
        with tab_map["🛠️ Korekta Salda Osoby"]:
            st.markdown("<div style='max-width: 550px;'>", unsafe_allow_html=True)
            if not dane_przeliczone:
                st.warning("Brak członków w kole.")
            else:
                opcje_k = {d["id"]: f"{d['imie_nazwisko']} | Obecne saldo: {d['saldo_akt_pln']:.2f} zł" for d in dane_przeliczone}
                with st.form("form_korekta_czlonek", clear_on_submit=True):
                    wybrany_k = st.selectbox("Wybierz członka", options=list(opcje_k.keys()), format_func=lambda x: opcje_k[x])
                    nowe_saldo_pln = st.number_input("Docelowe nowe saldo (PLN)", value=0.0, step=1.0)
                    data_kor = st.date_input("Data korekty", value=dzis_pl(), min_value=date(2015, 1, 1), max_value=dzis_pl())
                    powod = st.text_input("Powód korekty", value="Wyrównanie ze stanem papierowym")
                    if st.form_submit_button("Zastosuj korektę członka"):
                        nowe_saldo_gr = int(round(nowe_saldo_pln * 100))
                        dane_wtedy, _, _, _, _, _, _ = przelicz_finanse_dla_kola(wybrane_kolo_id, data_kor)
                        osoba_wtedy = next((x for x in dane_wtedy if x["id"] == wybrany_k), None)
                        saldo_wtedy_gr = osoba_wtedy["saldo_akt_gr"] if osoba_wtedy else 0
                        
                        delta_gr = nowe_saldo_gr - saldo_wtedy_gr
                        db_execute("""
                            INSERT INTO korekty (czlonek_id, delta_gr, docelowe_saldo_gr, data_korekty, powod, data_wpisu)
                            VALUES (%s, %s, %s, %s, %s, %s)
                        """, (wybrany_k, delta_gr, nowe_saldo_gr, data_kor, powod, teraz_utc()))
                        st.cache_data.clear()
                        st.success(f"Zaktualizowano saldo na dzień {data_kor} o deltę {delta_gr/100:+.2f} zł.")
                        st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)

    # 7. ZARZĄDZANIE CZŁONKAMI
    with tab_map["👤 Zarządzaj Członkami"]:
        st.markdown("<div style='max-width: 650px;'>", unsafe_allow_html=True)
        opcje_operacji_czlonka = ["➕ Dodaj nowego członka", "✏️ Edytuj profil członka"]
        if rola_uzytkownika in ("ADMIN", "SKARBNIK_KRAJOWY"):
            opcje_operacji_czlonka.append("🗑️ Usuń członka z koła")

        tryb_czlonka = st.radio("Wybierz operację na bazie członków:", opcje_operacji_czlonka, horizontal=True)
        st.markdown("---")

        if tryb_czlonka == "➕ Dodaj nowego członka":
            st.markdown(f"### ➕ Dodaj członka do: **{nazwa_aktywnego_kola}**")
            with st.form("form_dodaj_czlonka", clear_on_submit=True):
                nazwa = st.text_input("Imię i Nazwisko")
                c_u1, c_u2 = st.columns(2)
                with c_u1:
                    ur = st.date_input("Data urodzenia", value=date(2004, 1, 1), min_value=date(1940, 1, 1), max_value=dzis_pl())
                with c_u2:
                    wst = st.date_input("Data przystąpienia", value=dzis_pl(), min_value=date(2015, 1, 1), max_value=dzis_pl())
                c_u3, c_u4 = st.columns(2)
                with c_u3:
                    s_start_pln = st.number_input("Saldo początkowe (PLN)", min_value=-10000.0, max_value=10000.0, value=0.0, step=1.0)
                with c_u4:
                    param = st.selectbox("Próg składek", ["AUTO", "B", "M", "S"])
                if st.form_submit_button("Zapisz profil w bazie"):
                    poprawne, err_msg = waliduj_daty_czlonka(ur, wst)
                    if not poprawne:
                        st.error(f"⚠️ {err_msg}")
                    elif not nazwa.strip():
                        st.error("Imię i nazwisko jest wymagane.")
                    else:
                        db_execute("""
                            INSERT INTO czlonkowie (kolo_id, imie_nazwisko, data_urodzenia, data_przystapienia, saldo_startowe_gr, reczny_parametr)
                            VALUES (%s, %s, %s, %s, %s, %s)
                        """, (wybrane_kolo_id, nazwa.strip(), ur, wst, int(round(s_start_pln * 100)), param))
                        st.cache_data.clear()
                        st.success(f"Dodano członka: {nazwa}")
                        st.rerun()

        elif tryb_czlonka == "✏️ Edytuj profil członka":
            st.markdown(f"### ✏️ Edycja profilu członka w: **{nazwa_aktywnego_kola}**")
            if not dane_przeliczone:
                st.info("Brak członków w tym kole do edycji.")
            else:
                mapa_edycji = {d["id"]: f"{d['imie_nazwisko']} (Saldo: {d['saldo_akt_pln']:.2f} zł)" for d in dane_przeliczone}
                czlonek_edit_id = st.selectbox("Wybierz członka do edycji:", options=list(mapa_edycji.keys()), format_func=lambda x: mapa_edycji[x])
                osoba_edytowana = next(d for d in dane_przeliczone if d["id"] == czlonek_edit_id)
                
                with st.form("form_edytuj_czlonka"):
                    nowe_imie = st.text_input("Imię i Nazwisko", value=osoba_edytowana["imie_nazwisko"])
                    c_e1, c_e2 = st.columns(2)
                    with c_e1:
                        data_ur_val = parse_date(osoba_edytowana["data_ur"])
                        nowa_data_ur = st.date_input("Data urodzenia", value=data_ur_val, min_value=date(1940, 1, 1), max_value=dzis_pl())
                    with c_e2:
                        data_wst_val = parse_date(osoba_edytowana["data_wst"])
                        nowa_data_wst = st.date_input("Data przystąpienia", value=data_wst_val, min_value=date(2015, 1, 1), max_value=dzis_pl())
                    
                    c_e3, c_e4 = st.columns(2)
                    with c_e3:
                        s_start_biezace = float(osoba_edytowana["saldo_start_gr"] / 100.0)
                        nowe_s_start_pln = st.number_input("Saldo początkowe (PLN)", min_value=-10000.0, max_value=10000.0, value=s_start_biezace, step=1.0)
                    with c_e4:
                        param_options = ["AUTO", "B", "M", "S"]
                        cur_param = osoba_edytowana["reczny_parametr"] if osoba_edytowana["reczny_parametr"] in param_options else "AUTO"
                        nowy_param = st.selectbox("Próg składek", param_options, index=param_options.index(cur_param))
                    
                    if rola_uzytkownika in ("ADMIN", "SKARBNIK_KRAJOWY"):
                        lista_kol_docelowych = db_query("SELECT id, nazwa FROM aktywne_kola ORDER BY nazwa ASC")
                    elif rola_uzytkownika == "SKARBNIK_REGIONU":
                        lista_kol_docelowych = db_query("SELECT id, nazwa FROM aktywne_kola WHERE region_id = %s ORDER BY nazwa ASC", (zalogowany_uzytkownik["region_id"],))
                    else:
                        lista_kol_docelowych = db_query("SELECT id, nazwa FROM aktywne_kola WHERE id = %s", (wybrane_kolo_id,))

                    mapa_kol_doc = dict(zip(lista_kol_docelowych["id"], lista_kol_docelowych["nazwa"]))
                    docelowe_kolo_id = st.selectbox(
                        "Koło przynależne:", 
                        options=list(mapa_kol_doc.keys()), 
                        index=list(mapa_kol_doc.keys()).index(wybrane_kolo_id) if wybrane_kolo_id in mapa_kol_doc else 0,
                        format_func=lambda x: mapa_kol_doc[x],
                        disabled=(rola_uzytkownika == "SKARBNIK_KOLA")
                    )

                    czy_zmieniono_krytyczne = (nowa_data_wst != data_wst_val) or (int(round(nowe_s_start_pln * 100)) != osoba_edytowana["saldo_start_gr"])
                    czy_transfer = (docelowe_kolo_id != wybrane_kolo_id)

                    if czy_transfer:
                        st.warning("⚠️ **Transfer do innego koła:** Dotychczasowe wpłaty członka pozostaną w kasie obecnego koła (zgodnie z historią bankową).")

                    potwierdzenie_krytyczne = not czy_zmieniono_krytyczne
                    if czy_zmieniono_krytyczne:
                        st.error("⚠️ **Modyfikacja parametrów krytycznych:** Zmiana daty przystąpienia lub salda początkowego przeliczy wstecznie naliczenia i wskaźnik KDI od początku obecności członka!")
                        potwierdzenie_krytyczne = st.checkbox("Świadomie potwierdzam wsteczną modyfikację parametrów finansowych członka")

                    if st.form_submit_button("💾 Zapisz zmiany w profilu"):
                        poprawne, err_msg = waliduj_daty_czlonka(nowa_data_ur, nowa_data_wst)
                        if not poprawne:
                            st.error(f"⚠️ {err_msg}")
                        elif not nowe_imie.strip():
                            st.error("Imię i nazwisko nie może być puste.")
                        elif czy_zmieniono_krytyczne and not potwierdzenie_krytyczne:
                            st.error("Musisz zaznaczyć checkbox potwierdzający modyfikację parametrów krytycznych!")
                        else:
                            db_execute("""
                                UPDATE czlonkowie
                                SET imie_nazwisko = %s,
                                    data_urodzenia = %s,
                                    data_przystapienia = %s,
                                    saldo_startowe_gr = %s,
                                    reczny_parametr = %s,
                                    kolo_id = %s
                                WHERE id = %s
                            """, (
                                nowe_imie.strip(), 
                                nowa_data_ur, 
                                nowa_data_wst, 
                                int(round(nowe_s_start_pln * 100)), 
                                nowy_param, 
                                docelowe_kolo_id,
                                czlonek_edit_id
                            ))
                            st.cache_data.clear()
                            st.success(f"Zaktualizowano profil: {nowe_imie.strip()}")
                            st.rerun()

        elif tryb_czlonka == "🗑️ Usuń członka z koła":
            st.markdown(f"### 🔥 Usuwanie członka z koła: **{nazwa_aktywnego_kola}**")
            if not dane_przeliczone:
                st.info("Brak członków w tym kole.")
            else:
                mapa_usun = {d["id"]: f"{d['imie_nazwisko']} (Saldo: {d['saldo_akt_pln']:.2f} zł)" for d in dane_przeliczone}
                czlonek_del_id = st.selectbox("Wybierz osobę do usunięcia:", options=list(mapa_usun.keys()), format_func=lambda x: mapa_usun[x])
                osoba_kasowana = next(d for d in dane_przeliczone if d["id"] == czlonek_del_id)
                
                with st.form("form_usun_czlonka"):
                    st.error(f"⚠️ **UWAGA:** Usunięcie profilu **{osoba_kasowana['imie_nazwisko']}** nie usunie jego wpłat z kasy koła (zostaną zarchiwizowane w kasie).")
                    st.write(f"• Bieżące saldo: **{osoba_kasowana['saldo_akt_pln']:.2f} zł**")
                    st.write(f"• Suma zarejestrowanych wpłat: **{(osoba_kasowana['wplaty_gr'] / 100.0):.2f} zł**")
                    st.write(f"• Wskaźnik KDI: **{osoba_kasowana['kdi_str']}**")
                    
                    potwierdzenie_del = st.checkbox(f"Potwierdzam: usuń profil {osoba_kasowana['imie_nazwisko']} (wpłaty pozostaną w kasie koła)")
                    if st.form_submit_button("🔥 Usuń członka"):
                        if potwierdzenie_del:
                            try:
                                usun_czlonka_bezpiecznie(czlonek_del_id)
                                st.success(f"Profil {osoba_kasowana['imie_nazwisko']} został usunięty. Wpłaty zachowano w kasie.")
                                st.rerun()
                            except ValueError as err:
                                st.error(str(err))
                        else:
                            st.warning("Musisz zaznaczyć checkbox potwierdzenia.")
        st.markdown("</div>", unsafe_allow_html=True)

    # 8. SANDBOX / KALKULATOR PODRĘCZNY
    with tab_map["🧮 Kalkulator"]:
        st.markdown("### 🧮 Podręczny Kalkulator Składek i Mandatów")
        st.caption("Narzędzie symulacyjne — przeliczaj saldo, wskaźnik KDI oraz uprawnienia do głosu bez dotykania bazy danych i bez tworzenia wpisów audytowych.")

        col_in, col_out = st.columns([1.1, 1.4], gap="large")

        with col_in:
            st.markdown("#### 📥 Parametry Członka")
            
            tryb_naliczania = st.radio(
                "Sposób ustalania stawki miesięcznej:",
                ["🎂 Automatycznie z daty urodzenia (Wiek)", "🏷️ Ręczny wybór progu (B / M / S)"],
                horizontal=True
            )

            c_k1, c_k2 = st.columns(2)
            if tryb_naliczania == "🎂 Automatycznie z daty urodzenia (Wiek)":
                with c_k1:
                    calc_data_ur = st.date_input("Data urodzenia", value=date(2004, 5, 15), min_value=date(1940, 1, 1), max_value=dzis_pl(), key="calc_ur")
                with c_k2:
                    calc_param_kod = "AUTO"
                    st.text_input("Wybrany próg", value="AUTO (wg wieku)", disabled=True)
            else:
                with c_k1:
                    calc_data_ur = date(2000, 1, 1)
                    st.text_input("Data urodzenia", value="Pominięto (tryb ręczny)", disabled=True)
                with c_k2:
                    wybrana_stawka = st.selectbox("Próg składek:", ["M (9.00 zł / msc)", "B (6.00 zł / msc)", "S (15.00 zł / msc)"], key="calc_param_sel")
                    calc_param_kod = wybrana_stawka[0]

            c_k3, c_k4 = st.columns(2)
            with c_k3:
                calc_data_wst = st.date_input("Data przystąpienia", value=date(2025, 1, 1), min_value=date(2015, 1, 1), max_value=dzis_pl(), key="calc_wst")
            with c_k4:
                calc_punkt_odniesienia = st.date_input("Kalkulacja na dzień:", value=dzis_pl(), min_value=date(2015, 1, 1), key="calc_punkt")

            opcja_startu = st.selectbox(
                "Naliczaj składki od:",
                [
                    "Od daty przystąpienia członka",
                    "Od początku 2026 r. (01.01.2026)",
                    "Od systemowej daty odcięcia (01.10.2026)",
                    "Własna data początkowa"
                ]
            )
            
            if opcja_startu == "Od daty przystąpienia członka":
                data_poczatku_naliczania = calc_data_wst
            elif opcja_startu == "Od początku 2026 r. (01.01.2026)":
                data_poczatku_naliczania = max(calc_data_wst, date(2026, 1, 1))
            elif opcja_startu == "Od systemowej daty odcięcia (01.10.2026)":
                data_poczatku_naliczania = max(calc_data_wst, DATA_ODCIECIA)
            else:
                data_poczatku_naliczania = st.date_input("Własna data początkowa naliczania:", value=date(2025, 1, 1), min_value=date(2015, 1, 1))

            st.markdown("---")
            st.markdown("#### 💰 Wartości Finansowe")
            c_f1, c_f2 = st.columns(2)
            with c_f1:
                calc_saldo_start_pln = st.number_input("Saldo początkowe (PLN)", min_value=-10000.0, max_value=10000.0, value=0.0, step=10.0, key="calc_s_start")
            with c_f2:
                calc_wplaty_pln = st.number_input("Suma dotychczasowych wpłat (PLN)", min_value=0.0, max_value=50000.0, value=0.0, step=10.0, key="calc_wpl")

        poczatek_kalkulacji = max(calc_data_wst, data_poczatku_naliczania)
        suma_naliczen_gr = 0
        licznik_miesiecy = 0
        kursor_kalk = date(poczatek_kalkulacji.year, poczatek_kalkulacji.month, 1)

        while kursor_kalk <= calc_punkt_odniesienia:
            _, last_day = calendar.monthrange(kursor_kalk.year, kursor_kalk.month)
            ostatni_dzien_msc = date(kursor_kalk.year, kursor_kalk.month, last_day)
            if ostatni_dzien_msc <= calc_punkt_odniesienia:
                _, stawka_msc_gr = pobierz_parametr(calc_data_ur, calc_param_kod, ostatni_dzien_msc)
                suma_naliczen_gr += stawka_msc_gr
                licznik_miesiecy += 1
            kursor_kalk += relativedelta(months=1)

        prog_biezacy, stawka_biezaca_gr = pobierz_parametr(calc_data_ur, calc_param_kod, calc_punkt_odniesienia)
        stawka_biezaca_pln = stawka_biezaca_gr / 100.0

        saldo_start_gr = int(round(calc_saldo_start_pln * 100))
        wplaty_gr = int(round(calc_wplaty_pln * 100))
        saldo_koncowe_gr = saldo_start_gr + wplaty_gr - suma_naliczen_gr
        saldo_koncowe_pln = saldo_koncowe_gr / 100.0

        s_i_gr = max(0, saldo_start_gr) + wplaty_gr
        z_i_gr = max(0, s_i_gr - saldo_koncowe_gr)
        kdi_calc = round(z_i_gr / s_i_gr, 2) if s_i_gr > 0 else None
        kdi_str = f"{kdi_calc:.2f}" if kdi_calc is not None else "Brak danych"
        kolor_kdi = pobierz_kolor_kdi(kdi_calc)

        if saldo_koncowe_gr >= 0:
            moze_glosowac = True
            miesiace_dlugu = 0.0
            doplata_do_glosu_pln = 0.0
        else:
            miesiace_dlugu = abs(saldo_koncowe_gr) / stawka_biezaca_gr
            moze_glosowac = (miesiace_dlugu <= 6.0)
            limit_karencji_gr = 6 * stawka_biezaca_gr
            doplata_do_glosu_gr = max(0, abs(saldo_koncowe_gr) - limit_karencji_gr)
            doplata_do_glosu_pln = doplata_do_glosu_gr / 100.0

        doplata_do_zera_pln = max(0.0, -saldo_koncowe_pln)

        with col_out:
            st.markdown("#### 📊 Wynik Symulacji")

            cb1, cb2 = st.columns(2)
            with cb1:
                kolor_salda = "accent-green" if saldo_koncowe_pln >= 0 else "accent-rose"
                st.markdown(f"""
                    <div class="bento-card">
                        <div class="bento-card-header">Saldo Końcowe</div>
                        <div class="bento-card-value {kolor_salda}">{saldo_koncowe_pln:,.2f} PLN</div>
                        <div class="bento-card-sub">Start: {calc_saldo_start_pln:.2f} zł | Wpłaty: {calc_wplaty_pln:.2f} zł</div>
                    </div>
                """, unsafe_allow_html=True)
            with cb2:
                st.markdown(f"""
                    <div class="bento-card">
                        <div class="bento-card-header">Wskaźnik KDI</div>
                        <div class="bento-card-value" style="color: {kolor_kdi}; text-shadow: 0 0 16px {kolor_kdi}55;">{kdi_str}</div>
                        <div class="bento-card-sub">Cel statutowy: ≤ 1.20</div>
                    </div>
                """, unsafe_allow_html=True)

            cb3, cb4 = st.columns(2)
            with cb3:
                kolor_glosu = "#10b981" if moze_glosowac else "#f43f5e"
                napis_glosu = "TAK (UPRAWNIONY)" if moze_glosowac else "NIE (ZAWIESZONY)"
                st.markdown(f"""
                    <div class="bento-card">
                        <div class="bento-card-header">Prawo Głosu (Karencja ≤ 6 msc)</div>
                        <div class="bento-card-value" style="color: {kolor_glosu}; font-size: 1.45rem;">{napis_glosu}</div>
                        <div class="bento-card-sub">Zadłużenie: {miesiace_dlugu:.1f} msc (limit: 6.0 msc)</div>
                    </div>
                """, unsafe_allow_html=True)
            with cb4:
                st.markdown(f"""
                    <div class="bento-card">
                        <div class="bento-card-header">Naliczone Składki</div>
                        <div class="bento-card-value accent-cyan">{(suma_naliczen_gr / 100.0):,.2f} PLN</div>
                        <div class="bento-card-sub">{licznik_miesiecy} msc × {stawka_biezaca_pln:.2f} zł (Próg {prog_biezacy})</div>
                    </div>
                """, unsafe_allow_html=True)

            st.markdown("##### 📋 Rekomendacja dla wpłacającego:")
            if saldo_koncowe_pln >= 0:
                st.success(f"✅ **Konto w pełni uregulowane.** Nadpłata wynosi **{saldo_koncowe_pln:.2f} zł**. Członek ma pewne prawo głosu na zebraniach.")
            elif moze_glosowac:
                st.warning(f"⚠️ **Zadłużenie w granicach karencji ({miesiace_dlugu:.1f} msc długu).** Członek zachowuje prawo głosu. Do pełnego wyzerowania konta brakuje: **{doplata_do_zera_pln:.2f} zł**.")
            else:
                st.error(f"""
                    ❌ **Utrata prawa głosu!** Zadłużenie przekracza limit 6 miesięcy (wynosi **{miesiace_dlugu:.1f} msc**).
                    * Aby **przywrócić prawo głosu**, członek musi wpłacić minimum: **{doplata_do_glosu_pln:.2f} zł**
                    * Aby **całkowicie wyzerować zadłużenie**, należy wpłacić: **{doplata_do_zera_pln:.2f} zł**
                """)

            with st.expander("🔍 Symulacja natychmiastowej dopłaty (Co jeśli wpłaci X zł?)"):
                sym_doplata = st.slider("Symulowana kwota przelewu (PLN):", min_value=0.0, max_value=float(max(100.0, doplata_do_zera_pln + 50.0)), value=float(doplata_do_glosu_pln), step=5.0)
                sym_nowe_saldo = saldo_koncowe_pln + sym_doplata
                sym_nowe_msc_dlugu = abs(sym_nowe_saldo) / stawka_biezaca_pln if sym_nowe_saldo < 0 else 0.0
                sym_glos = (sym_nowe_saldo >= 0) or (sym_nowe_msc_dlugu <= 6.0)
                
                st.write(f"• Nowe saldo po dopłacie: **{sym_nowe_saldo:+.2f} zł**")
                st.write(f"• Nowe zadłużenie: **{sym_nowe_msc_dlugu:.1f} miesięcy**")
                st.write(f"• Status głosu: **{'✅ UPRAWNIONY' if sym_glos else '❌ NADAL BEZ PRAWA GŁOSU'}**")

    # 9. WPŁATY DO ZAAKCEPTOWANIA (ADMIN & SKARBNIK KRAJOWY)
    klucz_akceptacji = next((k for k in zakladki_nazwy if "Wpłaty do zaakceptowania" in k), None)
    if klucz_akceptacji and klucz_akceptacji in tab_map:
        with tab_map[klucz_akceptacji]:
            st.markdown("### 📥 Kolejka Weryfikacji Wpłat")
            st.caption("Wpłaty zadeklarowane przez Skarbników Kół i Regionów. Akceptacja natychmiast zasila saldo członka i bilans kasy koła.")
            
            oczekujace_df = db_query("""
                SELECT wo.id, wo.kolo_id, k.nazwa as kolo_nazwa, wo.czlonek_id, c.imie_nazwisko as czlonek_nazwa,
                       wo.kwota_gr, wo.data_wplaty, wo.notatka, wo.oswiadczenie, wo.data_zgloszenia,
                       u.imie_nazwisko as zglosil_nazwa
                FROM wplaty_oczekujace wo
                JOIN kola k ON wo.kolo_id = k.id
                LEFT JOIN czlonkowie c ON wo.czlonek_id = c.id
                LEFT JOIN uzytkownicy u ON wo.zglosil_uzytkownik_id = u.id
                WHERE wo.status = 'OCZEKUJE'
                ORDER BY wo.data_zgloszenia ASC
            """)

            if oczekujace_df.empty:
                st.success("🎉 Brak oczekujących wpłat. Wszystkie transakcje są na bieżąco rozpatrzone!")
            else:
                for _, r_oczek in oczekujace_df.iterrows():
                    o_id = r_oczek["id"]
                    o_kolo = r_oczek["kolo_nazwa"]
                    o_czl = r_oczek["czlonek_nazwa"] or "Brak przypisania"
                    o_kwota = r_oczek["kwota_gr"] / 100.0
                    o_data_w = r_oczek["data_wplaty"]
                    o_zglosil = r_oczek["zglosil_nazwa"] or "Użytkownik usunięty"
                    o_data_zgl = formatuj_czas_pl(r_oczek["data_zgloszenia"])
                    o_notatka = r_oczek["notatka"]
                    o_oswiadczenie = r_oczek["oswiadczenie"]
                    
                    if o_oswiadczenie == "MAM_POTWIERDZENIE":
                        badge_osw = "<span style='color: #10b981; font-weight: 700;'>📄 Zadeklarowano potwierdzenie przelewu</span>"
                    else:
                        badge_osw = "<span style='color: #f59e0b; font-weight: 700;'>⚠️ Brak potwierdzenia — weryfikacja z bankiem!</span>"

                    with st.container():
                        st.markdown(f"""
                            <div class="bento-card" style="margin-bottom: 12px; padding: 14px 20px;">
                                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                                    <div>
                                        <span style="font-size: 1.15rem; font-weight: 700; color: #ffffff;">{o_czl}</span>
                                        <span style="color: #94a3b8; font-size: 0.9rem;"> ({o_kolo})</span>
                                        <div style="font-size: 0.85rem; color: #cbd5e1; margin-top: 4px;">Data przelewu: <strong>{o_data_w}</strong> | Kwota: <strong style="color: #06b6d4; font-size: 1.05rem;">{o_kwota:.2f} zł</strong></div>
                                        <div style="font-size: 0.8rem; color: #64748b; margin-top: 2px;">Zgłosił: {o_zglosil} ({o_data_zgl}) | Tytuł: <em>{o_notatka}</em></div>
                                    </div>
                                    <div style="text-align: right;">{badge_osw}</div>
                                </div>
                            </div>
                        """, unsafe_allow_html=True)
                        
                        c_ak1, c_ak2, _ = st.columns([1, 1, 3])
                        with c_ak1:
                            if st.button(f"✅ Akceptuj wpłatę", key=f"btn_akcept_{o_id}", use_container_width=True):
                                teraz_akcept = teraz_utc()
                                idempotent_key = f"zaakceptowana_oczekujaca_{o_id}"
                                with pool.connection() as conn:
                                    with conn.cursor() as cur:
                                        cur.execute("""
                                            INSERT INTO wplaty (kolo_id, czlonek_id, kwota_gr, data_wplaty, notatka, data_wpisu, idempotency_key)
                                            VALUES (%s, %s, %s, %s, %s, %s, %s)
                                        """, (r_oczek["kolo_id"], r_oczek["czlonek_id"], r_oczek["kwota_gr"], r_oczek["data_wplaty"], r_oczek["notatka"], teraz_akcept, idempotent_key))
                                        
                                        cur.execute("""
                                            UPDATE wplaty_oczekujace 
                                            SET status = 'ZAAKCEPTOWANA', rozpatrzyl_uzytkownik_id = %s, data_rozpatrzenia = %s 
                                            WHERE id = %s
                                        """, (curr_user_id, teraz_akcept, o_id))
                                    conn.commit()
                                st.cache_data.clear()
                                st.success(f"Wpłata {o_kwota:.2f} zł dla {o_czl} została zaksięgowana w kasie!")
                                st.rerun()

                        with c_ak2:
                            with st.expander("❌ Odrzuć wpłatę"):
                                powod_odrzucenia = st.text_input("Powód odrzucenia:", value="Brak wpływu na rachunek bankowy", key=f"txt_odrzuc_{o_id}")
                                if st.button("Potwierdź odrzucenie", key=f"btn_odrzuc_{o_id}"):
                                    teraz_odrzut = teraz_utc()
                                    db_execute("""
                                        UPDATE wplaty_oczekujace 
                                        SET status = 'ODRZUCONA', rozpatrzyl_uzytkownik_id = %s, data_rozpatrzenia = %s, powod_odrzucenia = %s 
                                        WHERE id = %s
                                    """, (curr_user_id, teraz_odrzut, powod_odrzucenia, o_id))
                                    st.warning("Wpłata została odrzucona.")
                                    st.rerun()
                        st.markdown("<hr style='border: 1px solid #1f1a35;'>", unsafe_allow_html=True)

    # 10. ZARZĄDZANIE STRUKTURĄ
    if "🏛️ Zarządzaj Strukturą" in tab_map:
        with tab_map["🏛️ Zarządzaj Strukturą"]:
            st.markdown("### 🏛️ Zarządzanie Architekturą Organizacji")
            st.caption("Konfiguracja Regionów i Kół, dynamiczne przypinanie oraz bezpieczny Kosz | Czas audytu: **Warszawa**")
            
            if wybrany_region_id == -1:
                st.error(f"⚠️ **To koło ({nazwa_aktywnego_kola}) nie ma przypisanego regionu!** Wybierz region poniżej i kliknij przypisz:")
                if mapa_regionow:
                    with st.form("form_szybkie_przypisanie"):
                        docelowy_reg = st.selectbox("Wybierz region dla tego koła:", options=list(mapa_regionow.keys()), format_func=lambda x: mapa_regionow[x])
                        if st.form_submit_button("✅ Przypisz koło do tego regionu"):
                            db_execute("UPDATE kola SET region_id = %s WHERE id = %s", (docelowy_reg, wybrane_kolo_id))
                            st.cache_data.clear()
                            st.success(f"Koło zostało przypisane do regionu: {mapa_regionow[docelowy_reg]}.")
                            st.rerun()
                else:
                    st.info("Najpierw utwórz co najmniej jeden region w sekcji poniżej, aby móc do niego przypisać koło.")

            subtab_list = ["🌳 Aktywna Struktura"]
            if rola_uzytkownika == "ADMIN":
                subtab_list.append("🗑️ Kosz & Przywracanie")

            struktura_subtabs = st.tabs(subtab_list)
            
            with struktura_subtabs[0]:
                col_s1, col_s2 = st.columns(2)
                
                with col_s1:
                    st.markdown(f"#### 🌍 Regiony ({nazwa_kraju})")
                    with st.form("form_nowy_region", clear_on_submit=True):
                        nowy_reg_nazwa = st.text_input("Nazwa nowego regionu (np. Okręg Łódzki)")
                        if st.form_submit_button("➕ Utwórz Region"):
                            if nowy_reg_nazwa.strip():
                                try:
                                    db_execute("INSERT INTO regiony (kraj_id, nazwa) VALUES (%s, %s)", (wybrany_kraj_id, nowy_reg_nazwa.strip()))
                                    st.cache_data.clear()
                                    st.success(f"Dodano region: {nowy_reg_nazwa.strip()}")
                                    st.rerun()
                                except (psycopg.IntegrityError, errors.UniqueViolation):
                                    st.error("Aktywny region o tej nazwie już istnieje.")
                            else:
                                st.error("Nazwa regionu nie może być pusta.")

                    if mapa_regionow:
                        with st.form("form_edytuj_region"):
                            st.caption("Edycja nazwy istniejącego regionu:")
                            reg_do_edycji = st.selectbox("Wybierz region do edycji:", options=list(mapa_regionow.keys()), format_func=lambda x: mapa_regionow[x])
                            nowa_nazwa_reg = st.text_input("Nowa nazwa regionu", value=mapa_regionow[reg_do_edycji])
                            if st.form_submit_button("✏️ Zapisz nową nazwę regionu"):
                                if nowa_nazwa_reg.strip() and nowa_nazwa_reg.strip() != mapa_regionow[reg_do_edycji]:
                                    try:
                                        db_execute("UPDATE regiony SET nazwa = %s WHERE id = %s", (nowa_nazwa_reg.strip(), reg_do_edycji))
                                        st.cache_data.clear()
                                        st.success("Zmieniono nazwę regionu.")
                                        st.rerun()
                                    except (psycopg.IntegrityError, errors.UniqueViolation):
                                        st.error("Inny aktywny region ma już taką nazwę.")
                                elif not nowa_nazwa_reg.strip():
                                    st.error("Nazwa regionu nie może być pusta.")

                        if rola_uzytkownika == "ADMIN":
                            with st.form("form_kosz_region"):
                                st.markdown("<span style='color: #f59e0b; font-weight: 700;'>🗑️ Przenieś Region do Kosza</span>", unsafe_allow_html=True)
                                reg_do_kosza = st.selectbox("Wybierz region do usunięcia:", options=list(mapa_regionow.keys()), format_func=lambda x: mapa_regionow[x])
                                st.caption("Podległe koła również trafią do kosza, ale ich dane nie znikną.")
                                potwierdzenie_reg_kosz = st.checkbox("Potwierdzam: przenieś ten region do kosza")
                                if st.form_submit_button("Wyrzuć region do kosza"):
                                    if potwierdzenie_reg_kosz:
                                        ile_reg = db_scalar("SELECT COUNT(*) FROM aktywne_regiony WHERE kraj_id = %s", (wybrany_kraj_id,))
                                        if ile_reg <= 1:
                                            st.error("Nie możesz przenieść do kosza jedynego aktywnego regionu.")
                                        else:
                                            przenies_region_do_kosza(reg_do_kosza)
                                            st.success("Region trafił do kosza.")
                                            st.rerun()
                                    else:
                                        st.warning("Zaznacz checkbox, aby potwierdzić.")

                with col_s2:
                    st.markdown(f"#### 🏢 Zarządzanie Kołami")
                    
                    with st.form("form_edytuj_kolo"):
                        st.caption(f"Zmień nazwę aktywnego koła: **{nazwa_aktywnego_kola}**")
                        nowa_nazwa_kola_edit = st.text_input("Nowa nazwa koła", value=nazwa_aktywnego_kola)
                        if st.form_submit_button("✏️ Zapisz nową nazwę koła"):
                            if nowa_nazwa_kola_edit.strip() and nowa_nazwa_kola_edit.strip() != nazwa_aktywnego_kola:
                                try:
                                    db_execute("UPDATE kola SET nazwa = %s WHERE id = %s", (nowa_nazwa_kola_edit.strip(), wybrane_kolo_id))
                                    st.cache_data.clear()
                                    st.success("Zmieniono nazwę koła.")
                                    st.rerun()
                                except (psycopg.IntegrityError, errors.UniqueViolation):
                                    st.error("Inne aktywne koło ma już taką nazwę.")
                            elif not nowa_nazwa_kola_edit.strip():
                                st.error("Nazwa koła nie może być pusta.")

                    with st.form("form_przepnij_kolo"):
                        st.caption(f"Przepięcie koła **{nazwa_aktywnego_kola}** do innego regionu:")
                        opcje_docelowe = {0: "-- Usuń przypisanie (Koło bez regionu) --"}
                        opcje_docelowe.update(mapa_regionow)
                        aktualny_indeks = list(opcje_docelowe.keys()).index(wybrany_region_id) if wybrany_region_id in opcje_docelowe and wybrany_region_id != -1 else 0
                        docelowy_region = st.selectbox(
                            "Wybierz region docelowy:", 
                            options=list(opcje_docelowe.keys()), 
                            index=aktualny_indeks,
                            format_func=lambda x: opcje_docelowe[x]
                        )
                        if st.form_submit_button("🔄 Zastosuj przypisanie do regionu"):
                            nowe_r_id = docelowy_region if docelowy_region != 0 else None
                            db_execute("UPDATE kola SET region_id = %s WHERE id = %s", (nowe_r_id, wybrane_kolo_id))
                            st.cache_data.clear()
                            st.success("Zaktualizowano przypisanie koła.")
                            st.rerun()

                    with st.form("form_nowe_kolo_str", clear_on_submit=True):
                        st.caption("Dodaj nowe koło:")
                        nowa_nazwa_k = st.text_input("Nazwa nowego koła")
                        opcje_dla_nowego = {0: "-- Bez regionu (ostrzeżenie) --"}
                        opcje_dla_nowego.update(mapa_regionow)
                        indeks_domyslny = list(opcje_dla_nowego.keys()).index(wybrany_region_id) if wybrany_region_id in opcje_dla_nowego and wybrany_region_id != -1 else 0
                        region_dla_nowego = st.selectbox("Przypisz do regionu:", options=list(opcje_dla_nowego.keys()), index=indeks_domyslny, format_func=lambda x: opcje_dla_nowego[x])
                        if st.form_submit_button("➕ Utwórz Koło"):
                            if nowa_nazwa_k.strip():
                                try:
                                    r_val = region_dla_nowego if region_dla_nowego != 0 else None
                                    db_execute("INSERT INTO kola (nazwa, region_id, kraj_id) VALUES (%s, %s, %s)", (nowa_nazwa_k.strip(), r_val, wybrany_kraj_id))
                                    st.cache_data.clear()
                                    st.success(f"Utworzono koło: {nowa_nazwa_k.strip()}")
                                    st.rerun()
                                except (psycopg.IntegrityError, errors.UniqueViolation):
                                    st.error("Aktywne koło o takiej nazwie już istnieje.")
                            else:
                                st.error("Nazwa koła nie może być pusta.")

                    if rola_uzytkownika == "ADMIN":
                        with st.form("form_kosz_kolo"):
                            st.markdown("<span style='color: #f59e0b; font-weight: 700;'>🗑️ Przenieś Koło do Kosza</span>", unsafe_allow_html=True)
                            st.caption(f"Koło: **{nazwa_aktywnego_kola}** (zostanie ukryte, finanse i członkowie pozostaną bezpieczni)")
                            potwierdzenie_kolo_kosz = st.checkbox("Potwierdzam: przenieś to koło do kosza")
                            if st.form_submit_button("Wyrzuć koło do kosza"):
                                if potwierdzenie_kolo_kosz:
                                    przenies_kolo_do_kosza(wybrane_kolo_id)
                                    st.success(f"Koło '{nazwa_aktywnego_kola}' zostało przeniesione do kosza.")
                                    st.rerun()
                                else:
                                    st.warning("Zaznacz checkbox, aby przenieść koło do kosza.")

            if rola_uzytkownika == "ADMIN" and len(struktura_subtabs) > 1:
                with struktura_subtabs[1]:
                    st.markdown("### 🗑️ Elementy w Koszu")
                    st.caption("Jednostki w koszu są odcięte od statystyk i selektorów. Możesz je przywrócić lub usunąć na zawsze.")
                    
                    c_k_reg, c_k_kola = st.columns(2)
                    
                    with c_k_reg:
                        st.markdown("#### 🌍 Usunięte Regiony")
                        regiony_kosz_df = db_query("""
                            SELECT id, nazwa, deleted_at FROM regiony 
                            WHERE kraj_id = %s AND is_deleted = TRUE 
                            ORDER BY deleted_at DESC
                        """, (wybrany_kraj_id,))
                        
                        if regiony_kosz_df.empty:
                            st.info("Kosz regionów jest pusty.")
                        else:
                            for _, r_row in regiony_kosz_df.iterrows():
                                r_id = r_row["id"]
                                r_nazwa = r_row["nazwa"]
                                del_str = formatuj_czas_pl(r_row["deleted_at"])
                                
                                st.markdown(f"**{r_nazwa}** (usunięto: {del_str})")
                                c_r1, c_r2 = st.columns([1, 1])
                                with c_r1:
                                    if st.button(f"♻️ Przywróć region", key=f"btn_res_reg_{r_id}"):
                                        przywroc_region_z_kosza(r_id)
                                        st.success(f"Przywrócono region '{r_nazwa}'.")
                                        st.rerun()
                                with c_r2:
                                    with st.expander("💥 Trwałe usunięcie"):
                                        potw_hard_r = st.checkbox("Potwierdzam trwałe skasowanie", key=f"chk_hard_reg_{r_id}")
                                        if st.button(f"Usuń na zawsze", key=f"btn_hard_reg_{r_id}"):
                                            if potw_hard_r:
                                                try:
                                                    usun_region_trwale(r_id)
                                                    st.success(f"Region '{r_nazwa}' usunięty bezpowrotnie.")
                                                    st.rerun()
                                                except ValueError as err:
                                                    st.error(str(err))
                                            else:
                                                st.warning("Zaznacz checkbox!")
                                st.divider()

                    with c_k_kola:
                        st.markdown("#### 🏢 Usunięte Koła")
                        kola_kosz_df = db_query("""
                            SELECT k.id, k.nazwa, k.deleted_at, r.nazwa as reg_nazwa, r.is_deleted as reg_is_deleted
                            FROM kola k
                            LEFT JOIN regiony r ON k.region_id = r.id
                            WHERE k.is_deleted = TRUE AND k.kraj_id = %s
                            ORDER BY k.deleted_at DESC
                        """, (wybrany_kraj_id,))
                        
                        if kola_kosz_df.empty:
                            st.info("Kosz kół jest pusty.")
                        else:
                            for _, k_row in kola_kosz_df.iterrows():
                                k_id = k_row["id"]
                                k_nazwa = k_row["nazwa"]
                                r_nazwa = k_row["reg_nazwa"] or "Brak regionu"
                                reg_w_koszu = k_row["reg_is_deleted"]
                                del_str = formatuj_czas_pl(k_row["deleted_at"])
                                
                                st.markdown(f"**{k_nazwa}** | Region: *{r_nazwa}* (usunięto: {del_str})")
                                c_k1, c_k2 = st.columns([1, 1])
                                with c_k1:
                                    if reg_w_koszu:
                                        st.caption("⚠️ Region tego koła jest w koszu. Przywróć najpierw region.")
                                    else:
                                        if st.button(f"♻️ Przywróć koło", key=f"btn_res_kolo_{k_id}"):
                                            try:
                                                przywroc_kolo_z_kosza(k_id)
                                                st.success(f"Przywrócono koło '{k_nazwa}'.")
                                                st.rerun()
                                            except ValueError as err:
                                                st.error(str(err))
                                with c_k2:
                                    with st.expander("💥 Trwałe usunięcie"):
                                        potw_hard_k = st.checkbox("Potwierdzam trwałe skasowanie", key=f"chk_hard_kolo_{k_id}")
                                        if st.button(f"Usuń na zawsze", key=f"btn_hard_kolo_{k_id}"):
                                            if potw_hard_k:
                                                try:
                                                    usun_kolo_trwale(k_id)
                                                    st.success(f"Koło '{k_nazwa}' usunięte bezpowrotnie.")
                                                    st.rerun()
                                                except ValueError as err:
                                                    st.error(str(err))
                                            else:
                                                st.warning("Zaznacz checkbox!")
                                st.divider()

    # 11. LOGI AUDYTOWE (TYLKO ADMIN)
    if "📜 Logi Audytowe" in tab_map:
        with tab_map["📜 Logi Audytowe"]:
            subtab_audyt_db, subtab_audyt_wplaty, subtab_backup = st.tabs([
                "🛡️ Dziennik Audytu Zdarzeń (Trigger PG)", 
                "💰 Rejestr Wpłat",
                "💾 Kopia Zapasowa (.sql)"
            ])
            
            with subtab_audyt_db:
                st.markdown("#### 🛡️ Rejestr Zmian Systemowych (PostgreSQL Audit Trigger)")
                st.caption("Rejestruje każde zdarzenie INSERT, UPDATE oraz DELETE bezpośrednio na poziomie bazy.")
                
                c_f1, c_f2 = st.columns(2)
                with c_f1:
                    tabela_filtr = st.selectbox("Filtruj tabelę:", ["Wszystkie", "czlonkowie", "wplaty", "wplaty_oczekujace", "naliczenia_reczne", "korekty", "wydatki", "korekty_kasy", "kola", "regiony", "uzytkownicy"])
                with c_f2:
                    limit_logow = st.selectbox("Liczba ostatnich wpisów:", [50, 100, 200, 500], index=0)
                
                if tabela_filtr == "Wszystkie":
                    logi_db = db_query("SELECT * FROM audit_log ORDER BY id DESC LIMIT %s", (limit_logow,))
                else:
                    logi_db = db_query("SELECT * FROM audit_log WHERE tabela = %s ORDER BY id DESC LIMIT %s", (tabela_filtr, limit_logow))
                
                if logi_db.empty:
                    st.info("Brak zarejestrowanych wpisów w dzienniku audytu.")
                else:
                    logi_db["Czas (PL)"] = logi_db["zmieniono_o"].apply(formatuj_czas_pl)
                    wyswietl_db = logi_db[["id", "Czas (PL)", "tabela", "operacja", "rekord_id", "stare_dane", "nowe_dane"]].rename(columns={
                        "id": "ID", "tabela": "Tabela", "operacja": "Akcja", "rekord_id": "ID Rekordu", "stare_dane": "Stan Przed", "nowe_dane": "Stan Po"
                    })
                    st.dataframe(wyswietl_db, width="stretch", hide_index=True)
                    
                    csv_audyt = wyswietl_db.to_csv(index=False).encode('utf-8')
                    st.download_button(
                        "📥 Pobierz Dziennik Audytu (CSV)", 
                        data=csv_audyt, 
                        file_name=f"audit_log_{dzis.strftime('%Y%m%d')}.csv", 
                        mime="text/csv"
                    )

            with subtab_audyt_wplaty:
                logi_w = db_query("""
                    SELECT w.id as "ID", w.data_wpisu, w.data_wplaty as "Data Wpływu", 
                           COALESCE(c.imie_nazwisko, 'Były członek') as "Członek", 
                           (w.kwota_gr / 100.0) as "Kwota (PLN)", w.notatka as "Uwagi"
                    FROM wplaty w 
                    LEFT JOIN czlonkowie c ON w.czlonek_id = c.id 
                    WHERE w.kolo_id = %s ORDER BY w.id DESC
                """, (wybrane_kolo_id,))
                if not logi_w.empty:
                    logi_w["Zarejestrowano (PL)"] = logi_w["data_wpisu"].apply(formatuj_czas_pl)
                    kolumny_w = ["ID", "Zarejestrowano (PL)", "Data Wpływu", "Członek", "Kwota (PLN)", "Uwagi"]
                    st.dataframe(logi_w[kolumny_w], width="stretch", hide_index=True)
                    st.download_button("Pobierz CSV wpłat", data=logi_w[kolumny_w].to_csv(index=False).encode('utf-8'), file_name="wplaty.csv", mime="text/csv")
                else:
                    st.info("Brak wpłat w historii tego koła.")

            with subtab_backup:
                st.markdown("#### 💾 Pełna Kopia Zapasowa Bazy Danych (.sql)")
                st.caption("Wykonaj zrzut bazy PostgreSQL do pliku `.sql` bez obciążania pamięci RAM serwera (zapis strumieniowy na dysk).")

                c_s1, c_s2, c_s3, c_s4 = st.columns(4)
                with c_s1:
                    cnt_czl = db_scalar("SELECT COUNT(*) FROM czlonkowie") or 0
                    st.metric("Członkowie w bazie", f"{cnt_czl}")
                with c_s2:
                    cnt_wpl = db_scalar("SELECT COUNT(*) FROM wplaty") or 0
                    st.metric("Zarejestrowane wpłaty", f"{cnt_wpl}")
                with c_s3:
                    cnt_kola = db_scalar("SELECT COUNT(*) FROM kola WHERE is_deleted = FALSE") or 0
                    st.metric("Aktywne koła", f"{cnt_kola}")
                with c_s4:
                    cnt_aud = db_scalar("SELECT COUNT(*) FROM audit_log") or 0
                    st.metric("Wpisy w audycie", f"{cnt_aud}")

                st.markdown("---")

                col_btn, _ = st.columns([1.2, 2.0])
                with col_btn:
                    if st.button("🚀 Wygeneruj zrzut bazy (.sql)", key="btn_generate_sql_backup", use_container_width=True):
                        with st.spinner("Generowanie i strumieniowanie zrzutu na dysk..."):
                            try:
                                f_path, f_name, f_size_kb, silnik = generuj_zrzut_bazy_sql()
                                st.session_state["backup_filepath"] = f_path
                                st.session_state["backup_filename"] = f_name
                                st.session_state["backup_filesize_kb"] = f_size_kb
                                st.session_state["backup_timestamp"] = teraz_utc()
                                st.session_state["backup_engine"] = silnik
                            except Exception as e:
                                st.error(f"Błąd podczas tworzenia zrzutu bazy: {e}")

                if "backup_filepath" in st.session_state and os.path.exists(st.session_state["backup_filepath"]):
                    b_path = st.session_state["backup_filepath"]
                    b_name = st.session_state["backup_filename"]
                    b_size_kb = st.session_state["backup_filesize_kb"]
                    czas_pl_str = formatuj_czas_pl(st.session_state["backup_timestamp"])
                    silnik_info = st.session_state.get("backup_engine", "Citadel Engine")

                    st.success(f"✅ Zrzut bazy zapisany na dysku! Rozmiar: **{b_size_kb:.1f} KB** | Czas: **{czas_pl_str}** | Silnik: **{silnik_info}**")
                    
                    with open(b_path, "rb") as f_dl:
                        st.download_button(
                            label="📥 Pobierz plik bazy (.sql)",
                            data=f_dl.read(),
                            file_name=b_name,
                            mime="application/sql",
                            key="btn_download_sql_file"
                        )

    # 12. PANEL CENTAURI (TYLKO DLA ADMINA — ZABEZPIECZONY PRZED SELF-LOCKOUTEM)
    if "🏛️ Panel Centauri" in tab_map:
        with tab_map["🏛️ Panel Centauri"]:
            st.markdown("### 🏛️ Panel Centauri — Zarządzanie Kontami i Uprawnieniami")
            st.caption("Centrum kontroli dostępu, tworzenie skarbników, przypisywanie do kół i regionów, natychmiastowe zawieszanie sesji.")

            sub_cent1, sub_cent2 = st.tabs(["➕ Nowe Konto", "👥 Rejestr Użytkowników & Akcje"])

            # SUBTAB 1: TWORZENIE NOWEGO UŻYTKOWNIKA
            with sub_cent1:
                st.markdown("<div style='max-width: 600px;'>", unsafe_allow_html=True)
                st.markdown("#### 👤 Dane Uwierzytelniające")
                nowy_login = st.text_input("Login (np. skarbnik_lodz)", key="txt_nowy_login")
                nowe_imie_nazw = st.text_input("Imię i Nazwisko użytkownika", key="txt_nowe_imie")
                nowe_haslo_start = st.text_input("Hasło startowe", value="Citadel2026!", key="txt_nowe_haslo")
                
                st.markdown("#### 🏷️ Rola i Zakres Dostępów")
                wybrana_rola = st.selectbox(
                    "Wybierz rolę w organizacji:",
                    ["SKARBNIK_KOLA", "SKARBNIK_REGIONU", "SKARBNIK_KRAJOWY", "ADMIN"],
                    format_func=lambda x: {
                        "SKARBNIK_KOLA": "🏢 Skarbnik Koła",
                        "SKARBNIK_REGIONU": "📊 Skarbnik Regionu",
                        "SKARBNIK_KRAJOWY": "🇵🇱 Skarbnik Krajowy",
                        "ADMIN": "👑 Administrator (Super Admin)"
                    }[x],
                    key="sel_dynamiczna_rola"
                )

                assigned_kolo = None
                assigned_reg = None

                if wybrana_rola == "SKARBNIK_KOLA":
                    wszystkie_aktywne_kola = db_query("""
                        SELECT k.id, k.nazwa, k.region_id, k.kraj_id, r.nazwa as region_nazwa
                        FROM aktywne_kola k
                        LEFT JOIN aktywne_regiony r ON k.region_id = r.id
                        ORDER BY k.nazwa ASC
                    """)
                    if wszystkie_aktywne_kola.empty:
                        st.error("Brak aktywnych kół w bazie. Najpierw utwórz koło w strukturze.")
                    else:
                        mapa_opcji_kol = {
                            row["id"]: f"{row['nazwa']} (Region: {row['region_nazwa'] or 'Brak'})" 
                            for _, row in wszystkie_aktywne_kola.iterrows()
                        }
                        assigned_kolo = st.selectbox("Przypisz Skarbnika do Koła:", options=list(mapa_opcji_kol.keys()), format_func=lambda x: mapa_opcji_kol[x])

                elif wybrana_rola == "SKARBNIK_REGIONU":
                    wszystkie_aktywne_reg = pobierz_slownik_regionow(wybrany_kraj_id)
                    if wszystkie_aktywne_reg.empty:
                        st.error("Brak aktywnych regionów w bazie. Najpierw utwórz region w strukturze.")
                    else:
                        mapa_opcji_reg = dict(zip(wszystkie_aktywne_reg["id"], wszystkie_aktywne_reg["nazwa"]))
                        assigned_reg = st.selectbox("Przypisz Skarbnika do Regionu:", options=list(mapa_opcji_reg.keys()), format_func=lambda x: mapa_opcji_reg[x])

                else:
                    st.info("ℹ️ **Dostęp ogólnokrajowy:** Użytkownik z tą rolą ma automatyczny wgląd we wszystkie regiony i koła. Nie wymaga przypisania do jednostki.")

                wymus_haslo_check = st.checkbox("Wymuś zmianę hasła przy pierwszym logowaniu", value=True, key="chk_wymus_nowy")

                if st.button("➕ Utwórz konto użytkownika", key="btn_commit_nowy_user", use_container_width=True):
                    if not nowy_login.strip() or not nowe_imie_nazw.strip():
                        st.error("Login oraz Imię i Nazwisko są obowiązkowe!")
                    elif len(nowe_haslo_start) < 6:
                        st.error("Hasło musi mieć co najmniej 6 znaków.")
                    elif wybrana_rola == "SKARBNIK_KOLA" and assigned_kolo is None:
                        st.error("Musisz wybrać koło dla Skarbnika Koła!")
                    elif wybrana_rola == "SKARBNIK_REGIONU" and assigned_reg is None:
                        st.error("Musisz wybrać region dla Skarbnika Regionu!")
                    else:
                        try:
                            if wybrana_rola == "SKARBNIK_KOLA":
                                k_row = db_query("SELECT region_id, kraj_id FROM kola WHERE id = %s", (assigned_kolo,)).iloc[0]
                                k_id = assigned_kolo
                                r_id = k_row["region_id"]
                                kr_id = k_row["kraj_id"]
                            elif wybrana_rola == "SKARBNIK_REGIONU":
                                r_row = db_query("SELECT kraj_id FROM regiony WHERE id = %s", (assigned_reg,)).iloc[0]
                                k_id = None
                                r_id = assigned_reg
                                kr_id = r_row["kraj_id"]
                            else:
                                k_id = None
                                r_id = None
                                kr_id = wybrany_kraj_id

                            sol_u = generuj_sol()
                            h_u = hashuj_haslo(nowe_haslo_start, sol_u)

                            db_execute("""
                                INSERT INTO uzytkownicy (login, haslo_hash, salt, imie_nazwisko, rola, kraj_id, region_id, kolo_id, is_active, wymus_zmiane_hasla)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, TRUE, %s)
                            """, (nowy_login.strip(), h_u, sol_u, nowe_imie_nazw.strip(), wybrana_rola, kr_id, r_id, k_id, wymus_haslo_check))
                            st.success(f"Pomyślnie utworzono konto: {nowy_login.strip()}!")
                            st.rerun()
                        except (psycopg.IntegrityError, errors.UniqueViolation):
                            st.error("Użytkownik o takim loginie już istnieje w systemie.")
                st.markdown("</div>", unsafe_allow_html=True)

            # SUBTAB 2: LISTA I ZARZĄDZANIE KONTAMI
            with sub_cent2:
                st.markdown("#### 👥 Zarejestrowane Konta w Citadel")
                uzytkownicy_df = db_query("""
                    SELECT u.id, u.login, u.imie_nazwisko, u.rola, u.is_active, u.ostatnie_logowanie,
                           r.nazwa as region_nazwa, k.nazwa as kolo_nazwa
                    FROM uzytkownicy u
                    LEFT JOIN regiony r ON u.region_id = r.id
                    LEFT JOIN kola k ON u.kolo_id = k.id
                    ORDER BY u.id ASC
                """)

                tabela_kont = []
                for _, u_r in uzytkownicy_df.iterrows():
                    rola_label = {
                        "ADMIN": "👑 Super Admin",
                        "SKARBNIK_KRAJOWY": "🇵🇱 Skarbnik Krajowy",
                        "SKARBNIK_REGIONU": "📊 Skarbnik Regionu",
                        "SKARBNIK_KOLA": "🏢 Skarbnik Koła"
                    }.get(u_r["rola"], u_r["rola"])

                    if u_r["rola"] == "SKARBNIK_KOLA":
                        przypisanie_str = f"Koło: {u_r['kolo_nazwa'] or 'Brak'}"
                    elif u_r["rola"] == "SKARBNIK_REGIONU":
                        przypisanie_str = f"Region: {u_r['region_nazwa'] or 'Brak'}"
                    else:
                        przypisanie_str = "Centrala (Kraj)"

                    status_str = "🟢 Aktywny" if u_r["is_active"] else "🔴 ZAWIESZONY"

                    tabela_kont.append({
                        "ID": u_r["id"],
                        "Login": u_r["login"],
                        "Imię i Nazwisko": u_r["imie_nazwisko"],
                        "Rola": rola_label,
                        "Przypisanie": przypisanie_str,
                        "Status": status_str,
                        "Ostatnie logowanie": formatuj_czas_pl(u_r["ostatnie_logowanie"])
                    })

                st.dataframe(pd.DataFrame(tabela_kont), width="stretch", hide_index=True)

                st.markdown("---")
                col_akc1, col_akc2, col_akc3 = st.columns(3)

                # AKCJA 1: ZAWIESZENIE / ODBLOKOWANIE (WYKLUCZENIE SIEBIE)
                with col_akc1:
                    st.markdown("#### ⏸️ Zawieś / Odblokuj Dostęp")
                    opcje_zawieszenia = {
                        u["id"]: f"{u['login']} ({u['imie_nazwisko']}) — {'Aktywny' if u['is_active'] else 'ZAWIESZONY'}"
                        for _, u in uzytkownicy_df.iterrows() if u["id"] != curr_user_id
                    }
                    if opcje_zawieszenia:
                        sel_zawies = st.selectbox("Wybierz użytkownika:", options=list(opcje_zawieszenia.keys()), format_func=lambda x: opcje_zawieszenia[x], key="sel_zawies")
                        target_u = uzytkownicy_df[uzytkownicy_df["id"] == sel_zawies].iloc[0]
                        akcja_label = "🔴 Zawieś dostęp użytkownikowi" if target_u["is_active"] else "🟢 Przywróć dostęp użytkownikowi"
                        if st.button(akcja_label, key="btn_toggle_active"):
                            nowy_stan = not target_u["is_active"]
                            db_execute("UPDATE uzytkownicy SET is_active = %s WHERE id = %s", (nowy_stan, sel_zawies))
                            st.success("Zaktualizowano status konta!")
                            st.rerun()
                    else:
                        st.caption("Brak innych użytkowników do zawieszenia.")

                # AKCJA 2: PRZEPIĘCIE UPRAWNIEŃ (BEZWZGLĘDNA BLOKADA SAMOOKALECZENIA ADMINA)
                with col_akc2:
                    st.markdown("#### 🔄 Przepnij Uprawnienia")
                    opcje_przepiecia = {
                        u["id"]: f"{u['login']} ({u['imie_nazwisko']})" 
                        for _, u in uzytkownicy_df.iterrows()
                        if u["id"] != curr_user_id
                    }
                    
                    if not opcje_przepiecia:
                        st.caption("Brak innych użytkowników do zmiany uprawnień.")
                    else:
                        sel_przepnij = st.selectbox("Wybierz konto do modyfikacji:", options=list(opcje_przepiecia.keys()), format_func=lambda x: opcje_przepiecia[x], key="sel_przepnij")
                        
                        nowa_rola_edit = st.selectbox(
                            "Nowa rola:", 
                            ["SKARBNIK_KOLA", "SKARBNIK_REGIONU", "SKARBNIK_KRAJOWY", "ADMIN"],
                            format_func=lambda x: {
                                "SKARBNIK_KOLA": "🏢 Skarbnik Koła",
                                "SKARBNIK_REGIONU": "📊 Skarbnik Regionu",
                                "SKARBNIK_KRAJOWY": "🇵🇱 Skarbnik Krajowy",
                                "ADMIN": "👑 Administrator"
                            }[x],
                            key="sel_nowa_rola_edit"
                        )

                        new_kolo_id = None
                        new_reg_id = None

                        if nowa_rola_edit == "SKARBNIK_KOLA":
                            wszystkie_aktywne_kola = db_query("SELECT id, nazwa FROM aktywne_kola ORDER BY nazwa ASC")
                            mapa_all_kola = dict(zip(wszystkie_aktywne_kola["id"], wszystkie_aktywne_kola["nazwa"])) if not wszystkie_aktywne_kola.empty else {}
                            new_kolo_id = st.selectbox("Przypisz nowe koło:", options=list(mapa_all_kola.keys()), format_func=lambda x: mapa_all_kola[x], key="sel_new_kolo")
                        elif nowa_rola_edit == "SKARBNIK_REGIONU":
                            wszystkie_aktywne_reg = pobierz_slownik_regionow(wybrany_kraj_id)
                            mapa_all_reg = dict(zip(wszystkie_aktywne_reg["id"], wszystkie_aktywne_reg["nazwa"])) if not wszystkie_aktywne_reg.empty else {}
                            new_reg_id = st.selectbox("Przypisz nowy region:", options=list(mapa_all_reg.keys()), format_func=lambda x: mapa_all_reg[x], key="sel_new_reg")
                        else:
                            st.caption("ℹ️ Ta rola ma dostęp ogólnokrajowy (brak przypisania do jednostki).")

                        if st.button("Zastosuj przepięcie", key="btn_apply_reassign"):
                            if sel_przepnij == curr_user_id:
                                st.error("❌ Blokada bezpieczeństwa: Nie możesz zmodyfikować uprawnień własnego profilu!")
                            elif nowa_rola_edit == "SKARBNIK_KOLA":
                                k_info = db_query("SELECT region_id, kraj_id FROM kola WHERE id = %s", (new_kolo_id,)).iloc[0]
                                db_execute("""
                                    UPDATE uzytkownicy 
                                    SET rola = %s, kolo_id = %s, region_id = %s, kraj_id = %s 
                                    WHERE id = %s
                                """, (nowa_rola_edit, new_kolo_id, k_info["region_id"], k_info["kraj_id"], sel_przepnij))
                                st.cache_data.clear()
                                st.success("Uprawnienia zostały zaktualizowane!")
                                st.rerun()
                            elif nowa_rola_edit == "SKARBNIK_REGIONU":
                                r_info = db_query("SELECT kraj_id FROM regiony WHERE id = %s", (new_reg_id,)).iloc[0]
                                db_execute("""
                                    UPDATE uzytkownicy 
                                    SET rola = %s, kolo_id = NULL, region_id = %s, kraj_id = %s 
                                    WHERE id = %s
                                """, (nowa_rola_edit, new_reg_id, r_info["kraj_id"], sel_przepnij))
                                st.cache_data.clear()
                                st.success("Uprawnienia zostały zaktualizowane!")
                                st.rerun()
                            else:
                                db_execute("""
                                    UPDATE uzytkownicy 
                                    SET rola = %s, kolo_id = NULL, region_id = NULL 
                                    WHERE id = %s
                                """, (nowa_rola_edit, sel_przepnij))
                                st.cache_data.clear()
                                st.success("Uprawnienia zostały zaktualizowane!")
                                st.rerun()

                # AKCJA 3: RESET HASŁA
                with col_akc3:
                    st.markdown("#### 🔑 Reset Hasła")
                    opcje_resetu = {u["id"]: f"{u['login']} ({u['imie_nazwisko']})" for _, u in uzytkownicy_df.iterrows()}
                    sel_reset = st.selectbox("Konto do resetu:", options=list(opcje_resetu.keys()), format_func=lambda x: opcje_resetu[x], key="sel_reset")
                    haslo_reset_val = st.text_input("Nowe hasło:", value="Citadel2026!", key="txt_reset_pass")
                    wymus_reset_check = st.checkbox("Wymuś zmianę przy kolejnym logowaniu", value=True, key="chk_reset_wymus")
                    if st.button("Ustaw nowe hasło", key="btn_apply_reset_pass"):
                        if len(haslo_reset_val) < 6:
                            st.error("Hasło musi mieć co najmniej 6 znaków!")
                        else:
                            r_sol = generuj_sol()
                            r_hash = hashuj_haslo(haslo_reset_val, r_sol)
                            db_execute("""
                                UPDATE uzytkownicy 
                                SET haslo_hash = %s, salt = %s, wymus_zmiane_hasla = %s 
                                WHERE id = %s
                            """, (r_hash, r_sol, wymus_reset_check, sel_reset))
                            st.success("Hasło zostało pomyślnie zresetowane!")
