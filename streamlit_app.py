# streamlit_app.py
import os
import datetime as dt

import streamlit as st
import pandas as pd
import bcrypt
import psycopg
from psycopg.rows import dict_row


# =========================
# Config UI
# =========================
st.set_page_config(page_title="KR_TGM • Mantenciones e Historial", layout="wide")


# =========================
# Helpers
# =========================
def get_db_url() -> str:
    """
    DB_URL debe venir desde Streamlit Secrets.
    Recomendado (Supabase Session Pooler IPv4):
    postgresql://...@aws-0-us-west-2.pooler.supabase.com:5432/postgres?sslmode=require
    """
    if "DB_URL" in st.secrets:
        return st.secrets["DB_URL"]
    # fallback local (si quieres usar env var en desarrollo)
    env = os.getenv("DB_URL")
    if env:
        return env
    raise KeyError("DB_URL no está definido en Secrets (ni env var).")


def connect():
    db_url = get_db_url()
    # dict_row => fetch devuelve dicts
    return psycopg.connect(db_url, row_factory=dict_row, connect_timeout=8)


def hash_password(plain: str) -> str:
    pw = plain.encode("utf-8")
    hashed = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12))
    return hashed.decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def require_login():
    if not st.session_state.get("auth"):
        st.stop()


# =========================
# DB Setup
# =========================
def db_prepare():
    """
    Crea tablas mínimas si no existen.
    OJO: Supabase suele traer schema "public" por defecto.
    """
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""
            create table if not exists public.users (
                id bigserial primary key,
                username text unique not null,
                password_hash text not null,
                role text not null default 'read',
                created_at timestamptz not null default now()
            );
            """)

            cur.execute("""
            create table if not exists public.machines (
                id bigserial primary key,
                mcc text unique not null,
                brand text,
                model text,
                serial text,
                sector text,
                status text not null default 'activa',
                created_at timestamptz not null default now()
            );
            """)

            cur.execute("""
            create table if not exists public.maintenance (
                id bigserial primary key,
                machine_id bigint references public.machines(id) on delete set null,
                mcc text,
                type text not null default 'preventiva',
                status text not null default 'pendiente',
                scheduled_date date,
                executed_date date,
                technician text,
                detail text,
                created_at timestamptz not null default now()
            );
            """)

        conn.commit()


# =========================
# Auth DB ops
# =========================
def get_user_by_username(username: str):
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select id, username, password_hash, role from public.users where username = %s",
                (username.strip().lower(),)
            )
            return cur.fetchone()


def create_user(username: str, plain_password: str, role: str):
    username = username.strip().lower()
    pwd_hash = hash_password(plain_password)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "insert into public.users (username, password_hash, role) values (%s, %s, %s)",
                (username, pwd_hash, role)
            )
        conn.commit()


# =========================
# Machines DB ops
# =========================
def machines_list(search: str = ""):
    q = "select * from public.machines"
    params = ()
    if search.strip():
        q += " where mcc ilike %s or sector ilike %s or brand ilike %s or model ilike %s"
        s = f"%{search.strip()}%"
        params = (s, s, s, s)
    q += " order by mcc"
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(q, params)
            return cur.fetchall()


def machine_upsert(mcc: str, brand: str, model: str, serial: str, sector: str, status: str):
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                insert into public.machines (mcc, brand, model, serial, sector, status)
                values (%s, %s, %s, %s, %s, %s)
                on conflict (mcc) do update
                set brand = excluded.brand,
                    model = excluded.model,
                    serial = excluded.serial,
                    sector = excluded.sector,
                    status = excluded.status
            """, (mcc, brand, model, serial, sector, status))
        conn.commit()


def machine_get_by_mcc(mcc: str):
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("select * from public.machines where mcc = %s", (mcc,))
            return cur.fetchone()


# =========================
# Maintenance DB ops
# =========================
def maintenance_list(status_filter: str = "todas", search_mcc: str = ""):
    q = "select * from public.maintenance where 1=1"
    params = []

    if status_filter != "todas":
        q += " and status = %s"
        params.append(status_filter)

    if search_mcc.strip():
        q += " and (mcc ilike %s)"
        params.append(f"%{search_mcc.strip()}%")

    q += " order by coalesce(scheduled_date, executed_date) desc nulls last, id desc"

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(q, tuple(params))
            return cur.fetchall()


def maintenance_create(mcc: str, mtype: str, status: str, scheduled_date, executed_date, technician: str, detail: str):
    mach = machine_get_by_mcc(mcc)
    machine_id = mach["id"] if mach else None

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                insert into public.maintenance
                (machine_id, mcc, type, status, scheduled_date, executed_date, technician, detail)
                values (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (machine_id, mcc, mtype, status, scheduled_date, executed_date, technician, detail))
        conn.commit()


# =========================
# UI: Header
# =========================
st.title("🛠️ KR_TGM • Mantenciones e Historial")
st.caption("Registro de máquinas, mantenciones e historial (Supabase + Streamlit Cloud)")


# =========================
# Boot: prepare DB (con mensaje claro)
# =========================
try:
    db_prepare()
except Exception as e:
    st.error("No se pudo preparar la base de datos. Revisa DB_URL en Secrets.")
    st.info(f"Detalle técnico: {type(e).__name__}: {e}")
    st.stop()


# =========================
# Sidebar: Session
# =========================
with st.sidebar:
    st.subheader("Sesión")

    if st.session_state.get("auth"):
        st.success(f"Conectado: {st.session_state['username']} ({st.session_state['role']})")
        if st.button("Cerrar sesión", use_container_width=True):
            for k in ["auth", "user_id", "username", "role"]:
                st.session_state.pop(k, None)
            st.rerun()
    else:
        st.info("Inicia sesión para continuar")


# =========================
# Login
# =========================
if not st.session_state.get("auth"):
    c1, c2 = st.columns([1, 1])

    with c1:
        st.subheader("Iniciar sesión")
        username = st.text_input("Usuario", placeholder="cristian").strip().lower()
        password = st.text_input("Contraseña", type="password")

        if st.button("Entrar", use_container_width=True):
            u = get_user_by_username(username)
            if not u:
                st.error("Usuario no existe.")
            elif not verify_password(password, u["password_hash"]):
                st.error("Contraseña incorrecta.")
            else:
                st.session_state["auth"] = True
                st.session_state["user_id"] = u["id"]
                st.session_state["username"] = u["username"]
                st.session_state["role"] = u["role"]
                st.rerun()

    with c2:
        st.subheader("Crear usuario (solo admin setup)")
        st.caption("Para crear usuarios desde la app debes ingresar la SETUP_KEY.")
        setup_key_in = st.text_input("SETUP_KEY", type="password", help="Debe coincidir con st.secrets['SETUP_KEY']")
        new_user = st.text_input("Nuevo usuario", key="new_user").strip().lower()
        new_pass = st.text_input("Nueva contraseña", type="password", key="new_pass")
        new_role = st.selectbox("Rol", ["admin", "supervisor", "tecnico", "read"], index=3)

        if st.button("Crear usuario", use_container_width=True):
            expected = st.secrets.get("SETUP_KEY")
            if not expected:
                st.error("No existe SETUP_KEY en Secrets.")
            elif setup_key_in != expected:
                st.error("SETUP_KEY incorrecta.")
            elif not new_user or not new_pass:
                st.error("Completa usuario y contraseña.")
            else:
                try:
                    create_user(new_user, new_pass, new_role)
                    st.success("Usuario creado. Ahora puedes iniciar sesión.")
                except Exception as e:
                    st.error(f"No se pudo crear: {type(e).__name__}: {e}")

    st.stop()


# =========================
# Main App (requiere login)
# =========================
require_login()

tabs = st.tabs(["🎰 Máquinas", "🛠 Mantenciones", "📜 Historial"])

# ---- Tab Máquinas
with tabs[0]:
    st.subheader("Máquinas")

    left, right = st.columns([2, 1], vertical_alignment="top")

    with left:
        search = st.text_input("Buscar", placeholder="MCC, sector, marca, modelo...")
        rows = machines_list(search)
        df = pd.DataFrame(rows) if rows else pd.DataFrame(columns=["mcc", "brand", "model", "serial", "sector", "status"])
        st.dataframe(df, use_container_width=True, hide_index=True)

    with right:
        st.markdown("### Crear / Editar (por MCC)")
        role = st.session_state.get("role", "read")
        can_edit = role in ("admin", "supervisor")

        if not can_edit:
            st.info("Tu rol no permite editar máquinas.")
        else:
            mcc = st.text_input("MCC").strip()
            if st.button("Cargar datos por MCC"):
                if mcc:
                    m = machine_get_by_mcc(mcc)
                    if m:
                        st.session_state["m_form"] = m
                    else:
                        st.session_state["m_form"] = {"mcc": mcc, "brand": "", "model": "", "serial": "", "sector": "", "status": "activa"}

            m_form = st.session_state.get("m_form", {"mcc": "", "brand": "", "model": "", "serial": "", "sector": "", "status": "activa"})
            mcc2 = st.text_input("MCC (form)", value=m_form.get("mcc", ""), key="mcc_form").strip()
            brand = st.text_input("Marca", value=m_form.get("brand", "") or "")
            model = st.text_input("Modelo", value=m_form.get("model", "") or "")
            serial = st.text_input("Serie", value=m_form.get("serial", "") or "")
            sector = st.text_input("Sector", value=m_form.get("sector", "") or "")
            status = st.selectbox("Estado", ["activa", "fuera_servicio", "baja"], index=["activa","fuera_servicio","baja"].index(m_form.get("status","activa")))

            if st.button("Guardar máquina", use_container_width=True):
                if not mcc2:
                    st.error("MCC es obligatorio.")
                else:
                    try:
                        machine_upsert(mcc2, brand, model, serial, sector, status)
                        st.success("Guardado.")
                        st.session_state.pop("m_form", None)
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error: {type(e).__name__}: {e}")

# ---- Tab Mantenciones
with tabs[1]:
    st.subheader("Mantenciones")

    role = st.session_state.get("role", "read")
    can_write = role in ("admin", "supervisor", "tecnico")

    c1, c2 = st.columns([2, 1], vertical_alignment="top")

    with c1:
        colf1, colf2 = st.columns([1, 1])
        with colf1:
            status_filter = st.selectbox("Estado", ["todas", "pendiente", "en_proceso", "realizada", "cancelada"])
        with colf2:
            search_mcc = st.text_input("Filtrar por MCC", placeholder="10.123 / 32045 / etc...")

        mrows = maintenance_list(status_filter=status_filter, search_mcc=search_mcc)
        mdf = pd.DataFrame(mrows) if mrows else pd.DataFrame(columns=["mcc", "type", "status", "scheduled_date", "executed_date", "technician", "detail"])
        st.dataframe(mdf, use_container_width=True, hide_index=True)

    with c2:
        st.markdown("### Crear mantención")
        if not can_write:
            st.info("Tu rol no permite registrar mantenciones.")
        else:
            mcc = st.text_input("MCC", key="mt_mcc").strip()
            mtype = st.selectbox("Tipo", ["preventiva", "correctiva", "upgrade", "inspeccion"], index=0)
            mstatus = st.selectbox("Estado", ["pendiente", "en_proceso", "realizada", "cancelada"], index=0)
            scheduled = st.date_input("Fecha programada", value=dt.date.today())
            executed = st.date_input("Fecha ejecución", value=None)
            tech = st.text_input("Técnico", value=st.session_state.get("username", ""))
            detail = st.text_area("Detalle", height=120)

            if st.button("Guardar mantención", use_container_width=True):
                if not mcc:
                    st.error("MCC es obligatorio.")
                else:
                    try:
                        maintenance_create(
                            mcc=mcc,
                            mtype=mtype,
                            status=mstatus,
                            scheduled_date=scheduled,
                            executed_date=executed,
                            technician=tech,
                            detail=detail,
                        )
                        st.success("Mantención registrada.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error: {type(e).__name__}: {e}")

# ---- Tab Historial
with tabs[2]:
    st.subheader("Historial (últimas 200)")

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                select id, mcc, type, status, scheduled_date, executed_date, technician, created_at
                from public.maintenance
                order by created_at desc
                limit 200
            """)
            hist = cur.fetchall()

    hdf = pd.DataFrame(hist) if hist else pd.DataFrame()
    st.dataframe(hdf, use_container_width=True, hide_index=True)
