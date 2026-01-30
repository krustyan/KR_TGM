import os
import datetime as dt

import streamlit as st
import pandas as pd
import bcrypt
import psycopg
from psycopg.rows import dict_row

st.set_page_config(page_title="KR_TGM • Mantenciones e Historial", layout="wide")


# =========================
# DB / Secrets
# =========================
def get_db_url() -> str:
    # Streamlit Cloud: st.secrets
    if "DB_URL" in st.secrets:
        return st.secrets["DB_URL"]
    # Local dev fallback
    env = os.getenv("DB_URL")
    if env:
        return env
    raise KeyError("DB_URL no está definido en Secrets (ni env var).")


def connect():
    # row_factory=dict_row => fetchall/fetchone entregan dicts
    return psycopg.connect(get_db_url(), row_factory=dict_row, connect_timeout=8)


def hash_password(plain: str) -> str:
    hashed = bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12))
    return hashed.decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


# =========================
# DB Setup
# =========================
def db_prepare():
    with connect() as conn:
        with conn.cursor() as cur:
            # --- users (ok) ---
            cur.execute("""
            create table if not exists public.users (
                id bigserial primary key,
                username text unique not null,
                password_hash text not null,
                role text not null default 'read',
                created_at timestamptz not null default now()
            );
            """)

            # --- machines: crear si no existe ---
            cur.execute("""
            create table if not exists public.machines (
                id bigserial primary key,
                mcc text unique,
                created_at timestamptz not null default now()
            );
            """)

            # --- maintenance: crear si no existe ---
            cur.execute("""
            create table if not exists public.maintenance (
                id bigserial primary key,
                machine_id bigint,
                mcc text,
                type text,
                status text,
                scheduled_date date,
                executed_date date,
                technician text,
                detail text,
                created_at timestamptz not null default now()
            );
            """)

            # ===== MIGRACIONES (add column if missing) =====
            # Machines
            cur.execute("alter table public.machines add column if not exists brand text;")
            cur.execute("alter table public.machines add column if not exists model text;")
            cur.execute("alter table public.machines add column if not exists serial text;")
            cur.execute("alter table public.machines add column if not exists sector text;")
            cur.execute("alter table public.machines add column if not exists status text not null default 'activa';")

            # Ensure mcc exists + unique (si no existe, la agrega)
            cur.execute("alter table public.machines add column if not exists mcc text;")
            # Índice unique (si ya existe, no pasa nada)
            cur.execute("create unique index if not exists machines_mcc_uidx on public.machines(mcc);")

            # Maintenance
            cur.execute("alter table public.maintenance add column if not exists machine_id bigint;")
            cur.execute("alter table public.maintenance add column if not exists mcc text;")
            cur.execute("alter table public.maintenance add column if not exists type text not null default 'preventiva';")
            cur.execute("alter table public.maintenance add column if not exists status text not null default 'pendiente';")
            cur.execute("alter table public.maintenance add column if not exists scheduled_date date;")
            cur.execute("alter table public.maintenance add column if not exists executed_date date;")
            cur.execute("alter table public.maintenance add column if not exists technician text;")
            cur.execute("alter table public.maintenance add column if not exists detail text;")
            cur.execute("alter table public.maintenance add column if not exists created_at timestamptz not null default now();")

            # FK (solo si puedes; si ya existe, fallará, así que lo hacemos “best effort”)
            try:
                cur.execute("""
                    alter table public.maintenance
                    add constraint maintenance_machine_fk
                    foreign key (machine_id) references public.machines(id)
                    on delete set null
                """)
            except Exception:
                pass

        conn.commit()



def users_count() -> int:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("select count(*) as c from public.users")
            return int(cur.fetchone()["c"])


def create_user(username: str, plain_password: str, role: str):
    username = username.strip().lower()
    pwd_hash = hash_password(plain_password)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "insert into public.users (username, password_hash, role) values (%s, %s, %s)",
                (username, pwd_hash, role),
            )
        conn.commit()


def get_user_by_username(username: str):
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select id, username, password_hash, role from public.users where username = %s",
                (username.strip().lower(),),
            )
            return cur.fetchone()

def ensure_bootstrap_admin():
    admin_user = (st.secrets.get("BOOTSTRAP_ADMIN_USER") or "").strip().lower()
    admin_pass = st.secrets.get("BOOTSTRAP_ADMIN_PASS") or ""
    force = str(st.secrets.get("BOOTSTRAP_FORCE", "false")).lower() in ("1", "true", "yes")

    # si no hay bootstrap configurado, no hacemos nada
    if not admin_user or not admin_pass:
        return

    # buscamos usuario
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("select id from public.users where username = %s", (admin_user,))
            row = cur.fetchone()

    pwd_hash = hash_password(admin_pass)

    with connect() as conn:
        with conn.cursor() as cur:
            if row and force:
                # fuerza reset de password + rol admin
                cur.execute("""
                    update public.users
                    set password_hash = %s,
                        role = 'admin'
                    where username = %s
                """, (pwd_hash, admin_user))
            elif not row:
                # crea si no existe
                cur.execute("""
                    insert into public.users (username, password_hash, role)
                    values (%s, %s, 'admin')
                """, (admin_user, pwd_hash))
        conn.commit()
# =========================
# Machines
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
# Maintenance
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
# Boot
# =========================
st.title("🛠️ KR_TGM • Mantenciones e Historial")
st.caption("Registro de máquinas, mantenciones e historial (Supabase + Streamlit Cloud)")

try:
    db_prepare()
    ensure_bootstrap_admin()
except Exception as e:
    st.error("No se pudo preparar la base de datos. Revisa DB_URL en Secrets.")
    st.info(f"Detalle técnico: {type(e).__name__}: {e}")
    st.stop()


# =========================
# Auth
# =========================
def logout():
    for k in ["auth", "user_id", "username", "role"]:
        st.session_state.pop(k, None)
    st.rerun()


with st.sidebar:
    st.subheader("Sesión")
    if st.session_state.get("auth"):
        st.success(f"{st.session_state['username']} ({st.session_state['role']})")
        if st.button("Cerrar sesión", use_container_width=True):
            logout()
    else:
        st.info("Inicia sesión para continuar")


# =========================
# Login Screen (solo login)
# =========================
if not st.session_state.get("auth"):
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

    st.stop()


# =========================
# Main App
# =========================
role = st.session_state.get("role", "read")

pages = ["🎰 Máquinas", "🛠 Mantenciones", "📜 Historial"]
if role == "admin":
    pages.append("⚙️ Administración")

page = st.sidebar.radio("Menú", pages)

# ---- Máquinas
if page == "🎰 Máquinas":
    st.subheader("Máquinas")
    left, right = st.columns([2, 1], vertical_alignment="top")

    with left:
        search = st.text_input("Buscar", placeholder="MCC, sector, marca, modelo...")
        rows = machines_list(search)
        df = pd.DataFrame(rows) if rows else pd.DataFrame(columns=["mcc", "brand", "model", "serial", "sector", "status"])
        st.dataframe(df, use_container_width=True, hide_index=True)

    with right:
        st.markdown("### Crear / Editar (por MCC)")
        can_edit = role in ("admin", "supervisor")
        if not can_edit:
            st.info("Tu rol no permite editar máquinas.")
        else:
            mcc = st.text_input("MCC").strip()
            if st.button("Cargar datos por MCC"):
                if mcc:
                    m = machine_get_by_mcc(mcc)
                    st.session_state["m_form"] = m if m else {"mcc": mcc, "brand": "", "model": "", "serial": "", "sector": "", "status": "activa"}

            m_form = st.session_state.get("m_form", {"mcc": "", "brand": "", "model": "", "serial": "", "sector": "", "status": "activa"})
            mcc2 = st.text_input("MCC (form)", value=m_form.get("mcc", ""), key="mcc_form").strip()
            brand = st.text_input("Marca", value=m_form.get("brand", "") or "")
            model = st.text_input("Modelo", value=m_form.get("model", "") or "")
            serial = st.text_input("Serie", value=m_form.get("serial", "") or "")
            sector = st.text_input("Sector", value=m_form.get("sector", "") or "")
            status = st.selectbox("Estado", ["activa", "fuera_servicio", "baja"],
                                  index=["activa", "fuera_servicio", "baja"].index(m_form.get("status", "activa")))

            if st.button("Guardar máquina", use_container_width=True):
                if not mcc2:
                    st.error("MCC es obligatorio.")
                else:
                    machine_upsert(mcc2, brand, model, serial, sector, status)
                    st.success("Guardado.")
                    st.session_state.pop("m_form", None)
                    st.rerun()

# ---- Mantenciones
elif page == "🛠 Mantenciones":
    st.subheader("Mantenciones")
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
                    maintenance_create(mcc, mtype, mstatus, scheduled, executed, tech, detail)
                    st.success("Mantención registrada.")
                    st.rerun()

# ---- Historial
elif page == "📜 Historial":
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

# ---- Administración (solo admin)
elif page == "⚙️ Administración":
    st.subheader("Administración • Usuarios (solo admin)")

    st.markdown("### Crear usuario")
    new_user = st.text_input("Nuevo usuario").strip().lower()
    new_pass = st.text_input("Nueva contraseña", type="password")
    new_role = st.selectbox("Rol", ["admin", "supervisor", "tecnico", "read"], index=3)

    if st.button("Crear usuario", use_container_width=True):
        if not new_user or not new_pass:
            st.error("Completa usuario y contraseña.")
        else:
            create_user(new_user, new_pass, new_role)
            st.success("Usuario creado.")

    st.markdown("---")
    st.markdown("### Usuarios existentes")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, username, role, created_at from public.users order by id")
            users = cur.fetchall()

    udf = pd.DataFrame(users) if users else pd.DataFrame()
    st.dataframe(udf, use_container_width=True, hide_index=True)
