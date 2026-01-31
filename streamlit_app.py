# -*- coding: utf-8 -*-
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
    if "DB_URL" in st.secrets:
        return st.secrets["DB_URL"]
    env = os.getenv("DB_URL")
    if env:
        return env
    raise KeyError("DB_URL no está definido en Secrets (ni en variable de entorno).")


def connect():
    return psycopg.connect(get_db_url(), row_factory=dict_row, connect_timeout=10)


def hash_password(plain: str) -> str:
    hashed = bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12))
    return hashed.decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


# =========================
# Introspection helpers (evita UndefinedColumn)
# =========================
@st.cache_data(ttl=60, show_spinner=False)
def table_columns(schema: str, table: str) -> set[str]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select column_name
                from information_schema.columns
                where table_schema = %s and table_name = %s
                """,
                (schema, table),
            )
            return {r["column_name"] for r in cur.fetchall()}


def safe_select(schema: str, table: str, wanted: list[str], search: str,
                search_cols: list[str], order_candidates: list[str]):
    cols = table_columns(schema, table)

    select_cols = [c for c in wanted if c in cols]
    if not select_cols:
        # fallback: muestra algo sin romper
        select_cols = (["id"] if "id" in cols else []) + [c for c in sorted(cols) if c != "id"][:8]
        if not select_cols:
            return [], [], cols

    q = f"select {', '.join(select_cols)} from {schema}.{table}"
    params = []

    like_cols = [c for c in search_cols if c in cols]
    if search.strip() and like_cols:
        q += " where " + " or ".join([f"{c} ilike %s" for c in like_cols])
        s = f"%{search.strip()}%"
        params = [s] * len(like_cols)

    order_by = next((c for c in order_candidates if c in cols), select_cols[0])
    q += f" order by {order_by}"

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(q, tuple(params))
            rows = cur.fetchall()

    return rows, select_cols, cols


# =========================
# DB Setup (crea + agrega columnas clave)
# =========================
def db_prepare():
    with connect() as conn:
        with conn.cursor() as cur:
            # users
            cur.execute("""
            create table if not exists public.users (
                id bigserial primary key,
                username text unique not null,
                password_hash text not null,
                role text not null default 'read',
                created_at timestamptz not null default now()
            );
            """)

            # machines (mínimo)
            cur.execute("""
            create table if not exists public.machines (
                id bigserial primary key,
                created_at timestamptz not null default now()
            );
            """)

            # columnas operativas principales
            cur.execute("alter table public.machines add column if not exists id_maquina text;")
            cur.execute("alter table public.machines add column if not exists fabricante text;")
            cur.execute("alter table public.machines add column if not exists sector text;")
            cur.execute("alter table public.machines add column if not exists banco text;")

            # opcionales
            cur.execute("alter table public.machines add column if not exists modelo text;")
            cur.execute("alter table public.machines add column if not exists serie text;")
            cur.execute("alter table public.machines add column if not exists estado text not null default 'activa';")

            # unique por id_maquina (si usas ese ID como clave)
            try:
                cur.execute("create unique index if not exists machines_id_maquina_uidx on public.machines(id_maquina);")
            except Exception:
                pass

            # maintenance (mínimo)
            cur.execute("""
            create table if not exists public.maintenance (
                id bigserial primary key,
                created_at timestamptz not null default now()
            );
            """)

            # columnas estándar de mantención
            cur.execute("alter table public.maintenance add column if not exists id_maquina text;")
            cur.execute("alter table public.maintenance add column if not exists tipo text not null default 'preventiva';")
            cur.execute("alter table public.maintenance add column if not exists estado text not null default 'pendiente';")
            cur.execute("alter table public.maintenance add column if not exists fecha_programada date;")
            cur.execute("alter table public.maintenance add column if not exists fecha_ejecucion date;")
            cur.execute("alter table public.maintenance add column if not exists tecnico text;")
            cur.execute("alter table public.maintenance add column if not exists detalle text;")

        conn.commit()

    table_columns.clear()


# =========================
# Auth ops
# =========================
def get_user_by_username(username: str):
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select id, username, password_hash, role from public.users where username = %s",
                (username.strip().lower(),),
            )
            return cur.fetchone()


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


def ensure_bootstrap_admin():
    admin_user = (st.secrets.get("BOOTSTRAP_ADMIN_USER") or "").strip().lower()
    admin_pass = st.secrets.get("BOOTSTRAP_ADMIN_PASS") or ""
    force = str(st.secrets.get("BOOTSTRAP_FORCE", "false")).lower() in ("1", "true", "yes")

    if not admin_user or not admin_pass:
        return

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("select id from public.users where username = %s", (admin_user,))
            row = cur.fetchone()

    pwd_hash = hash_password(admin_pass)

    with connect() as conn:
        with conn.cursor() as cur:
            if row and force:
                cur.execute("""
                    update public.users
                    set password_hash = %s,
                        role = 'admin'
                    where username = %s
                """, (pwd_hash, admin_user))
            elif not row:
                cur.execute("""
                    insert into public.users (username, password_hash, role)
                    values (%s, %s, 'admin')
                """, (admin_user, pwd_hash))
        conn.commit()


# =========================
# Machines ops
# =========================
def machines_list(search: str = ""):
    wanted = ["id_maquina", "fabricante", "sector", "banco", "modelo", "serie", "estado", "created_at"]
    rows, shown, cols = safe_select(
        schema="public",
        table="machines",
        wanted=wanted,
        search=search,
        search_cols=["id_maquina", "fabricante", "sector", "banco", "modelo"],
        order_candidates=["id_maquina", "created_at", "id"],
    )
    return rows, shown, cols


def machine_get_by_id_maquina(id_maquina: str):
    cols = table_columns("public", "machines")
    if "id_maquina" not in cols:
        return None

    wanted = ["id_maquina", "fabricante", "sector", "banco", "modelo", "serie", "estado", "created_at"]
    select_cols = [c for c in wanted if c in cols]
    q = f"select {', '.join(select_cols)} from public.machines where id_maquina = %s"
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(q, (id_maquina,))
            return cur.fetchone()


def machine_upsert(id_maquina: str, fabricante: str, sector: str, banco: str, modelo: str, serie: str, estado: str):
    cols = table_columns("public", "machines")
    if "id_maquina" not in cols:
        raise RuntimeError("La tabla public.machines no tiene columna 'id_maquina'.")

    # asegura unique index
    with connect() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute("create unique index if not exists machines_id_maquina_uidx on public.machines(id_maquina);")
            except Exception:
                pass
        conn.commit()

    data = {
        "id_maquina": id_maquina,
        "fabricante": fabricante,
        "sector": sector,
        "banco": banco,
        "modelo": modelo,
        "serie": serie,
        "estado": estado,
    }

    insert_cols = [k for k in data.keys() if k in cols]
    insert_vals = [data[k] for k in insert_cols]
    set_cols = [c for c in insert_cols if c != "id_maquina"]
    set_clause = ", ".join([f"{c}=excluded.{c}" for c in set_cols]) if set_cols else ""

    q = f"""
        insert into public.machines ({", ".join(insert_cols)})
        values ({", ".join(["%s"] * len(insert_cols))})
        on conflict (id_maquina) do update
        set {set_clause}
    """
    if not set_cols:
        q = f"""
            insert into public.machines ({", ".join(insert_cols)})
            values ({", ".join(["%s"] * len(insert_cols))})
            on conflict (id_maquina) do nothing
        """

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(q, tuple(insert_vals))
        conn.commit()


# =========================
# Maintenance ops
# =========================
def maintenance_list(status_filter: str = "todas", search_id: str = ""):
    cols = table_columns("public", "maintenance")
    wanted = ["id", "id_maquina", "tipo", "estado", "fecha_programada", "fecha_ejecucion", "tecnico", "detalle", "created_at"]
    select_cols = [c for c in wanted if c in cols]
    if not select_cols:
        select_cols = (["id"] if "id" in cols else []) + [c for c in sorted(cols) if c != "id"][:8]

    q = f"select {', '.join(select_cols)} from public.maintenance where 1=1"
    params = []

    if status_filter != "todas" and "estado" in cols:
        q += " and estado = %s"
        params.append(status_filter)

    if search_id.strip() and "id_maquina" in cols:
        q += " and id_maquina ilike %s"
        params.append(f"%{search_id.strip()}%")

    order_by = "created_at" if "created_at" in cols else ("id" if "id" in cols else select_cols[0])
    q += f" order by {order_by} desc"

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(q, tuple(params))
            return cur.fetchall(), select_cols, cols


def maintenance_create(id_maquina: str, tipo: str, estado: str, fecha_programada, fecha_ejecucion, tecnico: str, detalle: str):
    cols = table_columns("public", "maintenance")
    data = {
        "id_maquina": id_maquina,
        "tipo": tipo,
        "estado": estado,
        "fecha_programada": fecha_programada,
        "fecha_ejecucion": fecha_ejecucion,
        "tecnico": tecnico,
        "detalle": detalle,
    }

    insert_cols = [k for k in data.keys() if k in cols]
    if not insert_cols:
        raise RuntimeError("La tabla public.maintenance no tiene columnas compatibles para insertar.")
    insert_vals = [data[k] for k in insert_cols]

    q = f"insert into public.maintenance ({', '.join(insert_cols)}) values ({', '.join(['%s'] * len(insert_cols))})"

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(q, tuple(insert_vals))
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
# Session helpers
# =========================
def logout():
    for k in ["auth", "user_id", "username", "role"]:
        st.session_state.pop(k, None)
    st.rerun()


# =========================
# Sidebar
# =========================
with st.sidebar:
    st.subheader("Sesión")
    if st.session_state.get("auth"):
        st.success(f"{st.session_state['username']} ({st.session_state['role']})")
        if st.button("Cerrar sesión", use_container_width=True):
            logout()
    else:
        st.info("Inicia sesión para continuar")


# =========================
# Login
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

# Claves ASCII (sin emojis) para evitar problemas de encoding/sintaxis
MENU = [
    ("machines", "🎰 Máquinas"),
    ("maintenance", "🛠 Mantenciones"),
    ("history", "📜 Historial"),
]
if role == "admin":
    MENU.append(("admin", "⚙️ Administración"))

label_by_key = {k: v for k, v in MENU}
keys = [k for k, _ in MENU]
labels = [v for _, v in MENU]

choice_label = st.sidebar.radio("Menú", labels)
page = next(k for k, v in MENU if v == choice_label)

# ---- Máquinas
if page == "machines":
    st.subheader("Máquinas")

    search = st.text_input("Buscar", placeholder="ID máquina, fabricante, sector, banco, modelo...")

    rows, shown, cols = machines_list(search)
    df = pd.DataFrame(rows) if rows else pd.DataFrame(columns=shown)
    st.dataframe(df, use_container_width=True, hide_index=True)

    if role == "admin":
        with st.expander("🔎 Diagnóstico tabla public.machines (solo admin)"):
            st.write("Columnas reales:", sorted(list(cols)))
            st.write("Columnas mostradas:", shown)

    st.markdown("---")
    st.markdown("### Crear / Editar máquina (por ID Máquina)")
    can_edit = role in ("admin", "supervisor")
    if not can_edit:
        st.info("Tu rol no permite editar máquinas.")
    else:
        idq = st.text_input("ID Máquina (ej: 32045)").strip()
        current = machine_get_by_id_maquina(idq) if idq else {}

        fabricante = st.text_input("Fabricante", value=(current.get("fabricante") or "") if current else "")
        sector = st.text_input("Sector", value=(current.get("sector") or "") if current else "")
        banco = st.text_input("Banco", value=(current.get("banco") or "") if current else "")
        modelo = st.text_input("Modelo", value=(current.get("modelo") or "") if current else "")
        serie = st.text_input("Serie", value=(current.get("serie") or "") if current else "")

        estado_opts = ["activa", "fuera_servicio", "baja"]
        current_estado = (current.get("estado") or "activa") if current else "activa"
        idx = estado_opts.index(current_estado) if current_estado in estado_opts else 0
        estado = st.selectbox("Estado", estado_opts, index=idx)

        if st.button("Guardar máquina", use_container_width=True):
            if not idq:
                st.error("ID Máquina es obligatorio.")
            else:
                try:
                    machine_upsert(idq, fabricante, sector, banco, modelo, serie, estado)
                    table_columns.clear()
                    st.success("Guardado.")
                    st.rerun()
                except Exception as e:
                    st.error(f"No se pudo guardar: {type(e).__name__}: {e}")

# ---- Mantenciones
elif page == "maintenance":
    st.subheader("Mantenciones")

    col1, col2 = st.columns([1, 1])
    with col1:
        status_filter = st.selectbox("Estado", ["todas", "pendiente", "en_proceso", "realizada", "cancelada"])
    with col2:
        search_id = st.text_input("Filtrar por ID Máquina", placeholder="32045 / 10.123 / etc...")

    mrows, shown, cols = maintenance_list(status_filter=status_filter, search_id=search_id)
    mdf = pd.DataFrame(mrows) if mrows else pd.DataFrame(columns=shown)
    st.dataframe(mdf, use_container_width=True, hide_index=True)

    if role == "admin":
        with st.expander("🔎 Diagnóstico tabla public.maintenance (solo admin)"):
            st.write("Columnas reales:", sorted(list(cols)))
            st.write("Columnas mostradas:", shown)

    st.markdown("---")
    st.markdown("### Crear mantención")
    can_write = role in ("admin", "supervisor", "tecnico")
    if not can_write:
        st.info("Tu rol no permite registrar mantenciones.")
    else:
        id_maquina = st.text_input("ID Máquina", key="mt_id").strip()
        tipo = st.selectbox("Tipo", ["preventiva", "correctiva", "upgrade", "inspeccion"], index=0)
        estado = st.selectbox("Estado", ["pendiente", "en_proceso", "realizada", "cancelada"], index=0)
        fecha_prog = st.date_input("Fecha programada", value=dt.date.today())

        # opcional: permitir vacío
        fecha_ejec = st.date_input("Fecha ejecución", value=None)

        tecnico = st.text_input("Técnico", value=st.session_state.get("username", ""))
        detalle = st.text_area("Detalle", height=120)

        if st.button("Guardar mantención", use_container_width=True):
            if not id_maquina:
                st.error("ID Máquina es obligatorio.")
            else:
                try:
                    maintenance_create(id_maquina, tipo, estado, fecha_prog, fecha_ejec, tecnico, detalle)
                    table_columns.clear()
                    st.success("Mantención registrada.")
                    st.rerun()
                except Exception as e:
                    st.error(f"No se pudo guardar: {type(e).__name__}: {e}")

# ---- Historial
elif page == "history":
    st.subheader("Historial")
    mrows, shown, _ = maintenance_list(status_filter="todas", search_id="")
    hdf = pd.DataFrame(mrows) if mrows else pd.DataFrame(columns=shown)
    st.dataframe(hdf.head(300), use_container_width=True, hide_index=True)

# ---- Administración
elif page == "admin":
    st.subheader("Administración • Usuarios (solo admin)")

    st.markdown("### Crear usuario")
    new_user = st.text_input("Nuevo usuario").strip().lower()
    new_pass = st.text_input("Nueva contraseña", type="password")
    new_role = st.selectbox("Rol", ["admin", "supervisor", "tecnico", "read"], index=3)

    if st.button("Crear usuario", use_container_width=True):
        if not new_user or not new_pass:
            st.error("Completa usuario y contraseña.")
        else:
            try:
                create_user(new_user, new_pass, new_role)
                st.success("Usuario creado.")
            except Exception as e:
                st.error(f"No se pudo crear: {type(e).__name__}: {e}")

    st.markdown("---")
    st.markdown("### Usuarios existentes")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, username, role, created_at from public.users order by id")
            users = cur.fetchall()

    udf = pd.DataFrame(users) if users else pd.DataFrame()
    st.dataframe(udf, use_container_width=True, hide_index=True)
