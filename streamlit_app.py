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
    raise KeyError("DB_URL no está definido en Secrets (ni env var).")


def connect():
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


def safe_select(schema: str, table: str, wanted: list[str], search: str, search_cols: list[str], order_candidates: list[str]):
    cols = table_columns(schema, table)

    # Selecciona solo columnas existentes
    select_cols = [c for c in wanted if c in cols]
    if not select_cols:
        # fallback: muestra algo, sin reventar
        select_cols = (["id"] if "id" in cols else []) + [c for c in sorted(cols) if c != "id"][:6]
        if not select_cols:
            return [], [], cols

    q = f"select {', '.join(select_cols)} from {schema}.{table}"
    params = []

    # Filtros solo por columnas existentes
    like_cols = [c for c in search_cols if c in cols]
    if search.strip() and like_cols:
        q += " where " + " or ".join([f"{c} ilike %s" for c in like_cols])
        s = f"%{search.strip()}%"
        params = [s] * len(like_cols)

    # ORDER BY seguro
    order_by = next((c for c in order_candidates if c in cols), select_cols[0])
    q += f" order by {order_by}"

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(q, tuple(params))
            rows = cur.fetchall()

    return rows, select_cols, cols


# =========================
# DB Setup (mínimo + no rompe si ya tienes tablas)
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

            # ===== columnas clave para tu operación =====
            # OJO: "id_maquina" es tu ID operativo (ej: 32045), distinto del id bigserial interno
            cur.execute("alter table public.machines add column if not exists id_maquina text;")
            cur.execute("alter table public.machines add column if not exists fabricante text;")
            cur.execute("alter table public.machines add column if not exists sector text;")
            cur.execute("alter table public.machines add column if not exists banco text;")

            # Opcionales
            cur.execute("alter table public.machines add column if not exists modelo text;")
            cur.execute("alter table public.machines add column if not exists serie text;")
            cur.execute("alter table public.machines add column if not exists estado text not null default 'activa';")

            # índice único por id_maquina (si aplica)
            try:
                cur.execute("create unique index if not exists machines_id_maquina_uidx on public.machines(id_maquina);")
            except Exception:
                pass

        conn.commit()

    table_columns.clear()

    # Limpia cache de columnas por si hubo cambios
    table_columns.clear()


# =========================
# Auth DB ops
# =========================
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
    """
    Bootstrap admin seguro:
    - Crea si no existe
    - Si BOOTSTRAP_FORCE=true, resetea password aunque ya exista
    """
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
# Machines ops (SAFE)
# =========================
def machines_list(search: str = ""):
    wanted = ["id_maquina", "fabricante", "sector", "banco", "modelo", "serie", "estado", "created_at"]
    rows, shown, cols = safe_select(
        schema="public",
        table="machines",
        wanted=wanted,
        search=search,
        search_cols=["id_maquina", "fabricante", "sector", "banco", "modelo"],
        order_candidates=["id_maquina", "created_at"],
    )
    return rows, shown, cols

def machine_upsert(mcc: str, brand: str, model: str, serial: str, sector: str, status: str):
    """
    Upsert SOLO si existen las columnas. Si tu tabla no tiene esas columnas,
    guardará únicamente lo que exista.
    """
    cols = table_columns("public", "machines")

    # Asegura que exista mcc para poder hacer upsert por mcc.
    # Si no existe, no podemos upsert; hacemos insert simple.
    if "mcc" not in cols:
        raise RuntimeError("La tabla public.machines no tiene columna 'mcc'. Agrega 'mcc' o dime tus nombres reales.")

    # Asegura índice unique para ON CONFLICT (si no existe, lo crea best-effort)
    with connect() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute("create unique index if not exists machines_mcc_uidx on public.machines(mcc);")
            except Exception:
                pass
        conn.commit()

    data = {
        "mcc": mcc,
        "brand": brand,
        "model": model,
        "serial": serial,
        "sector": sector,
        "status": status,
    }

    # Filtra columnas que existan realmente
    insert_cols = [k for k in data.keys() if k in cols]
    if not insert_cols:
        raise RuntimeError("No hay columnas compatibles para guardar en public.machines (revisa esquema).")

    insert_vals = [data[k] for k in insert_cols]

    set_cols = [c for c in insert_cols if c != "mcc"]
    set_clause = ", ".join([f"{c}=excluded.{c}" for c in set_cols]) if set_cols else ""

    q = f"""
        insert into public.machines ({", ".join(insert_cols)})
        values ({", ".join(["%s"] * len(insert_cols))})
        on conflict (mcc) do update
        set {set_clause}
    """
    # Si no hay nada para actualizar, hacemos DO NOTHING
    if not set_cols:
        q = f"""
            insert into public.machines ({", ".join(insert_cols)})
            values ({", ".join(["%s"] * len(insert_cols))})
            on conflict (mcc) do nothing
        """

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(q, tuple(insert_vals))
        conn.commit()


def machine_get_by_mcc(mcc: str):
    cols = table_columns("public", "machines")
    if "mcc" not in cols:
        return None

    wanted = ["id", "mcc", "brand", "model", "serial", "sector", "status", "created_at"]
    select_cols = [c for c in wanted if c in cols]
    if not select_cols:
        select_cols = ["mcc"]  # mínimo

    q = f"select {', '.join(select_cols)} from public.machines where mcc = %s"
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(q, (mcc,))
            return cur.fetchone()


# =========================
# Maintenance ops (SAFE)
# =========================
def maintenance_list(status_filter: str = "todas", search_mcc: str = ""):
    cols = table_columns("public", "maintenance")

    wanted = ["id", "machine_id", "mcc", "type", "status", "scheduled_date", "executed_date", "technician", "detail", "created_at"]
    select_cols = [c for c in wanted if c in cols]
    if not select_cols:
        select_cols = (["id"] if "id" in cols else []) + [c for c in sorted(cols) if c != "id"][:8]

    q = f"select {', '.join(select_cols)} from public.maintenance where 1=1"
    params = []

    if status_filter != "todas" and "status" in cols:
        q += " and status = %s"
        params.append(status_filter)

    if search_mcc.strip() and "mcc" in cols:
        q += " and mcc ilike %s"
        params.append(f"%{search_mcc.strip()}%")

    order_by = "created_at" if "created_at" in cols else ("id" if "id" in cols else select_cols[0])
    q += f" order by {order_by} desc"

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(q, tuple(params))
            return cur.fetchall(), select_cols, cols


def maintenance_create(mcc: str, mtype: str, status: str, scheduled_date, executed_date, technician: str, detail: str):
    cols = table_columns("public", "maintenance")

    data = {
        "mcc": mcc,
        "type": mtype,
        "status": status,
        "scheduled_date": scheduled_date,
        "executed_date": executed_date,
        "technician": technician,
        "detail": detail,
    }

    insert_cols = [k for k in data.keys() if k in cols]
    if not insert_cols:
        raise RuntimeError("La tabla public.maintenance no tiene columnas compatibles para insertar.")

    insert_vals = [data[k] for k in insert_cols]

    q = f"""
        insert into public.maintenance ({", ".join(insert_cols)})
        values ({", ".join(["%s"] * len(insert_cols))})
    """

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
# Login Screen
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

    search = st.text_input("Buscar", placeholder="MCC, sector, marca, modelo...")

    rows, shown, cols = machines_list(search)
    df = pd.DataFrame(rows) if rows else pd.DataFrame(columns=shown)

    st.dataframe(df, use_container_width=True, hide_index=True)

    if role == "admin":
        with st.expander("🔎 Diagnóstico tabla public.machines (solo admin)"):
            st.write("Columnas reales:", sorted(list(cols)))
            st.write("Columnas mostradas:", shown)

    st.markdown("---")
    st.markdown("### Crear / Editar (por MCC)")
    can_edit = role in ("admin", "supervisor")
    if not can_edit:
        st.info("Tu rol no permite editar máquinas.")
    else:
        mcc = st.text_input("MCC").strip()
        if st.button("Cargar datos por MCC"):
            if mcc:
                m = machine_get_by_mcc(mcc)
                st.session_state["m_form"] = m if m else {"mcc": mcc}

        m_form = st.session_state.get("m_form", {"mcc": ""})
        mcc2 = st.text_input("MCC (form)", value=m_form.get("mcc", "") or "", key="mcc_form").strip()

        # Campos opcionales: se guardan solo si existen en tu tabla
        brand = st.text_input("Marca (si existe)", value=m_form.get("brand", "") or "")
        model = st.text_input("Modelo (si existe)", value=m_form.get("model", "") or "")
        serial = st.text_input("Serie (si existe)", value=m_form.get("serial", "") or "")
        sector = st.text_input("Sector (si existe)", value=m_form.get("sector", "") or "")
        status = st.text_input("Status (si existe)", value=m_form.get("status", "") or "activa")

        if st.button("Guardar máquina", use_container_width=True):
            if not mcc2:
                st.error("MCC es obligatorio.")
            else:
                try:
                    machine_upsert(mcc2, brand, model, serial, sector, status)
                    st.success("Guardado.")
                    st.session_state.pop("m_form", None)
                    table_columns.clear()
                    st.rerun()
                except Exception as e:
                    st.error(f"No se pudo guardar: {type(e).__name__}: {e}")


# ---- Mantenciones
elif page == "🛠 Mantenciones":
    st.subheader("Mantenciones")

    colf1, colf2 = st.columns([1, 1])
    with colf1:
        status_filter = st.selectbox("Estado", ["todas", "pendiente", "en_proceso", "realizada", "cancelada"])
    with colf2:
        search_mcc = st.text_input("Filtrar por MCC", placeholder="10.123 / 32045 / etc...")

    mrows, shown, cols = maintenance_list(status_filter=status_filter, search_mcc=search_mcc)
    mdf = pd.DataFrame(mrows) if mrows else pd.DataFrame(columns=shown)
    st.dataframe(mdf, use_container_width=True, hide_index=True)

    if role == "admin":
        with st.expander("🔎 Diagnóstico tabla public.maintenance (solo admin)"):
            st.write("Columnas reales:", sorted(list(cols)))
            st.write("Columnas mostradas:", shown)

    st.markdown("---")
st.markdown("### Crear / Editar máquina (por ID Máquina)")
can_edit = role in ("admin", "supervisor")
if not can_edit:
    st.info("Tu rol no permite editar máquinas.")
else:
    cols = table_columns("public", "machines")

    idq = st.text_input("ID Máquina (ej: 32045)").strip()

    # Cargar por id_maquina si existe columna
    current = {}
    if idq and "id_maquina" in cols:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute("select * from public.machines where id_maquina = %s", (idq,))
                current = cur.fetchone() or {}

    fabricante = st.text_input("Fabricante", value=current.get("fabricante", "") or "")
    sector = st.text_input("Sector", value=current.get("sector", "") or "")
    banco = st.text_input("Banco", value=current.get("banco", "") or "")
    modelo = st.text_input("Modelo", value=current.get("modelo", "") or "")
    serie = st.text_input("Serie", value=current.get("serie", "") or "")
    estado = st.selectbox("Estado", ["activa", "fuera_servicio", "baja"],
                          index=["activa","fuera_servicio","baja"].index((current.get("estado") or "activa")))

    if st.button("Guardar", use_container_width=True):
        if not idq:
            st.error("ID Máquina es obligatorio.")
        else:
            # Inserta/actualiza según columna id_maquina
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("create unique index if not exists machines_id_maquina_uidx on public.machines(id_maquina);")
                    cur.execute("""
                        insert into public.machines (id_maquina, fabricante, sector, banco, modelo, serie, estado)
                        values (%s,%s,%s,%s,%s,%s,%s)
                        on conflict (id_maquina) do update
                        set fabricante=excluded.fabricante,
                            sector=excluded.sector,
                            banco=excluded.banco,
                            modelo=excluded.modelo,
                            serie=excluded.serie,
                            estado=excluded.estado
                    """, (idq, fabricante, sector, banco, modelo, serie, estado))
                conn.commit()

            table_columns.clear()
            st.success("Guardado.")
            st.rerun()

# ---- Historial
elif page == "📜 Historial":
    st.subheader("Historial")

    # reutiliza mantenimiento (últimos registros)
    mrows, shown, _ = maintenance_list(status_filter="todas", search_mcc="")
    hdf = pd.DataFrame(mrows) if mrows else pd.DataFrame(columns=shown)
    st.dataframe(hdf.head(200), use_container_width=True, hide_index=True)


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
