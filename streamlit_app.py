import os
import re
import hmac
import hashlib
import binascii
from datetime import date

import streamlit as st
import psycopg
from psycopg.rows import dict_row


# ----------------------------
# STREAMLIT CONFIG
# ----------------------------
st.set_page_config(
    page_title="KR_TGM • Mantenciones",
    page_icon="🛠️",
    layout="wide",
)
st.set_option("client.showErrorDetails", False)

CUSTOM_CSS = """
<style>
section[data-testid="stSidebar"] { padding-top: 0.5rem; }
div.stButton > button { border-radius: 10px; padding: 0.55rem 0.9rem; }
.kr-card { border: 1px solid rgba(255,255,255,0.12); border-radius: 14px; padding: 14px; background: rgba(255,255,255,0.03); }
.kr-title { font-size: 1.4rem; font-weight: 700; margin: 0; }
.kr-sub { opacity: 0.75; margin-top: 0.25rem; }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ----------------------------
# DB URL
# ----------------------------
def get_db_url() -> str:
    if "DB_URL" in st.secrets:
        return st.secrets["DB_URL"]
    env = os.getenv("DB_URL") or os.getenv("DATABASE_URL")
    if env:
        return env
    raise RuntimeError("No se encontró DB_URL en st.secrets ni en variables de entorno.")


DB_URL = get_db_url()


# ----------------------------
# DB CONNECTION (psycopg v3)
# ----------------------------
def db_conn():
    # Supabase generalmente requiere SSL
    return psycopg.connect(DB_URL, sslmode="require", row_factory=dict_row)


def run_exec(sql: str, params=None):
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
        conn.commit()


def run_fetchall(sql: str, params=None):
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()


def run_fetchone(sql: str, params=None):
    rows = run_fetchall(sql, params)
    return rows[0] if rows else None


# ----------------------------
# PASSWORD HASH (PBKDF2)
# ----------------------------
def hash_password(password: str, salt: bytes = None) -> str:
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return f"pbkdf2_sha256$120000${binascii.hexlify(salt).decode()}${binascii.hexlify(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, dk_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = binascii.unhexlify(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iters))
        return hmac.compare_digest(binascii.hexlify(dk).decode(), dk_hex)
    except Exception:
        return False


# ----------------------------
# INIT DB
# ----------------------------
def init_db():
    """
    Crea tablas si no existen.
    IMPORTANTE: id_maquina se define como INTEGER para coincidir con tu DB actual.
    Si ya existen tablas, esto no las altera (IF NOT EXISTS).
    """
    try:
        run_exec("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        """)

        run_exec("""
        CREATE TABLE IF NOT EXISTS machines (
            id_maquina INTEGER PRIMARY KEY,
            fabricante TEXT NOT NULL,
            sector TEXT NOT NULL,
            banco TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        """)

        run_exec("""
        CREATE TABLE IF NOT EXISTS mantenciones (
            id SERIAL PRIMARY KEY,
            id_maquina INTEGER NOT NULL,
            tipo TEXT NOT NULL,
            descripcion TEXT NOT NULL,
            fecha DATE NOT NULL,
            realizado_por TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT fk_mantenciones_machine
                FOREIGN KEY (id_maquina)
                REFERENCES machines(id_maquina)
                ON UPDATE CASCADE
                ON DELETE RESTRICT
        );
        """)

        # Seed admin si no existe ninguno
        existing_admin = run_fetchone("SELECT id FROM users WHERE is_admin = TRUE LIMIT 1;")
        if not existing_admin:
            run_exec(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (%s,%s,TRUE) ON CONFLICT (username) DO NOTHING;",
                ("admin", hash_password("Admin1234!"))
            )

    except Exception as e:
        st.warning("No pude ejecutar CREATE TABLE. Si las tablas ya existen, puedes ignorarlo. Detalle:")
        st.exception(e)


init_db()


# ----------------------------
# AUTH
# ----------------------------
def is_logged_in() -> bool:
    return bool(st.session_state.get("user"))


def current_user():
    return st.session_state.get("user")


def require_login():
    if not is_logged_in():
        st.warning("Debes iniciar sesión.")
        st.stop()


def require_admin():
    require_login()
    if not current_user().get("is_admin"):
        st.error("Acceso solo para administradores.")
        st.stop()


def login(username: str, password: str) -> bool:
    user = run_fetchone(
        "SELECT id, username, password_hash, is_admin FROM users WHERE username = %s;",
        (username,)
    )
    if not user:
        return False
    if not verify_password(password, user["password_hash"]):
        return False
    st.session_state["user"] = {"id": user["id"], "username": user["username"], "is_admin": user["is_admin"]}
    return True


def logout():
    st.session_state["user"] = None


# ----------------------------
# HELPERS
# ----------------------------
def get_all_machines():
    return run_fetchall("""
        SELECT id_maquina, fabricante, sector, banco
        FROM machines
        ORDER BY id_maquina;
    """)


def machine_exists(id_maquina: int) -> bool:
    row = run_fetchone("SELECT id_maquina FROM machines WHERE id_maquina = %s;", (id_maquina,))
    return bool(row)


def safe_int(value, default=None):
    try:
        return int(value)
    except Exception:
        return default


# ----------------------------
# UI: LOGIN PAGE
# ----------------------------
def render_login():
    st.markdown('<div class="kr-card">', unsafe_allow_html=True)
    st.markdown('<p class="kr-title">🔐 KR_TGM • Login</p>', unsafe_allow_html=True)
    st.markdown('<p class="kr-sub">Ingresa tus credenciales para continuar.</p>', unsafe_allow_html=True)

    c1, c2, c3 = st.columns([1, 1, 2])
    with c1:
        username = st.text_input("Usuario", key="login_user")
    with c2:
        password = st.text_input("Contraseña", type="password", key="login_pass")
    with c3:
        st.write("")
        st.write("")
        if st.button("Ingresar", use_container_width=True):
            if not username or not password:
                st.error("Completa usuario y contraseña.")
            else:
                ok = login(username.strip(), password)
                if ok:
                    st.success("Sesión iniciada.")
                    st.rerun()
                else:
                    st.error("Usuario o contraseña incorrectos.")

    st.info("Si es primera vez: usuario **admin** / clave **Admin1234!** (cámbiala apenas entres).")
    st.markdown("</div>", unsafe_allow_html=True)


# ----------------------------
# PAGES
# ----------------------------
def page_maquinas():
    require_login()

    st.markdown('<div class="kr-card">', unsafe_allow_html=True)
    st.markdown('<p class="kr-title">🎰 Máquinas</p>', unsafe_allow_html=True)
    st.markdown('<p class="kr-sub">Gestiona id_maquina (numérico), fabricante, sector y banco.</p>', unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["📋 Listado / Editar", "➕ Crear"])

    with tab1:
        machines = get_all_machines()
        if not machines:
            st.warning("No hay máquinas registradas.")
            return

        labels = [f'{m["id_maquina"]} • {m["fabricante"]} • {m["sector"]} • {m["banco"]}' for m in machines]
        idx_map = {labels[i]: machines[i] for i in range(len(machines))}
        sel = st.selectbox("Selecciona una máquina (buscable)", labels)
        m = idx_map[sel]

        colA, colB, colC, colD = st.columns(4)
        with colA:
            st.number_input("id_maquina (PK)", value=int(m["id_maquina"]), step=1, disabled=True)
        with colB:
            fabricante = st.text_input("fabricante", value=m["fabricante"])
        with colC:
            sector = st.text_input("sector", value=m["sector"])
        with colD:
            banco = st.text_input("banco", value=m["banco"])

        c1, c2, c3 = st.columns([1, 1, 2])
        with c1:
            if st.button("Guardar cambios", use_container_width=True):
                try:
                    run_exec("""
                        UPDATE machines
                        SET fabricante=%s, sector=%s, banco=%s
                        WHERE id_maquina=%s
                    """, (fabricante.strip(), sector.strip(), banco.strip(), int(m["id_maquina"])))
                    st.success("Máquina actualizada.")
                    st.rerun()
                except Exception as e:
                    st.error("No se pudo actualizar.")
                    st.exception(e)

        with c2:
            if st.button("Eliminar máquina", use_container_width=True):
                try:
                    run_exec("DELETE FROM machines WHERE id_maquina=%s;", (int(m["id_maquina"]),))
                    st.success("Máquina eliminada.")
                    st.rerun()
                except Exception as e:
                    st.error("No se pudo eliminar (puede tener mantenciones asociadas).")
                    st.exception(e)

        with c3:
            st.caption("Nota: si la máquina tiene mantenciones, no se eliminará (FK).")

        st.divider()
        st.dataframe(machines, use_container_width=True, hide_index=True)

    with tab2:
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            new_id = st.number_input("Nuevo id_maquina", step=1)
        with col2:
            new_fab = st.text_input("fabricante", placeholder="IGT / Novomatic / etc.")
        with col3:
            new_sector = st.text_input("sector", placeholder="Ej: Terraza / Sala Principal")
        with col4:
            new_banco = st.text_input("banco", placeholder="Ej: Banco A / King Kong Cash")

        if st.button("Crear máquina", use_container_width=True):
            nid = safe_int(new_id)
            if nid is None or not new_fab.strip() or not new_sector.strip() or not new_banco.strip():
                st.error("Completa todos los campos.")
                return

            try:
                run_exec("""
                    INSERT INTO machines (id_maquina, fabricante, sector, banco)
                    VALUES (%s,%s,%s,%s)
                """, (nid, new_fab.strip(), new_sector.strip(), new_banco.strip()))
                st.success("Máquina creada.")
                st.rerun()
            except Exception as e:
                st.error("No se pudo crear. ¿id_maquina ya existe?")
                st.exception(e)


def page_mantenciones():
    require_login()

    st.markdown('<div class="kr-card">', unsafe_allow_html=True)
    st.markdown('<p class="kr-title">🛠️ Mantenciones</p>', unsafe_allow_html=True)
    st.markdown('<p class="kr-sub">Registrar mantenciones con selección buscable de máquinas.</p>', unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    machines = get_all_machines()
    if not machines:
        st.warning("Primero debes registrar máquinas.")
        return

    labels = [f'{m["id_maquina"]} • {m["fabricante"]} • {m["sector"]} • {m["banco"]}' for m in machines]
    idx_map = {labels[i]: machines[i] for i in range(len(machines))}

    c1, c2, c3, c4 = st.columns([2, 1, 2, 2])
    with c1:
        sel_label = st.selectbox("Máquina (buscable)", labels)
        sel_machine = idx_map[sel_label]
        id_maquina = int(sel_machine["id_maquina"])
    with c2:
        fecha = st.date_input("Fecha", value=date.today())
    with c3:
        tipo = st.selectbox("Tipo", ["Preventiva", "Correctiva", "Revisión", "Software", "Otro"])
    with c4:
        realizado_por = st.text_input("Realizado por", value=current_user()["username"])

    descripcion = st.text_area("Descripción", height=120, placeholder="Detalle de la mantención, falla, acción realizada, repuestos, etc.")

    if st.button("Guardar mantención", use_container_width=True):
        if not descripcion.strip():
            st.error("La descripción es obligatoria.")
            return

        # Validación: no guardar si no existe máquina
        if not machine_exists(id_maquina):
            st.error("No se puede guardar: la máquina seleccionada ya no existe.")
            return

        try:
            run_exec("""
                INSERT INTO mantenciones (id_maquina, tipo, descripcion, fecha, realizado_por)
                VALUES (%s,%s,%s,%s,%s)
            """, (id_maquina, tipo, descripcion.strip(), fecha, realizado_por.strip()))
            st.success("Mantención registrada.")
            st.rerun()
        except Exception as e:
            st.error("No se pudo guardar la mantención.")
            st.exception(e)


def page_historial():
    require_login()

    st.markdown('<div class="kr-card">', unsafe_allow_html=True)
    st.markdown('<p class="kr-title">📚 Historial</p>', unsafe_allow_html=True)
    st.markdown('<p class="kr-sub">Historial con JOIN a máquinas (fabricante/sector/banco).</p>', unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns([2, 1, 1, 1])
    with c1:
        q = st.text_input("Buscar (id_maquina / sector / banco / descripción)", "")
    with c2:
        tipo = st.selectbox("Tipo", ["(Todos)", "Preventiva", "Correctiva", "Revisión", "Software", "Otro"])
    with c3:
        desde = st.date_input("Desde", value=date.today().replace(day=1))
    with c4:
        hasta = st.date_input("Hasta", value=date.today())

    params = {"desde": desde, "hasta": hasta}
    where = ["m.fecha BETWEEN %(desde)s AND %(hasta)s"]

    if tipo != "(Todos)":
        where.append("m.tipo = %(tipo)s")
        params["tipo"] = tipo

    if q.strip():
        where.append("""
            (
                ma.id_maquina::text ILIKE %(q)s OR
                ma.fabricante ILIKE %(q)s OR
                ma.sector ILIKE %(q)s OR
                ma.banco ILIKE %(q)s OR
                m.descripcion ILIKE %(q)s OR
                m.realizado_por ILIKE %(q)s
            )
        """)
        params["q"] = f"%{q.strip()}%"

    sql = f"""
        SELECT
            m.id,
            m.fecha,
            m.tipo,
            ma.id_maquina,
            ma.fabricante,
            ma.sector,
            ma.banco,
            m.realizado_por,
            m.descripcion,
            m.created_at
        FROM mantenciones m
        JOIN machines ma ON ma.id_maquina = m.id_maquina
        WHERE {" AND ".join(where)}
        ORDER BY m.fecha DESC, m.id DESC
        LIMIT 2000;
    """

    try:
        rows = run_fetchall(sql, params)
        st.dataframe(rows, use_container_width=True, hide_index=True)
        st.caption(f"Mostrando {len(rows)} registros (máximo 2000).")
    except Exception as e:
        st.error("No se pudo cargar historial.")
        st.exception(e)


def page_usuarios_admin():
    require_admin()

    st.markdown('<div class="kr-card">', unsafe_allow_html=True)
    st.markdown('<p class="kr-title">👤 Usuarios (Admin)</p>', unsafe_allow_html=True)
    st.markdown('<p class="kr-sub">Crear usuarios, resetear claves.</p>', unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["📋 Usuarios", "➕ Crear / Reset"])

    with tab1:
        users = run_fetchall("""
            SELECT id, username, is_admin, created_at
            FROM users
            ORDER BY is_admin DESC, username ASC;
        """)
        st.dataframe(users, use_container_width=True, hide_index=True)

        st.divider()
        st.write("Eliminar usuario:")
        usernames = [u["username"] for u in users]
        if usernames:
            u_sel = st.selectbox("Usuario", usernames)
            if st.button("Eliminar usuario seleccionado", use_container_width=True):
                if u_sel == current_user()["username"]:
                    st.error("No puedes eliminar tu propio usuario logueado.")
                else:
                    try:
                        run_exec("DELETE FROM users WHERE username=%s;", (u_sel,))
                        st.success("Usuario eliminado.")
                        st.rerun()
                    except Exception as e:
                        st.error("No se pudo eliminar el usuario.")
                        st.exception(e)

    with tab2:
        c1, c2, c3 = st.columns([2, 2, 1])
        with c1:
            new_user = st.text_input("Nuevo usuario", key="new_user")
        with c2:
            new_pass = st.text_input("Nueva contraseña", type="password", key="new_pass")
        with c3:
            new_is_admin = st.checkbox("Admin", value=False, key="new_is_admin")

        if st.button("Crear usuario", use_container_width=True):
            if not new_user.strip() or not new_pass:
                st.error("Usuario y contraseña son obligatorios.")
            else:
                try:
                    run_exec("""
                        INSERT INTO users (username, password_hash, is_admin)
                        VALUES (%s,%s,%s)
                    """, (new_user.strip(), hash_password(new_pass), bool(new_is_admin)))
                    st.success("Usuario creado.")
                    st.rerun()
                except Exception as e:
                    st.error("No se pudo crear. ¿Usuario ya existe?")
                    st.exception(e)

        st.divider()
        st.write("Reset contraseña:")
        users = run_fetchall("SELECT username FROM users ORDER BY username;")
        if users:
            u = st.selectbox("Usuario a resetear", [x["username"] for x in users], key="reset_user")
            np = st.text_input("Nueva contraseña", type="password", key="reset_pass")
            if st.button("Resetear contraseña", use_container_width=True):
                if not np:
                    st.error("Ingresa una nueva contraseña.")
                else:
                    try:
                        run_exec("UPDATE users SET password_hash=%s WHERE username=%s;", (hash_password(np), u))
                        st.success("Contraseña actualizada.")
                    except Exception as e:
                        st.error("No se pudo resetear la contraseña.")
                        st.exception(e)


# ----------------------------
# SIDEBAR NAV
# ----------------------------
def render_sidebar_nav():
    u = current_user()
    st.sidebar.markdown("### KR_TGM")
    st.sidebar.write(f"👋 **{u['username']}**")
    st.sidebar.caption("Mantenciones • Streamlit + Supabase")

    pages = ["🛠️ Mantenciones", "📚 Historial", "🎰 Máquinas"]
    if u.get("is_admin"):
        pages.append("👤 Usuarios (Admin)")
    pages.append("🚪 Cerrar sesión")

    choice = st.sidebar.radio("Navegación", pages, index=0)

    if choice == "🚪 Cerrar sesión":
        logout()
        st.success("Sesión cerrada.")
        st.rerun()

    return choice


# ----------------------------
# MAIN
# ----------------------------
def main():
    if not is_logged_in():
        render_login()
        return

    choice = render_sidebar_nav()

    if choice == "🎰 Máquinas":
        page_maquinas()
    elif choice == "🛠️ Mantenciones":
        page_mantenciones()
    elif choice == "📚 Historial":
        page_historial()
    elif choice == "👤 Usuarios (Admin)":
        page_usuarios_admin()
    else:
        page_mantenciones()


if __name__ == "__main__":
    main()
