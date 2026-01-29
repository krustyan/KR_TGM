import os
import re
from datetime import datetime, date

import streamlit as st

# Dependencias:
# - psycopg2-binary
# - bcrypt
# - pandas (opcional, pero útil)
import psycopg2
import psycopg2.extras
import bcrypt


# =========================
# Config
# =========================
APP_TITLE = "🛠️ KR_TGM • Mantenciones e Historial"

ESTADOS_MAQUINA = [
    "Operativa",
    "Fuera de Servicio",
    "En Mantención",
    "En Observación",
    "Retirada",
]

TIPOS_MANTENCION = [
    "Preventiva",
    "Correctiva",
    "Inspección",
    "Otro",
]


# =========================
# Helpers: DB
# =========================
def get_db_url() -> str:
    # Streamlit Cloud: st.secrets
    if "DB_URL" in st.secrets:
        return str(st.secrets["DB_URL"]).strip()
    # Local fallback: env var
    if os.getenv("DB_URL"):
        return os.getenv("DB_URL").strip()
    raise RuntimeError("Falta DB_URL en secrets o variables de entorno.")


def db_connect():
    return psycopg2.connect(get_db_url(), cursor_factory=psycopg2.extras.RealDictCursor)


def db_fetchone(sql: str, params=None):
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.fetchone()


def db_fetchall(sql: str, params=None):
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.fetchall()


def db_execute(sql: str, params=None):
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
        conn.commit()


def tables_exist() -> bool:
    try:
        row = db_fetchone(
            """
            select
              to_regclass('public.users') as users,
              to_regclass('public.machines') as machines,
              to_regclass('public.maintenance') as maintenance
            """
        )
        if not row:
            return False
        return bool(row["users"] and row["machines"] and row["maintenance"])
    except Exception:
        return False


def ensure_tables():
    """
    Crea tablas si no existen. Seguro de ejecutar múltiples veces.
    """
    db_execute(
        """
        create table if not exists public.users (
            id bigserial primary key,
            username text unique not null,
            password_hash text not null,
            role text not null check (role in ('tecnico','supervisor','admin')),
            nombre text,
            is_active boolean not null default true,
            created_at timestamp not null default now()
        );

        create table if not exists public.machines (
            id_maquina bigint primary key,
            serie text,
            fabricante text,
            modelo text,
            juego text,
            sector text,
            banco text,
            estado text default 'Operativa',
            notas text,
            created_at timestamp not null default now(),
            updated_at timestamp not null default now()
        );

        create table if not exists public.maintenance (
            id bigserial primary key,
            id_maquina bigint not null references public.machines(id_maquina) on delete cascade,
            tipo text not null,
            fecha timestamp not null default now(),
            tecnico_username text,
            falla text,
            diagnostico text,
            accion text,
            repuestos text,
            estado_final text,
            link_adjuntos text,
            created_at timestamp not null default now()
        );

        create index if not exists idx_maintenance_id_maquina on public.maintenance (id_maquina);
        create index if not exists idx_maintenance_fecha on public.maintenance (fecha desc);
        """
    )


# =========================
# Helpers: Auth
# =========================
def normalize_username(u: str) -> str:
    u = (u or "").strip().lower()
    u = re.sub(r"[^a-z0-9._-]", "", u)
    return u


def hash_password(plain: str) -> str:
    pw = (plain or "").encode("utf-8")
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(pw, salt).decode("utf-8")


def verify_password(plain: str, stored_hash: str) -> bool:
    try:
        return bcrypt.checkpw(
            (plain or "").encode("utf-8"),
            (stored_hash or "").encode("utf-8"),
        )
    except Exception:
        return False


def get_user(username: str):
    return db_fetchone(
        "select * from public.users where username=%s and is_active=true",
        (normalize_username(username),),
    )


def is_logged_in() -> bool:
    return bool(st.session_state.get("auth_user"))


def current_user():
    return st.session_state.get("auth_user")


def require_login():
    if not is_logged_in():
        st.warning("Debes iniciar sesión.")
        st.stop()


def require_admin():
    require_login()
    u = current_user()
    if not u or u.get("role") != "admin":
        st.error("Acceso solo para admin.")
        st.stop()


def bootstrap_admin_if_empty():
    """
    Si no existen usuarios, permite crear admin con SETUP_KEY.
    """
    setup_key = str(st.secrets.get("SETUP_KEY", "")).strip()
    if not setup_key:
        return

    row = db_fetchone("select count(*) as n from public.users")
    if row and int(row["n"]) == 0:
        st.info("🔐 No hay usuarios creados. Puedes inicializar el admin con SETUP_KEY.")
        with st.expander("Inicializar Admin (solo primera vez)", expanded=True):
            k = st.text_input("SETUP_KEY", type="password")
            if k != setup_key:
                st.caption("Ingresa tu SETUP_KEY para crear el primer admin.")
                return

            username = st.text_input("Username admin", value="cristian")
            nombre = st.text_input("Nombre", value="Cristian")
            pw = st.text_input("Contraseña admin", type="password")
            pw2 = st.text_input("Repetir contraseña", type="password")
            if st.button("Crear Admin", type="primary"):
                username_n = normalize_username(username)
                if not username_n:
                    st.error("Username inválido.")
                    st.stop()
                if not pw or pw != pw2:
                    st.error("Contraseña inválida o no coincide.")
                    st.stop()

                db_execute(
                    """
                    insert into public.users (username, password_hash, role, nombre, is_active)
                    values (%s,%s,'admin',%s,true)
                    """,
                    (username_n, hash_password(pw), nombre),
                )
                st.success("Admin creado. Ahora inicia sesión.")
                st.rerun()


# =========================
# UI: Layout
# =========================
st.set_page_config(page_title="KR_TGM", page_icon="🛠️", layout="wide")
st.title(APP_TITLE)

# Asegurar tablas (no rompe si ya existen)
try:
    ensure_tables()
except Exception as e:
    st.error(f"No se pudo asegurar la estructura de DB: {e}")
    st.stop()

# Bootstrap si DB vacía
try:
    bootstrap_admin_if_empty()
except Exception:
    pass


# =========================
# Pages
# =========================
def page_login():
    st.subheader("🔐 Login")

    col1, col2 = st.columns([2, 3])
    with col1:
        username = st.text_input("Usuario", key="login_user")
        password = st.text_input("Contraseña", type="password", key="login_pass")
        if st.button("Ingresar", type="primary"):
            u = get_user(username)
            if not u:
                st.error("Usuario no existe o está inactivo.")
                return
            if not verify_password(password, u["password_hash"]):
                st.error("Credenciales incorrectas.")
                return
            st.session_state["auth_user"] = {
                "username": u["username"],
                "role": u["role"],
                "nombre": u.get("nombre") or u["username"],
            }
            st.success("✅ Sesión iniciada.")
            st.rerun()

    with col2:
        st.caption(
            "Tip: Si es primera vez y no hay usuarios, inicializa el admin con SETUP_KEY (arriba)."
        )


def page_machines():
    require_login()

    st.subheader("🖥️ Máquinas")

    # Formulario: ficha máquina
    with st.form("machine_form", clear_on_submit=False):
        colA, colB = st.columns([1, 2])
        with colA:
            id_maquina_str = st.text_input("ID Máquina", placeholder="32345")
            serie = st.text_input("Serie", placeholder="MX0021318")
            estado = st.selectbox("Estado", ESTADOS_MAQUINA, index=0)
        with colB:
            fabricante = st.text_input("Fabricante", placeholder="IGT / Novomatic / WMS ...")
            modelo = st.text_input("Modelo", placeholder="Sierra 27 / Helix / ...")
            juego = st.text_input("Juego", placeholder="Nombre del juego / Theme")
            sector = st.text_input("Sector", placeholder="VIP / Terraza / Bingo / ...")
            banco = st.text_input("Banco", placeholder="Banco o isla (ej: Banco 12)")
            notas = st.text_area("Notas", placeholder="Observaciones generales de la máquina")

        submitted = st.form_submit_button("💾 Guardar / Actualizar", type="primary")

    if submitted:
        if not id_maquina_str.strip().isdigit():
            st.error("ID Máquina debe ser numérico.")
        else:
            id_maquina = int(id_maquina_str.strip())
            try:
                db_execute(
                    """
                    insert into public.machines
                    (id_maquina, serie, fabricante, modelo, juego, sector, banco, estado, notas, updated_at)
                    values (%s,%s,%s,%s,%s,%s,%s,%s,%s, now())
                    on conflict (id_maquina) do update set
                        serie=excluded.serie,
                        fabricante=excluded.fabricante,
                        modelo=excluded.modelo,
                        juego=excluded.juego,
                        sector=excluded.sector,
                        banco=excluded.banco,
                        estado=excluded.estado,
                        notas=excluded.notas,
                        updated_at=now()
                    """,
                    (id_maquina, serie, fabricante, modelo, juego, sector, banco, estado, notas),
                )
                st.success("✅ Máquina guardada/actualizada.")
            except Exception as e:
                st.error(f"Error guardando máquina: {e}")

    st.divider()

    # Listado y búsqueda
    st.markdown("### 🔎 Buscar / Listar")
    c1, c2, c3, c4 = st.columns([1, 1, 1, 2])
    with c1:
        q_id = st.text_input("ID (opcional)", placeholder="32345")
    with c2:
        q_sector = st.text_input("Sector", placeholder="VIP")
    with c3:
        q_banco = st.text_input("Banco", placeholder="Banco 12")
    with c4:
        q_text = st.text_input("Texto libre", placeholder="fabricante / modelo / juego")

    where = []
    params = []

    if q_id.strip():
        if q_id.strip().isdigit():
            where.append("id_maquina = %s")
            params.append(int(q_id.strip()))
        else:
            st.warning("ID debe ser numérico para filtrar por ID.")

    if q_sector.strip():
        where.append("coalesce(sector,'') ilike %s")
        params.append(f"%{q_sector.strip()}%")

    if q_banco.strip():
        where.append("coalesce(banco,'') ilike %s")
        params.append(f"%{q_banco.strip()}%")

    if q_text.strip():
        where.append(
            """
            (
              coalesce(serie,'') ilike %s
              or coalesce(fabricante,'') ilike %s
              or coalesce(modelo,'') ilike %s
              or coalesce(juego,'') ilike %s
              or coalesce(notas,'') ilike %s
            )
            """
        )
        params.extend([f"%{q_text.strip()}%"] * 5)

    sql = "select id_maquina, serie, fabricante, modelo, juego, sector, banco, estado, notas, updated_at from public.machines"
    if where:
        sql += " where " + " and ".join(where)
    sql += " order by id_maquina asc limit 500"

    try:
        rows = db_fetchall(sql, tuple(params))
        st.caption(f"Mostrando {len(rows)} máquinas (máx 500).")
        st.dataframe(rows, use_container_width=True, hide_index=True)
    except Exception as e:
        st.error(f"Error listando máquinas: {e}")


def page_register_maintenance():
    require_login()
    u = current_user()
    st.subheader("📝 Registrar Mantención (Preventiva / Correctiva)")

    with st.form("maint_form", clear_on_submit=True):
        col1, col2, col3 = st.columns([1, 1, 2])
        with col1:
            id_maquina_str = st.text_input("ID Máquina", placeholder="32345")
            tipo = st.selectbox("Tipo", TIPOS_MANTENCION, index=0)
            estado_final = st.selectbox("Estado final máquina", ESTADOS_MAQUINA, index=0)
        with col2:
            fecha = st.date_input("Fecha", value=date.today())
            hora = st.time_input("Hora", value=datetime.now().time())
            tecnico = st.text_input("Técnico (username)", value=u["username"])
        with col3:
            falla = st.text_area("Falla (si aplica)", placeholder="Describe la falla reportada")
            diagnostico = st.text_area("Diagnóstico", placeholder="Qué se encontró")
            accion = st.text_area("Acción / Trabajo realizado", placeholder="Qué se hizo")
            repuestos = st.text_area("Repuestos", placeholder="Repuestos usados")
            link_adjuntos = st.text_input("Link adjuntos (opcional)", placeholder="Drive / carpeta / ticket")

        submitted = st.form_submit_button("💾 Guardar mantención", type="primary")

    if not submitted:
        return

    if not id_maquina_str.strip().isdigit():
        st.error("ID Máquina debe ser numérico.")
        return

    id_maquina = int(id_maquina_str.strip())
    ts = datetime.combine(fecha, hora)

    # validar que exista máquina
    m = db_fetchone("select id_maquina from public.machines where id_maquina=%s", (id_maquina,))
    if not m:
        st.error("La máquina no existe. Primero crea la ficha en 'Máquinas'.")
        return

    try:
        db_execute(
            """
            insert into public.maintenance
            (id_maquina, tipo, fecha, tecnico_username, falla, diagnostico, accion, repuestos, estado_final, link_adjuntos)
            values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                id_maquina,
                tipo,
                ts,
                normalize_username(tecnico),
                falla,
                diagnostico,
                accion,
                repuestos,
                estado_final,
                link_adjuntos,
            ),
        )
        # si corresponde, actualiza estado actual de la máquina
        db_execute(
            "update public.machines set estado=%s, updated_at=now() where id_maquina=%s",
            (estado_final, id_maquina),
        )
        st.success("✅ Mantención guardada y estado actualizado.")
    except Exception as e:
        st.error(f"Error guardando mantención: {e}")


def page_history():
    require_login()
    st.subheader("📚 Historial por Máquina")

    cola, colb, colc = st.columns([1, 1, 2])
    with cola:
        id_str = st.text_input("ID Máquina", placeholder="32345")
    with colb:
        tipo = st.selectbox("Filtrar tipo", ["(Todos)"] + TIPOS_MANTENCION, index=0)
    with colc:
        limit = st.slider("Máximo de registros", 10, 500, 100)

    if not id_str.strip():
        st.info("Ingresa un ID de máquina para ver historial.")
        return

    if not id_str.strip().isdigit():
        st.error("ID Máquina debe ser numérico.")
        return

    mid = int(id_str.strip())

    m = db_fetchone(
        """
        select id_maquina, serie, fabricante, modelo, juego, sector, banco, estado, notas
        from public.machines
        where id_maquina=%s
        """,
        (mid,),
    )
    if not m:
        st.warning("No existe la máquina. Ve a 'Máquinas' para crearla.")
        return

    # ficha resumida
    st.markdown("### 🖥️ Ficha")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.write(f"**ID:** {m['id_maquina']}")
        st.write(f"**Serie:** {m.get('serie') or '-'}")
        st.write(f"**Estado:** {m.get('estado') or '-'}")
    with c2:
        st.write(f"**Fabricante:** {m.get('fabricante') or '-'}")
        st.write(f"**Modelo:** {m.get('modelo') or '-'}")
        st.write(f"**Juego:** {m.get('juego') or '-'}")
    with c3:
        st.write(f"**Sector:** {m.get('sector') or '-'}")
        st.write(f"**Banco:** {m.get('banco') or '-'}")
        st.write(f"**Notas:** {m.get('notas') or '-'}")

    st.divider()

    where = ["id_maquina=%s"]
    params = [mid]
    if tipo != "(Todos)":
        where.append("tipo=%s")
        params.append(tipo)

    try:
        rows = db_fetchall(
            f"""
            select
              id,
              fecha,
              tipo,
              tecnico_username,
              falla,
              diagnostico,
              accion,
              repuestos,
              estado_final,
              link_adjuntos
            from public.maintenance
            where {' and '.join(where)}
            order by fecha desc
            limit %s
            """,
            tuple(params + [limit]),
        )

        st.caption(f"Registros encontrados: {len(rows)}")
        st.dataframe(rows, use_container_width=True, hide_index=True)

    except Exception as e:
        st.error(f"Error consultando historial: {e}")


def page_users_admin():
    require_admin()
    st.subheader("👥 Usuarios (Admin)")

    st.markdown("### ➕ Crear usuario")
    with st.form("user_create", clear_on_submit=True):
        col1, col2, col3 = st.columns([1, 1, 1])
        with col1:
            username = st.text_input("Username (sin espacios)", placeholder="tecnico1")
            nombre = st.text_input("Nombre", placeholder="Juan Pérez")
        with col2:
            role = st.selectbox("Rol", ["tecnico", "supervisor", "admin"], index=0)
            is_active = st.checkbox("Activo", value=True)
        with col3:
            pw = st.text_input("Contraseña", type="password")
            pw2 = st.text_input("Repetir contraseña", type="password")

        submitted = st.form_submit_button("Crear usuario", type="primary")

    if submitted:
        u = normalize_username(username)
        if not u:
            st.error("Username inválido.")
        elif not pw or pw != pw2:
            st.error("Contraseña inválida o no coincide.")
        else:
            try:
                db_execute(
                    """
                    insert into public.users (username, password_hash, role, nombre, is_active)
                    values (%s,%s,%s,%s,%s)
                    """,
                    (u, hash_password(pw), role, nombre, bool(is_active)),
                )
                st.success("✅ Usuario creado.")
            except Exception as e:
                st.error(f"Error creando usuario: {e}")

    st.divider()

    st.markdown("### 📋 Listado")
    try:
        rows = db_fetchall(
            "select id, username, role, nombre, is_active, created_at from public.users order by id asc"
        )
        st.dataframe(rows, use_container_width=True, hide_index=True)
        st.caption("Para desactivar, edita is_active desde Supabase o te agrego botón si quieres.")
    except Exception as e:
        st.error(f"Error listando usuarios: {e}")


# =========================
# Sidebar + Navigation
# =========================
with st.sidebar:
    st.markdown("## Navegación")

    # Mostrar estado tablas
    ok_tables = tables_exist()
    if not ok_tables:
        st.error("Tablas no existen o no se pueden leer (users/machines/maintenance).")
    else:
        # debug suave
        row = db_fetchone(
            """
            select
              to_regclass('public.users') as u,
              to_regclass('public.machines') as m,
              to_regclass('public.maintenance') as t
            """
        )
        st.caption(f"DEBUG to_regclass: {row}")

    if is_logged_in():
        u = current_user()
        st.success(f"{u.get('nombre','Usuario')} ({u.get('role')})")
        if st.button("Cerrar sesión"):
            st.session_state.pop("auth_user", None)
            st.rerun()

    st.markdown("### Ir a:")
    # Menú
    options = ["Login", "Máquinas", "Registrar", "Historial", "Usuarios"]
    default = 0
    choice = st.radio("", options, index=default)

# Routing
if choice == "Login":
    page_login()
elif choice == "Máquinas":
    page_machines()
elif choice == "Registrar":
    page_register_maintenance()
elif choice == "Historial":
    page_history()
elif choice == "Usuarios":
    page_users_admin()
