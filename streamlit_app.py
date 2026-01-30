import os
import re
from datetime import datetime, date

import streamlit as st
import pandas as pd
import psycopg
from psycopg.rows import dict_row
import bcrypt


# =========================
# Config
# =========================
APP_TITLE = "KR_TGM • Mantenciones e Historial"

ESTADOS_MAQUINA = [
    "Operativa",
    "Fuera de Servicio",
    "En Mantención",
    "En Observación",
    "Bloqueada",
]

TIPOS_MANTENCION = ["Preventiva", "Correctiva", "Inspección", "Otro"]


def get_secret(key: str, default=None):
    # Streamlit Cloud: st.secrets
    if key in st.secrets:
        return st.secrets.get(key)
    # local env fallback
    return os.getenv(key, default)


DB_URL = get_secret("DB_URL")
SETUP_KEY = get_secret("SETUP_KEY", "KR2026Admin")


# =========================
# DB helpers
# =========================
def db_connect():
    if not DB_URL:
        raise RuntimeError("Falta DB_URL en Secrets.")
    return psycopg2.connect(DB_URL, cursor_factory=RealDictCursor, sslmode="require")


def db_fetchall(sql: str, params=None):
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.fetchall()


def db_fetchone(sql: str, params=None):
    rows = db_fetchall(sql, params)
    return rows[0] if rows else None


def db_execute(sql: str, params=None):
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
        conn.commit()


def table_exists(table_name: str, schema: str = "public") -> bool:
    r = db_fetchone(
        """
        select exists(
            select 1 from information_schema.tables
            where table_schema=%s and table_name=%s
        ) as ok
        """,
        (schema, table_name),
    )
    return bool(r and r["ok"])


def column_exists(table_name: str, column_name: str, schema: str = "public") -> bool:
    r = db_fetchone(
        """
        select exists(
            select 1 from information_schema.columns
            where table_schema=%s and table_name=%s and column_name=%s
        ) as ok
        """,
        (schema, table_name, column_name),
    )
    return bool(r and r["ok"])


# =========================
# Schema bootstrap
# =========================
SCHEMA_SQL = """
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
  id_maquina integer primary key,
  serie text,
  fabricante text,
  modelo text,
  juego text,
  sector text,
  banco text,
  estado text not null default 'Operativa',
  notas text,
  created_at timestamp not null default now(),
  updated_at timestamp not null default now()
);

create table if not exists public.maintenance (
  id bigserial primary key,
  id_maquina integer not null references public.machines(id_maquina) on delete cascade,
  tipo text not null,
  fecha date not null default current_date,
  tecnico text,
  falla text,
  diagnostico text,
  accion text,
  repuestos text,
  link_adjuntos text,
  estado_final text,
  created_at timestamp not null default now()
);

create index if not exists maintenance_id_maquina_idx on public.maintenance(id_maquina);
"""


def ensure_schema():
    # crea tablas si faltan
    db_execute(SCHEMA_SQL)

    # compat: si users no tiene is_active, lo agrega (pero el login NO depende de esto)
    if table_exists("users") and not column_exists("users", "is_active"):
        db_execute("alter table public.users add column is_active boolean not null default true;")

    # compat: si machines tenía columnas viejas, no las borra, solo asegura las nuevas
    # (si tu tabla ya existe con otra estructura, lo ideal es migrar, pero esto no rompe.)
    # Asegurar columnas clave (si faltan, se agregan)
    cols = [
        ("serie", "text"),
        ("fabricante", "text"),
        ("modelo", "text"),
        ("juego", "text"),
        ("sector", "text"),
        ("banco", "text"),
        ("estado", "text"),
        ("notas", "text"),
    ]
    for col, typ in cols:
        if not column_exists("machines", col):
            db_execute(f'alter table public.machines add column {col} {typ};')
    if column_exists("machines", "estado"):
        # default estado si está vacío
        db_execute("update public.machines set estado='Operativa' where estado is null;")

    # timestamps
    if not column_exists("machines", "created_at"):
        db_execute("alter table public.machines add column created_at timestamp not null default now();")
    if not column_exists("machines", "updated_at"):
        db_execute("alter table public.machines add column updated_at timestamp not null default now();")


# =========================
# Auth
# =========================
def bcrypt_hash(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def bcrypt_check(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def normalize_username(u: str) -> str:
    return (u or "").strip().lower()


def get_user(username: str):
    username = normalize_username(username)
    if not username:
        return None

    # Si existe is_active, lo respeta. Si NO existe, no filtra.
    if column_exists("users", "is_active"):
        return db_fetchone(
            "select * from public.users where username=%s and is_active=true",
            (username,),
        )
    return db_fetchone(
        "select * from public.users where username=%s",
        (username,),
    )


def login(username: str, password: str):
    u = get_user(username)
    if not u:
        return None, "Usuario no existe o está inactivo."
    if not bcrypt_check(password, u["password_hash"]):
        return None, "Contraseña incorrecta."
    return u, None


def is_admin() -> bool:
    return bool(st.session_state.get("auth_user") and st.session_state["auth_user"].get("role") == "admin")


# =========================
# UI helpers
# =========================
def set_page(page: str):
    st.session_state["page"] = page


def active_page() -> str:
    return st.session_state.get("page", "Login")


def inject_css():
    st.markdown(
        """
        <style>
          .kr-title { font-size: 2rem; font-weight: 800; margin-bottom: .5rem; }
          .kr-sub { opacity: .8; margin-bottom: 1rem; }
          .kr-card { border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 16px; background: rgba(255,255,255,0.03); }
          .kr-navbtn button {
              width: 100%;
              border-radius: 12px !important;
              padding: 10px 12px !important;
              border: 1px solid rgba(255,255,255,0.10) !important;
          }
          .kr-navbtn-active button{
              background: rgba(46, 204, 113, 0.20) !important;
              border: 1px solid rgba(46, 204, 113, 0.55) !important;
              font-weight: 700 !important;
          }
          .kr-navcaption { font-weight: 700; margin-top: .5rem; margin-bottom: .25rem; opacity: .9; }
          .kr-muted { opacity: .75; }
          .kr-badge { display:inline-block; padding:2px 10px; border-radius: 999px; background: rgba(255,255,255,.08); font-size: .85rem;}
        </style>
        """,
        unsafe_allow_html=True,
    )


def sidebar():
    with st.sidebar:
        st.markdown(f"<div class='kr-navcaption'>Navegación</div>", unsafe_allow_html=True)

        user = st.session_state.get("auth_user")
        if user:
            st.success(f"{user.get('nombre') or user.get('username')} ({user.get('role')})")

        def nav_button(label: str, page: str, icon: str = ""):
            cls = "kr-navbtn kr-navbtn-active" if active_page() == page else "kr-navbtn"
            st.markdown(f"<div class='{cls}'>", unsafe_allow_html=True)
            clicked = st.button(f"{icon} {label}", use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)
            if clicked:
                set_page(page)

        # Si no está logueado, solo Login/Setup
        if not st.session_state.get("auth_user"):
            nav_button("Login", "Login", "🔐")
            nav_button("Setup (crear admin)", "Setup", "🛠️")
            return

        nav_button("Máquinas", "Máquinas", "🖥️")
        nav_button("Registrar Mantención", "Registrar", "📝")
        nav_button("Historial", "Historial", "📚")
        if is_admin():
            nav_button("Usuarios", "Usuarios", "👥")

        st.divider()
        if st.button("🚪 Cerrar sesión", use_container_width=True):
            st.session_state["auth_user"] = None
            set_page("Login")
            st.rerun()


# =========================
# Pages
# =========================
def page_login():
    st.subheader("🔐 Login")

    with st.form("login_form", clear_on_submit=False):
        username = st.text_input("Usuario", value="")
        password = st.text_input("Contraseña", value="", type="password")
        ok = st.form_submit_button("Ingresar")

    if ok:
        user, err = login(username, password)
        if err:
            st.error(err)
        else:
            st.session_state["auth_user"] = user
            set_page("Máquinas")
            st.rerun()


def page_setup():
    st.subheader("🛠️ Setup (crear admin inicial)")
    st.caption("Usa esto solo la primera vez para crear un usuario administrador.")

    # si ya hay algún usuario admin, no permitir
    admin_exists = db_fetchone("select 1 from public.users where role='admin' limit 1")
    if admin_exists:
        st.info("Ya existe un usuario admin. Usa la pestaña Login.")
        return

    with st.form("setup_form"):
        setup_key = st.text_input("Setup Key", type="password", help="Debe coincidir con SETUP_KEY en Secrets.")
        username = st.text_input("Usuario admin (ej: cristian)", value="cristian")
        nombre = st.text_input("Nombre", value="Cristian")
        password = st.text_input("Contraseña admin", type="password")
        password2 = st.text_input("Repite contraseña", type="password")
        ok = st.form_submit_button("Crear admin")

    if ok:
        if setup_key != SETUP_KEY:
            st.error("Setup Key incorrecta.")
            return
        if normalize_username(username) == "":
            st.error("Usuario inválido.")
            return
        if password != password2:
            st.error("Las contraseñas no coinciden.")
            return
        if len(password) < 6:
            st.error("Contraseña muy corta (mínimo 6).")
            return

        ph = bcrypt_hash(password)
        db_execute(
            "insert into public.users(username, password_hash, role, nombre, is_active) values (%s,%s,'admin',%s,true)",
            (normalize_username(username), ph, nombre),
        )
        st.success("Admin creado. Ahora puedes iniciar sesión.")
        set_page("Login")
        st.rerun()


def page_machines():
    st.subheader("🖥️ Máquinas")

    # Form crear/actualizar máquina
    st.markdown("<div class='kr-card'>", unsafe_allow_html=True)
    st.markdown("### Crear / Actualizar Máquina")
    with st.form("machine_form"):
        c1, c2 = st.columns(2)
        with c1:
            id_maquina = st.text_input("ID Máquina", placeholder="32045")
            serie = st.text_input("Serie", placeholder="1173301001")
            estado = st.selectbox("Estado", ESTADOS_MAQUINA, index=0)
        with c2:
            fabricante = st.text_input("Fabricante", placeholder="ATRONIC")
            modelo = st.text_input("Modelo", placeholder="EMOTION")
            juego = st.text_input("Juego", placeholder="XANADU CITY OF LUCK KKC")

        sector = st.text_input("Sector", placeholder="TERRAZA")
        banco = st.text_input("Banco", placeholder="TE-05")
        notas = st.text_area("Notas", placeholder="Observaciones, detalles, etc.")

        ok = st.form_submit_button("Guardar")

    if ok:
        if not id_maquina.strip().isdigit():
            st.error("ID Máquina debe ser numérico.")
        else:
            mid = int(id_maquina.strip())
            # Upsert
            exists = db_fetchone("select 1 from public.machines where id_maquina=%s", (mid,))
            if exists:
                db_execute(
                    """
                    update public.machines
                    set serie=%s, fabricante=%s, modelo=%s, juego=%s, sector=%s, banco=%s,
                        estado=%s, notas=%s, updated_at=now()
                    where id_maquina=%s
                    """,
                    (serie, fabricante, modelo, juego, sector, banco, estado, notas, mid),
                )
                st.success("Máquina actualizada.")
            else:
                db_execute(
                    """
                    insert into public.machines
                    (id_maquina, serie, fabricante, modelo, juego, sector, banco, estado, notas)
                    values (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (mid, serie, fabricante, modelo, juego, sector, banco, estado, notas),
                )
                st.success("Máquina creada.")
            st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)

    st.divider()

    # Tabla listado
    st.markdown("### Listado")
    rows = db_fetchall(
        """
        select id_maquina, serie, fabricante, modelo, juego, sector, banco, estado, notas, updated_at
        from public.machines
        order by id_maquina asc
        """
    )
    if not rows:
        st.info("No hay máquinas registradas aún.")
        return

    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True)


def page_register():
    st.subheader("📝 Registrar Mantención")

    rows_m = db_fetchall("select id_maquina from public.machines order by id_maquina asc")
    if not rows_m:
        st.warning("Primero debes crear máquinas en la pestaña 'Máquinas'.")
        return

    ids = [r["id_maquina"] for r in rows_m]

    st.markdown("<div class='kr-card'>", unsafe_allow_html=True)
    with st.form("maint_form"):
        c1, c2 = st.columns(2)
        with c1:
            id_maquina = st.selectbox("ID Máquina", ids)
            tipo = st.selectbox("Tipo", TIPOS_MANTENCION)
            fecha = st.date_input("Fecha", value=date.today())
            tecnico = st.text_input("Técnico", value=st.session_state.get("auth_user", {}).get("nombre", ""))
        with c2:
            falla = st.text_input("Falla", placeholder="Descripción breve")
            diagnostico = st.text_area("Diagnóstico", placeholder="Diagnóstico / análisis")
            accion = st.text_area("Acción / Trabajo realizado", placeholder="Qué se hizo")
        repuestos = st.text_area("Repuestos", placeholder="Lista de repuestos")
        link_adjuntos = st.text_input("Link adjuntos", placeholder="Link Drive/Sharepoint/etc")
        estado_final = st.text_input("Estado final", placeholder="OK / pendiente / observado...")

        ok = st.form_submit_button("Guardar mantención")

    if ok:
        db_execute(
            """
            insert into public.maintenance
            (id_maquina, tipo, fecha, tecnico, falla, diagnostico, accion, repuestos, link_adjuntos, estado_final)
            values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (id_maquina, tipo, fecha, tecnico, falla, diagnostico, accion, repuestos, link_adjuntos, estado_final),
        )
        st.success("Mantención registrada.")
        set_page("Historial")
        st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)


def page_history():
    st.subheader("📚 Historial por Máquina")

    colA, colB, colC = st.columns([1, 1, 1])
    with colA:
        id_str = st.text_input("ID Máquina", placeholder="32045")
    with colB:
        tipo = st.selectbox("Filtrar tipo", ["(Todos)"] + TIPOS_MANTENCION)
    with colC:
        limit = st.slider("Máximo de registros", 10, 500, 100)

    if not id_str.strip():
        st.info("Ingresa un ID de máquina para ver historial.")
        return
    if not id_str.strip().isdigit():
        st.error("ID Máquina debe ser numérico.")
        return

    mid = int(id_str.strip())

    m = db_fetchone("select * from public.machines where id_maquina=%s", (mid,))
    if not m:
        st.warning("No existe esa máquina en la base. Créala en 'Máquinas'.")
        return

    st.markdown("<div class='kr-card'>", unsafe_allow_html=True)
    st.markdown(f"### 🖥️ Máquina {mid}  <span class='kr-badge'>{m.get('estado','')}</span>", unsafe_allow_html=True)
    st.write(
        {
            "Serie": m.get("serie"),
            "Fabricante": m.get("fabricante"),
            "Modelo": m.get("modelo"),
            "Juego": m.get("juego"),
            "Sector": m.get("sector"),
            "Banco": m.get("banco"),
            "Notas": m.get("notas"),
        }
    )
    st.markdown("</div>", unsafe_allow_html=True)

    if tipo == "(Todos)":
        rows = db_fetchall(
            """
            select *
            from public.maintenance
            where id_maquina=%s
            order by fecha desc, id desc
            limit %s
            """,
            (mid, limit),
        )
    else:
        rows = db_fetchall(
            """
            select *
            from public.maintenance
            where id_maquina=%s and tipo=%s
            order by fecha desc, id desc
            limit %s
            """,
            (mid, tipo, limit),
        )

    if not rows:
        st.info("No hay mantenciones registradas para esta máquina.")
        return

    df = pd.DataFrame(rows)

    # Orden de columnas "bonito"
    preferred = [
        "id", "fecha", "tipo", "tecnico", "falla", "diagnostico", "accion",
        "repuestos", "link_adjuntos", "estado_final", "created_at"
    ]
    cols = [c for c in preferred if c in df.columns] + [c for c in df.columns if c not in preferred]
    df = df[cols]

    st.dataframe(df, use_container_width=True, hide_index=True)


def page_users():
    st.subheader("👥 Usuarios (Admin)")

    if not is_admin():
        st.error("Acceso solo para admin.")
        return

    st.markdown("<div class='kr-card'>", unsafe_allow_html=True)
    st.markdown("### Crear usuario")
    with st.form("create_user"):
        c1, c2 = st.columns(2)
        with c1:
            username = st.text_input("Usuario", placeholder="tecnico1")
            nombre = st.text_input("Nombre", placeholder="Juan Pérez")
        with c2:
            role = st.selectbox("Rol", ["tecnico", "supervisor", "admin"])
            password = st.text_input("Contraseña", type="password")
        is_active = st.checkbox("Activo", value=True)
        ok = st.form_submit_button("Crear")

    if ok:
        if normalize_username(username) == "":
            st.error("Usuario inválido.")
        elif len(password) < 6:
            st.error("Contraseña muy corta (mínimo 6).")
        else:
            ph = bcrypt_hash(password)
            try:
                db_execute(
                    "insert into public.users(username,password_hash,role,nombre,is_active) values (%s,%s,%s,%s,%s)",
                    (normalize_username(username), ph, role, nombre, is_active),
                )
                st.success("Usuario creado.")
                st.rerun()
            except Exception as e:
                st.error(f"No se pudo crear (¿usuario repetido?): {e}")
    st.markdown("</div>", unsafe_allow_html=True)

    st.divider()
    st.markdown("### Listado")
    rows = db_fetchall("select id, username, role, nombre, is_active, created_at from public.users order by id asc")
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


# =========================
# Main
# =========================
def main():
    st.set_page_config(page_title=APP_TITLE, layout="wide")
    inject_css()

    st.markdown(f"<div class='kr-title'>🛠️ {APP_TITLE}</div>", unsafe_allow_html=True)
    st.markdown("<div class='kr-sub'>Registro de máquinas, mantenciones e historial (Supabase + Streamlit Cloud)</div>", unsafe_allow_html=True)

    # Preparar DB (sin mostrar debug)
    try:
        ensure_schema()
    except Exception:
        st.error("No se pudo preparar la base de datos. Revisa DB_URL en Secrets.")
        return

    # Sidebar (visual)
    sidebar()

    page = active_page()

    # Router
    if page == "Login":
        page_login()
    elif page == "Setup":
        page_setup()
    else:
        # Requiere login
        if not st.session_state.get("auth_user"):
            set_page("Login")
            st.rerun()

        if page == "Máquinas":
            page_machines()
        elif page == "Registrar":
            page_register()
        elif page == "Historial":
            page_history()
        elif page == "Usuarios":
            page_users()
        else:
            set_page("Máquinas")
            st.rerun()


if __name__ == "__main__":
    main()
