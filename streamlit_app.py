import os
import re
from datetime import date, datetime

import streamlit as st
import psycopg
from psycopg.rows import dict_row
import bcrypt


# =========================
# Config / Secrets
# =========================
APP_TITLE = "🛠️ KR_TGM • Mantenciones e Historial"

def get_secret(name: str, default=None):
    # Streamlit Cloud: st.secrets
    if name in st.secrets:
        return st.secrets.get(name)
    # Local: env var
    return os.getenv(name, default)

DB_URL = get_secret("DB_URL", "").strip()
SETUP_KEY = get_secret("SETUP_KEY", "").strip()

ESTADOS_MAQUINA = ["Operativa", "Fuera de Servicio", "En Mantención", "Baja", "Otra"]
TIPOS_MANTENCION = ["Preventiva", "Correctiva", "Inspección", "Otro"]


# =========================
# Estilo (Sidebar más visual)
# =========================
CSS = """
<style>
/* layout */
.block-container { padding-top: 1.2rem; }
h1, h2, h3 { letter-spacing: -0.02em; }

/* sidebar */
section[data-testid="stSidebar"] { background: #0f1116; }
.sidebar-title { color: #fff; font-weight: 700; font-size: 1.05rem; margin-bottom: .6rem; }

.navbox { margin-top: .7rem; display: flex; flex-direction: column; gap: .4rem; }
.navlink {
  display: block;
  padding: .65rem .75rem;
  border-radius: .7rem;
  text-decoration: none !important;
  color: rgba(255,255,255,.75);
  border: 1px solid rgba(255,255,255,.08);
  background: rgba(255,255,255,.03);
  font-weight: 600;
}
.navlink:hover { color: #fff; border-color: rgba(255,255,255,.18); }
.navlink.active {
  color: #fff !important;
  background: rgba(99, 102, 241, .22);   /* indigo */
  border-color: rgba(99, 102, 241, .45);
  box-shadow: 0 0 0 1px rgba(99, 102, 241, .12) inset;
}
.badge {
  display:inline-block;
  padding:.18rem .5rem;
  border-radius:999px;
  font-size:.78rem;
  font-weight:700;
  background: rgba(16,185,129,.18);
  color: rgba(255,255,255,.92);
  border: 1px solid rgba(16,185,129,.35);
  margin-left:.35rem;
}
hr { border: none; border-top: 1px solid rgba(255,255,255,.08); margin: .9rem 0; }
.small { color: rgba(255,255,255,.65); font-size: .9rem; }
</style>
"""
st.set_page_config(page_title="KR_TGM", layout="wide")
st.markdown(CSS, unsafe_allow_html=True)


# =========================
# DB helpers (psycopg v3)
# =========================
def db_connect():
    if not DB_URL:
        raise RuntimeError("Falta DB_URL en Secrets.")
    # row_factory=dict_row => fetch devuelve dict
    return psycopg.connect(DB_URL, row_factory=dict_row)

def db_exec(sql: str, params=None):
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
        conn.commit()

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


# =========================
# Schema / migrations (safe)
# =========================
def ensure_schema():
    """
    Crea/ajusta tablas sin borrar datos:
    - users (id, username, password_hash, role, nombre, is_active, created_at)
    - machines (id_maquina PK, serie, fabricante, modelo, juego, sector, banco, estado, notas, updated_at)
    - maintenance (id, id_maquina FK, fecha, tipo, tecnico, descripcion, falla, diagnostico, accion, repuestos,
                   estado_final, link_adjuntos, created_at)
    """
    # USERS
    db_exec("""
    create table if not exists public.users (
      id bigserial primary key,
      username text unique not null,
      password_hash text not null,
      role text not null check (role in ('tecnico','supervisor','admin')),
      nombre text,
      is_active boolean not null default true,
      created_at timestamp not null default now()
    );
    """)

    # MACHINES (con PK en id_maquina)
    db_exec("""
    create table if not exists public.machines (
      id_maquina integer primary key,
      serie text,
      fabricante text,
      modelo text,
      juego text,
      sector text,
      banco text,
      estado text default 'Operativa',
      notas text,
      updated_at timestamp not null default now()
    );
    """)

    # Asegurar columnas si venías de versiones anteriores
    # (IF NOT EXISTS en ALTER COLUMN no existe, así que vamos por CREATE/ALTER simple y tolerante)
    # Para evitar errores si ya existen, usamos DO blocks.
    db_exec("""
    do $$
    begin
      if not exists (select 1 from information_schema.columns where table_schema='public' and table_name='machines' and column_name='serie') then
        alter table public.machines add column serie text;
      end if;
      if not exists (select 1 from information_schema.columns where table_schema='public' and table_name='machines' and column_name='juego') then
        alter table public.machines add column juego text;
      end if;
      if not exists (select 1 from information_schema.columns where table_schema='public' and table_name='machines' and column_name='sector') then
        alter table public.machines add column sector text;
      end if;
      if not exists (select 1 from information_schema.columns where table_schema='public' and table_name='machines' and column_name='banco') then
        alter table public.machines add column banco text;
      end if;
      if not exists (select 1 from information_schema.columns where table_schema='public' and table_name='machines' and column_name='estado') then
        alter table public.machines add column estado text default 'Operativa';
      end if;
      if not exists (select 1 from information_schema.columns where table_schema='public' and table_name='machines' and column_name='notas') then
        alter table public.machines add column notas text;
      end if;
      if not exists (select 1 from information_schema.columns where table_schema='public' and table_name='machines' and column_name='updated_at') then
        alter table public.machines add column updated_at timestamp not null default now();
      end if;
    end $$;
    """)

    # MAINTENANCE
    db_exec("""
    create table if not exists public.maintenance (
      id bigserial primary key,
      id_maquina integer not null references public.machines(id_maquina) on delete cascade,
      fecha date not null,
      tipo text not null,
      tecnico text,
      descripcion text,
      falla text,
      diagnostico text,
      accion text,
      repuestos text,
      estado_final text,
      link_adjuntos text,
      created_at timestamp not null default now()
    );
    """)

def tables_exist():
    # Verifica tablas en schema public (users puede existir también en auth, pero la nuestra es public.users)
    row = db_fetchone("""
      select
        to_regclass('public.users') as users,
        to_regclass('public.machines') as machines,
        to_regclass('public.maintenance') as maintenance
    """)
    return bool(row and row["users"] and row["machines"] and row["maintenance"])


# =========================
# Auth (bcrypt)
# =========================
def bcrypt_check(password_plain: str, bcrypt_hash: str) -> bool:
    if not password_plain or not bcrypt_hash:
        return False
    try:
        return bcrypt.checkpw(password_plain.encode("utf-8"), bcrypt_hash.encode("utf-8"))
    except Exception:
        return False

def bcrypt_hash(password_plain: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password_plain.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def get_user(username: str):
    return db_fetchone("select * from public.users where username=%s and is_active=true", (username,))

def require_login():
    if "auth" not in st.session_state:
        st.session_state.auth = {"logged": False, "username": None, "role": None, "nombre": None}
    return st.session_state.auth["logged"]

def login_user(user_row):
    st.session_state.auth = {
        "logged": True,
        "username": user_row["username"],
        "role": user_row["role"],
        "nombre": user_row.get("nombre") or user_row["username"],
    }

def logout_user():
    st.session_state.auth = {"logged": False, "username": None, "role": None, "nombre": None}
    st.query_params["page"] = "Login"


# =========================
# Pages
# =========================
def page_login():
    st.subheader("🔐 Login")

    with st.form("login_form", clear_on_submit=False):
        username = st.text_input("Usuario", placeholder="cristian").strip().lower()
        password = st.text_input("Contraseña", type="password")
        ok = st.form_submit_button("Ingresar")

    if ok:
        u = get_user(username)
        if not u:
            st.error("Usuario no existe o está inactivo.")
            return
        if not bcrypt_check(password, u["password_hash"]):
            st.error("Usuario o contraseña incorrecta.")
            return
        login_user(u)
        st.success("Ingreso correcto ✅")
        st.query_params["page"] = "Máquinas"
        st.rerun()


def page_machines():
    st.subheader("🖥️ Máquinas")

    # Selector búsqueda
    colA, colB = st.columns([2, 3])
    with colA:
        id_busca = st.text_input("Buscar por ID Máquina", placeholder="32345").strip()
    with colB:
        st.caption("Tip: escribe un ID y presiona Enter. Si no existe, puedes crearla abajo.")

    machine = None
    if id_busca:
        if id_busca.isdigit():
            machine = db_fetchone("select * from public.machines where id_maquina=%s", (int(id_busca),))
        else:
            st.warning("El ID Máquina debe ser numérico.")

    with st.form("machine_form", clear_on_submit=False):
        col1, col2 = st.columns([1, 2])

        with col1:
            id_maquina = st.text_input("ID Máquina", value=str(machine["id_maquina"]) if machine else (id_busca if id_busca.isdigit() else ""))
            serie = st.text_input("Serie", value=machine["serie"] if machine else "")
            estado = st.selectbox("Estado", ESTADOS_MAQUINA, index=(ESTADOS_MAQUINA.index(machine["estado"]) if machine and machine.get("estado") in ESTADOS_MAQUINA else 0))
        with col2:
            fabricante = st.text_input("Fabricante", value=machine["fabricante"] if machine else "")
            modelo = st.text_input("Modelo", value=machine["modelo"] if machine else "")
            juego = st.text_input("Juego", value=machine["juego"] if machine else "")
            sector = st.text_input("Sector", value=machine["sector"] if machine else "")
            banco = st.text_input("Banco", value=machine["banco"] if machine else "")

        notas = st.text_area("Notas", value=machine["notas"] if machine else "", height=90)

        colS1, colS2, colS3 = st.columns([1,1,2])
        with colS1:
            guardar = st.form_submit_button("💾 Guardar / Actualizar")
        with colS2:
            borrar = st.form_submit_button("🗑️ Eliminar")
        with colS3:
            st.caption("Eliminar borra la máquina y su historial (mantenciones) por FK cascade.")

    # acciones form
    if guardar:
        if not id_maquina.strip().isdigit():
            st.error("ID Máquina debe ser numérico.")
            return
        mid = int(id_maquina.strip())

        db_exec("""
        insert into public.machines (id_maquina, serie, fabricante, modelo, juego, sector, banco, estado, notas, updated_at)
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
        """, (mid, serie, fabricante, modelo, juego, sector, banco, estado, notas))
        st.success("Máquina guardada ✅")
        st.query_params["page"] = "Máquinas"
        st.rerun()

    if borrar:
        if not st.session_state.auth["role"] in ("admin", "supervisor"):
            st.error("Solo admin/supervisor puede eliminar.")
            return
        if not id_maquina.strip().isdigit():
            st.error("ID Máquina debe ser numérico.")
            return
        mid = int(id_maquina.strip())
        db_exec("delete from public.machines where id_maquina=%s", (mid,))
        st.warning("Máquina eliminada.")
        st.query_params["page"] = "Máquinas"
        st.rerun()

    st.divider()
    st.markdown("### 📋 Listado (últimas 50)")
    rows = db_fetchall("""
      select id_maquina, serie, fabricante, modelo, juego, sector, banco, estado, updated_at
      from public.machines
      order by updated_at desc
      limit 50
    """)
    if rows:
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.info("Aún no hay máquinas registradas.")


def page_register_maintenance():
    st.subheader("📝 Registrar Mantención")

    machines = db_fetchall("select id_maquina, fabricante, modelo, juego, sector, banco, estado from public.machines order by id_maquina asc")
    if not machines:
        st.warning("Primero debes crear al menos 1 máquina en la pestaña Máquinas.")
        return

    # selector
    options = [m["id_maquina"] for m in machines]
    def fmt(mid):
        m = next((x for x in machines if x["id_maquina"] == mid), None)
        if not m:
            return str(mid)
        return f'{mid} • {m.get("fabricante","")} {m.get("modelo","")} • {m.get("sector","")} • {m.get("estado","")}'

    with st.form("maint_form", clear_on_submit=True):
        id_maquina = st.selectbox("Máquina", options=options, format_func=fmt)
        col1, col2, col3 = st.columns([1,1,1])
        with col1:
            fecha = st.date_input("Fecha", value=date.today())
        with col2:
            tipo = st.selectbox("Tipo", TIPOS_MANTENCION)
        with col3:
            tecnico = st.text_input("Técnico", value=st.session_state.auth.get("nombre") or st.session_state.auth.get("username"))

        descripcion = st.text_area("Descripción / Observación", height=90)
        colA, colB = st.columns(2)
        with colA:
            falla = st.text_area("Falla", height=80)
            diagnostico = st.text_area("Diagnóstico", height=80)
        with colB:
            accion = st.text_area("Acción realizada", height=80)
            repuestos = st.text_area("Repuestos", height=80)

        estado_final = st.selectbox("Estado final máquina", ESTADOS_MAQUINA)
        link_adjuntos = st.text_input("Link adjuntos (Drive/Sharepoint/etc.)", placeholder="https://...")

        guardar = st.form_submit_button("Guardar Mantención")

    if guardar:
        db_exec("""
        insert into public.maintenance
        (id_maquina, fecha, tipo, tecnico, descripcion, falla, diagnostico, accion, repuestos, estado_final, link_adjuntos)
        values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (id_maquina, fecha, tipo, tecnico, descripcion, falla, diagnostico, accion, repuestos, estado_final, link_adjuntos))

        # opcional: actualizar estado máquina si cambió
        db_exec("update public.machines set estado=%s, updated_at=now() where id_maquina=%s", (estado_final, id_maquina))

        st.success("Mantención guardada ✅")
        st.rerun()


def page_history():
    st.subheader("📚 Historial por Máquina")

    colA, colB, colC = st.columns([1, 1, 2])
    with colA:
        id_str = st.text_input("ID Máquina", placeholder="32345").strip()
    with colB:
        tipo = st.selectbox("Filtrar tipo", ["(Todos)"] + TIPOS_MANTENCION)
    with colC:
        limit = st.slider("Máximo de registros", 10, 500, 100)

    if not id_str:
        st.info("Ingresa un ID de máquina para ver historial.")
        return
    if not id_str.isdigit():
        st.error("ID Máquina debe ser numérico.")
        return

    mid = int(id_str)
    m = db_fetchone("select * from public.machines where id_maquina=%s", (mid,))
    if not m:
        st.warning("No existe esa máquina en la base.")
        return

    st.markdown(
        f"**Máquina {mid}** • {m.get('fabricante','')} {m.get('modelo','')} • "
        f"{m.get('juego','')} • {m.get('sector','')} • **{m.get('estado','')}**"
    )

    if tipo == "(Todos)":
        rows = db_fetchall("""
          select id, fecha, tipo, tecnico, descripcion, falla, diagnostico, accion, repuestos, estado_final, link_adjuntos, created_at
          from public.maintenance
          where id_maquina=%s
          order by fecha desc, id desc
          limit %s
        """, (mid, limit))
    else:
        rows = db_fetchall("""
          select id, fecha, tipo, tecnico, descripcion, falla, diagnostico, accion, repuestos, estado_final, link_adjuntos, created_at
          from public.maintenance
          where id_maquina=%s and tipo=%s
          order by fecha desc, id desc
          limit %s
        """, (mid, tipo, limit))

    if not rows:
        st.info("No hay mantenciones registradas para esta máquina.")
        return

    st.dataframe(rows, use_container_width=True, hide_index=True)

    st.markdown("### 🔎 Detalle rápido")
    # mostrar el último registro
    last = rows[0]
    st.write(
        f"**Última:** {last['fecha']} • {last['tipo']} • {last.get('tecnico','')} • "
        f"**Estado final:** {last.get('estado_final','')}"
    )
    if last.get("link_adjuntos"):
        st.write(f"**Adjuntos:** {last['link_adjuntos']}")


def page_users():
    st.subheader("👥 Usuarios")
    if st.session_state.auth["role"] != "admin":
        st.error("Solo admin puede administrar usuarios.")
        return

    st.markdown("### Crear usuario")
    with st.form("create_user", clear_on_submit=True):
        username = st.text_input("Username (minúsculas)", placeholder="tecnico1").strip().lower()
        nombre = st.text_input("Nombre", placeholder="Juan Pérez").strip()
        role = st.selectbox("Rol", ["tecnico", "supervisor", "admin"])
        password = st.text_input("Contraseña", type="password")
        password2 = st.text_input("Repetir contraseña", type="password")
        create = st.form_submit_button("Crear")

    if create:
        if not username or not re.match(r"^[a-z0-9._-]{3,40}$", username):
            st.error("Username inválido. Usa 3-40 chars: a-z 0-9 . _ -")
            return
        if password != password2 or len(password) < 6:
            st.error("Contraseña inválida o no coincide (mínimo 6).")
            return

        ph = bcrypt_hash(password)
        try:
            db_exec("""
              insert into public.users (username, password_hash, role, nombre, is_active)
              values (%s,%s,%s,%s,true)
            """, (username, ph, role, nombre))
            st.success("Usuario creado ✅")
        except Exception as e:
            st.error(f"No se pudo crear usuario: {e}")

    st.divider()
    st.markdown("### Lista usuarios")
    rows = db_fetchall("select id, username, role, nombre, is_active, created_at from public.users order by id asc")
    st.dataframe(rows, use_container_width=True, hide_index=True)


# =========================
# Sidebar nav (links con ?page=)
# =========================
def sidebar_nav(active_page: str):
    st.sidebar.markdown(f"<div class='sidebar-title'>Navegación</div>", unsafe_allow_html=True)

    auth = st.session_state.get("auth", {"logged": False})
    logged = auth.get("logged", False)
    role = auth.get("role")
    nombre = auth.get("nombre")

    if logged:
        st.sidebar.markdown(f"<div class='small'>👤 {nombre} <span class='badge'>{role}</span></div>", unsafe_allow_html=True)
        if st.sidebar.button("Cerrar sesión"):
            logout_user()
            st.rerun()
        st.sidebar.markdown("<hr/>", unsafe_allow_html=True)

    def link(label: str, page: str, require_auth=False, admin_only=False):
        if require_auth and not logged:
            return
        if admin_only and role != "admin":
            return
        cls = "navlink active" if page == active_page else "navlink"
        st.sidebar.markdown(f"<div class='navbox'><a class='{cls}' href='?page={page}'>{label}</a></div>", unsafe_allow_html=True)

    # Orden de opciones
    link("🔐 Login", "Login", require_auth=False)
    link("🖥️ Máquinas", "Máquinas", require_auth=True)
    link("📝 Registrar", "Registrar", require_auth=True)
    link("📚 Historial", "Historial", require_auth=True)
    link("👥 Usuarios", "Usuarios", require_auth=True, admin_only=True)


# =========================
# Main
# =========================
def main():
    st.title(APP_TITLE)

    if not DB_URL:
        st.error("❌ Falta DB_URL en Secrets de Streamlit Cloud. Ve a Settings → Secrets y agrega DB_URL.")
        st.stop()

    # Asegurar schema
    try:
        ensure_schema()
    except Exception as e:
        st.error(f"❌ No se pudo preparar la base de datos: {e}")
        st.stop()

    # páginas por query param
    page = st.query_params.get("page", "Login")
    sidebar_nav(page)

    # auth gate
    logged = require_login()

    if page != "Login" and not logged:
        st.warning("Debes iniciar sesión para continuar.")
        page_login()
        return

    # Render
    if page == "Login":
        page_login()
    elif page == "Máquinas":
        page_machines()
    elif page == "Registrar":
        page_register_maintenance()
    elif page == "Historial":
        page_history()
    elif page == "Usuarios":
        page_users()
    else:
        st.info("Página no encontrada. Volviendo a Login…")
        st.query_params["page"] = "Login"
        st.rerun()


if __name__ == "__main__":
    main()
