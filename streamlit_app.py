import os
import io
import csv
from datetime import datetime, date

import streamlit as st
import psycopg
from psycopg2.extras import RealDictCursor
from passlib.context import CryptContext

# =========================
# CONFIG
# =========================
APP_TITLE = "🛠️ KR_TGM • Mantenciones e Historial"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ESTADOS_MAQUINA = ["Operativa", "Fuera de Servicio", "En Mantención", "En Prueba", "Baja", "Otro"]
TIPOS_MANTENCION = ["Preventiva", "Correctiva", "Inspección", "Otro"]

st.set_page_config(page_title="KR_TGM", page_icon="🛠️", layout="wide")

# =========================
# STYLE (MENÚ VISUAL + SIN DEBUG)
# =========================
st.markdown(
    """
<style>
section[data-testid="stSidebar"] { background: #0f1117; }
section[data-testid="stSidebar"] .block-container { padding-top: 1.0rem; }

.kr-usercard {
  border: 1px solid rgba(255,255,255,0.10);
  background: rgba(255,255,255,0.05);
  padding: 10px 12px;
  border-radius: 12px;
  margin-bottom: 10px;
}
.kr-usercard b { font-size: 0.95rem; }

.kr-nav-title { color: rgba(255,255,255,0.75); font-size: 0.9rem; margin-top: 8px; margin-bottom: 6px; }

.kr-navbtn button {
  width: 100%;
  text-align: left;
  border-radius: 12px !important;
  padding: 10px 12px !important;
  border: 1px solid rgba(255,255,255,0.10) !important;
  background: rgba(255,255,255,0.04) !important;
}
.kr-navbtn button:hover {
  border-color: rgba(255,255,255,0.22) !important;
  background: rgba(255,255,255,0.08) !important;
}
.kr-navbtn-selected button {
  width: 100%;
  text-align: left;
  border-radius: 12px !important;
  padding: 10px 12px !important;
  border: 1px solid rgba(255,255,255,0.28) !important;
  background: rgba(255,255,255,0.16) !important;
  font-weight: 800 !important;
}

.kr-logout button {
  width: 100%;
  border-radius: 12px !important;
  padding: 10px 12px !important;
  background: rgba(255,70,70,0.16) !important;
  border: 1px solid rgba(255,70,70,0.30) !important;
}
.kr-logout button:hover { background: rgba(255,70,70,0.22) !important; }

h1, h2, h3 { letter-spacing: 0.2px; }
</style>
""",
    unsafe_allow_html=True,
)

# =========================
# SECRETS / DB
# =========================
def get_secret(key: str, default=None):
    if key in st.secrets:
        return st.secrets.get(key)
    return os.environ.get(key, default)

def get_db_url() -> str:
    db_url = get_secret("DB_URL")
    if not db_url:
        raise RuntimeError("Falta DB_URL en Secrets.")
    return db_url

@st.cache_resource
def db_connect():
    return psycopg2.connect(get_db_url())

def db_fetchone(sql: str, params=None):
    conn = db_connect()
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params or ())
        return cur.fetchone()

def db_fetchall(sql: str, params=None):
    conn = db_connect()
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params or ())
        return cur.fetchall()

def db_execute(sql: str, params=None):
    conn = db_connect()
    with conn.cursor() as cur:
        cur.execute(sql, params or ())
    conn.commit()

def tables_exist() -> bool:
    try:
        row = db_fetchone(
            """
            select
              to_regclass('public.users') is not null as users_ok,
              to_regclass('public.machines') is not null as machines_ok,
              to_regclass('public.maintenance') is not null as maintenance_ok
            """
        )
        return bool(row and row["users_ok"] and row["machines_ok"] and row["maintenance_ok"])
    except Exception:
        return False

# =========================
# AUTH
# =========================
def is_logged_in() -> bool:
    return bool(st.session_state.get("user"))

def current_user():
    return st.session_state.get("user")

def logout():
    st.session_state["user"] = None
    st.session_state["page"] = "Login"
    st.rerun()

def verify_password(plain: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(plain, password_hash)
    except Exception:
        return False

def login_user(username: str, password: str):
    u = db_fetchone(
        "select id, username, password_hash, role, nombre, is_active from public.users where username=%s",
        (username.strip().lower(),),
    )
    if not u or not u.get("is_active"):
        return False, "Usuario no existe o está desactivado."
    if not verify_password(password, u["password_hash"]):
        return False, "Contraseña incorrecta."
    st.session_state["user"] = {
        "id": u["id"],
        "username": u["username"],
        "role": u["role"],
        "nombre": u.get("nombre") or u["username"],
    }
    return True, None

def require_admin():
    u = current_user()
    return bool(u and u.get("role") == "admin")

# =========================
# SIDEBAR NAV
# =========================
def nav_button(label: str, page_name: str, icon: str):
    selected = st.session_state.get("page", "Login") == page_name
    cls = "kr-navbtn-selected" if selected else "kr-navbtn"
    st.markdown(f'<div class="{cls}">', unsafe_allow_html=True)
    if st.button(f"{icon}  {label}", use_container_width=True):
        st.session_state["page"] = page_name
        st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)

def render_sidebar():
    with st.sidebar:
        st.markdown("### Navegación")

        if not tables_exist():
            st.error("No se pudo verificar DB/tablas. Revisa DB_URL / conexión.")

        u = current_user()
        if u:
            st.markdown(
                f"""
<div class="kr-usercard">
<b>{u["nombre"]}</b><br/>
<span style="color:rgba(255,255,255,0.70)">@{u["username"]} • {u["role"]}</span>
</div>
""",
                unsafe_allow_html=True,
            )
            st.markdown('<div class="kr-logout">', unsafe_allow_html=True)
            if st.button("🚪 Cerrar sesión", use_container_width=True):
                logout()
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<div class="kr-nav-title">Ir a:</div>', unsafe_allow_html=True)
        nav_button("Login", "Login", "🔐")
        nav_button("Máquinas", "Máquinas", "🖥️")
        nav_button("Registrar Mantención", "Registrar", "📝")
        nav_button("Historial", "Historial", "📚")
        nav_button("Usuarios", "Usuarios", "👥")

# =========================
# UTIL: CSV
# =========================
MACHINE_COLS = ["id_maquina", "serie", "fabricante", "modelo", "juego", "sector", "banco", "estado", "notas"]

def machines_to_csv(rows):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=MACHINE_COLS)
    writer.writeheader()
    for r in rows:
        writer.writerow({k: r.get(k, "") for k in MACHINE_COLS})
    return output.getvalue().encode("utf-8")

def parse_csv_bytes(file_bytes: bytes):
    text = file_bytes.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))
    cols = [c.strip() for c in reader.fieldnames or []]
    missing = [c for c in MACHINE_COLS if c not in cols]
    if missing:
        raise ValueError(f"CSV inválido. Faltan columnas: {missing}")
    rows = []
    for row in reader:
        rows.append({k: (row.get(k) or "").strip() for k in MACHINE_COLS})
    return rows

# =========================
# PAGES
# =========================
def page_login():
    st.subheader("🔐 Login")
    col1, col2 = st.columns([1, 1])
    with col1:
        username = st.text_input("Usuario", placeholder="cristian")
    with col2:
        password = st.text_input("Contraseña", type="password", placeholder="••••••••")

    if st.button("Ingresar", type="primary"):
        if not username.strip() or not password:
            st.error("Completa usuario y contraseña.")
            return
        ok, err = login_user(username, password)
        if ok:
            st.success("Login correcto.")
            st.session_state["page"] = "Máquinas"
            st.rerun()
        else:
            st.error(err or "No se pudo iniciar sesión.")

def page_machines():
    if not is_logged_in():
        st.warning("Debes iniciar sesión.")
        return

    st.subheader("🖥️ Máquinas")

    # Filtros
    with st.expander("🔎 Buscar / Filtrar", expanded=True):
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            f_id = st.text_input("ID (exacto o parte)", placeholder="32045")
        with c2:
            f_fab = st.text_input("Fabricante", placeholder="ATRONIC")
        with c3:
            f_sector = st.text_input("Sector", placeholder="TERRAZA")
        with c4:
            f_estado = st.selectbox("Estado", ["(Todos)"] + ESTADOS_MAQUINA)

        c5, c6 = st.columns(2)
        with c5:
            f_modelo = st.text_input("Modelo", placeholder="EMOTION")
        with c6:
            f_banco = st.text_input("Banco", placeholder="TE-05")

    # Cargar lista
    rows = db_fetchall("select * from public.machines order by id_maquina asc")
    # filtrar en memoria
    def match(row):
        if f_id.strip():
            if f_id.strip() not in str(row.get("id_maquina", "")):
                return False
        if f_fab.strip() and f_fab.strip().lower() not in (row.get("fabricante") or "").lower():
            return False
        if f_sector.strip() and f_sector.strip().lower() not in (row.get("sector") or "").lower():
            return False
        if f_modelo.strip() and f_modelo.strip().lower() not in (row.get("modelo") or "").lower():
            return False
        if f_banco.strip() and f_banco.strip().lower() not in (row.get("banco") or "").lower():
            return False
        if f_estado != "(Todos)" and (row.get("estado") or "") != f_estado:
            return False
        return True

    filtered = [r for r in rows if match(r)]

    # Acciones CSV
    colA, colB, colC = st.columns([1, 1, 2])
    with colA:
        st.download_button(
            "⬇️ Descargar CSV (máquinas filtradas)",
            data=machines_to_csv(filtered),
            file_name="machines_export.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with colB:
        up = st.file_uploader("📤 Importar CSV", type=["csv"], label_visibility="collapsed")
    with colC:
        st.caption("CSV debe traer columnas: id_maquina, serie, fabricante, modelo, juego, sector, banco, estado, notas")

    if up is not None:
        try:
            incoming = parse_csv_bytes(up.getvalue())
            count = 0
            for r in incoming:
                # normalizar
                mid = int(r["id_maquina"]) if str(r["id_maquina"]).strip().isdigit() else None
                if not mid:
                    continue
                estado = r["estado"] if r["estado"] in ESTADOS_MAQUINA else "Operativa"
                db_execute(
                    """
                    insert into public.machines
                      (id_maquina, serie, fabricante, modelo, juego, sector, banco, estado, notas)
                    values
                      (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    on conflict (id_maquina) do update set
                      serie=excluded.serie,
                      fabricante=excluded.fabricante,
                      modelo=excluded.modelo,
                      juego=excluded.juego,
                      sector=excluded.sector,
                      banco=excluded.banco,
                      estado=excluded.estado,
                      notas=excluded.notas
                    """,
                    (
                        mid,
                        r["serie"],
                        r["fabricante"],
                        r["modelo"],
                        r["juego"],
                        r["sector"],
                        r["banco"],
                        estado,
                        r["notas"],
                    ),
                )
                count += 1
            st.success(f"✅ Importación lista. Filas procesadas: {count}")
            st.rerun()
        except Exception as e:
            st.error(f"Error importando CSV: {e}")

    st.divider()

    # Tabla + acciones
    st.markdown("### 📋 Lista de máquinas")
    if not filtered:
        st.info("No hay máquinas con esos filtros.")
        return

    # selector para editar / ver historial
    ids = [r["id_maquina"] for r in filtered]
    csel1, csel2 = st.columns([1, 1])
    with csel1:
        selected_id = st.selectbox("Selecciona una máquina para ver / editar", ids)
    with csel2:
        quick = st.button("📚 Ver historial de la seleccionada", use_container_width=True)

    if quick:
        st.session_state["history_id"] = int(selected_id)
        st.session_state["page"] = "Historial"
        st.rerun()

    machine = db_fetchone("select * from public.machines where id_maquina=%s", (int(selected_id),))

    st.divider()
    st.markdown("### ✏️ Editar máquina")

    with st.form("machine_form", clear_on_submit=False):
        c1, c2 = st.columns(2)
        with c1:
            id_maquina = st.number_input("ID Máquina", min_value=1, step=1, value=int(machine["id_maquina"]))
            serie = st.text_input("Serie", value=machine.get("serie") or "")
            estado = st.selectbox(
                "Estado",
                ESTADOS_MAQUINA,
                index=ESTADOS_MAQUINA.index(machine.get("estado")) if machine.get("estado") in ESTADOS_MAQUINA else 0,
            )
        with c2:
            fabricante = st.text_input("Fabricante", value=machine.get("fabricante") or "")
            modelo = st.text_input("Modelo", value=machine.get("modelo") or "")
            juego = st.text_input("Juego", value=machine.get("juego") or "")

        c3, c4 = st.columns(2)
        with c3:
            sector = st.text_input("Sector", value=machine.get("sector") or "")
        with c4:
            banco = st.text_input("Banco", value=machine.get("banco") or "")

        notas = st.text_area("Notas", value=machine.get("notas") or "", height=120)
        submitted = st.form_submit_button("💾 Guardar / Actualizar", type="primary")

    if submitted:
        try:
            db_execute(
                """
                update public.machines
                set serie=%s, fabricante=%s, modelo=%s, juego=%s, sector=%s, banco=%s, estado=%s, notas=%s
                where id_maquina=%s
                """,
                (serie, fabricante, modelo, juego, sector, banco, estado, notas, int(id_maquina)),
            )
            st.success("✅ Máquina actualizada.")
            st.rerun()
        except Exception as e:
            st.error(f"Error actualizando máquina: {e}")

def page_register_maintenance():
    if not is_logged_in():
        st.warning("Debes iniciar sesión.")
        return

    st.subheader("📝 Registrar Mantención")

    u = current_user()
    with st.form("maint_form", clear_on_submit=True):
        c1, c2, c3 = st.columns(3)
        with c1:
            id_maquina = st.number_input("ID Máquina", min_value=1, step=1, value=1)
            tipo = st.selectbox("Tipo", TIPOS_MANTENCION)
        with c2:
            fecha = st.date_input("Fecha", value=date.today())
            estado_final = st.selectbox("Estado final", ESTADOS_MAQUINA)
        with c3:
            tecnico = st.text_input("Técnico", value=u["nombre"])

        falla = st.text_input("Falla / Síntoma")
        diagnostico = st.text_area("Diagnóstico", height=110)
        accion = st.text_area("Acción realizada", height=110)
        repuestos = st.text_input("Repuestos")
        link_adjuntos = st.text_input("Link adjuntos (opcional)")

        ok = st.form_submit_button("✅ Guardar registro", type="primary")

    if ok:
        try:
            m = db_fetchone("select id_maquina from public.machines where id_maquina=%s", (int(id_maquina),))
            if not m:
                st.error("⚠️ Esa máquina no existe. Primero créala en 'Máquinas'.")
                return

            db_execute(
                """
                insert into public.maintenance
                  (id_maquina, fecha, tipo, estado_final, falla, diagnostico, accion, repuestos, link_adjuntos, tecnico, created_at)
                values
                  (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, now())
                """,
                (
                    int(id_maquina),
                    fecha,
                    tipo,
                    estado_final,
                    falla,
                    diagnostico,
                    accion,
                    repuestos,
                    link_adjuntos,
                    tecnico,
                ),
            )
            st.success("✅ Mantención registrada.")
        except Exception as e:
            st.error(f"Error guardando mantención: {e}")

def page_history():
    if not is_logged_in():
        st.warning("Debes iniciar sesión.")
        return

    st.subheader("📚 Historial por Máquina")

    default_id = st.session_state.get("history_id", "")
    colA, colB, colC = st.columns([1, 1, 2])
    with colA:
        id_str = st.text_input("ID Máquina", value=str(default_id) if default_id else "", placeholder="32045")
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
    st.session_state["history_id"] = mid

    m = db_fetchone("select * from public.machines where id_maquina=%s", (mid,))
    if not m:
        st.warning("No existe esa máquina en la base.")
        return

    st.markdown(
        f"""
**Máquina {m["id_maquina"]}** • **{m.get("fabricante","")}** • **{m.get("modelo","")}** • **{m.get("juego","")}**  
Sector: **{m.get("sector","")}** • Banco: **{m.get("banco","")}** • Estado: **{m.get("estado","")}**
""".strip()
    )

    if tipo == "(Todos)":
        rows = db_fetchall(
            """
            select *
            from public.maintenance
            where id_maquina=%s
            order by fecha desc, created_at desc
            limit %s
            """,
            (mid, int(limit)),
        )
    else:
        rows = db_fetchall(
            """
            select *
            from public.maintenance
            where id_maquina=%s and tipo=%s
            order by fecha desc, created_at desc
            limit %s
            """,
            (mid, tipo, int(limit)),
        )

    if not rows:
        st.info("No hay registros de mantención para esta máquina.")
        return

    show = []
    for r in rows:
        show.append(
            {
                "Fecha": r.get("fecha"),
                "Tipo": r.get("tipo"),
                "Técnico": r.get("tecnico"),
                "Estado final": r.get("estado_final"),
                "Falla": r.get("falla"),
                "Diagnóstico": r.get("diagnostico"),
                "Acción": r.get("accion"),
                "Repuestos": r.get("repuestos"),
                "Adjuntos": r.get("link_adjuntos"),
            }
        )

    st.dataframe(show, use_container_width=True, hide_index=True)

def page_users():
    if not is_logged_in():
        st.warning("Debes iniciar sesión.")
        return
    if not require_admin():
        st.error("Solo admin puede ver/gestionar usuarios.")
        return

    st.subheader("👥 Usuarios")

    users = db_fetchall("select id, username, role, nombre, is_active, created_at from public.users order by id asc")
    st.dataframe(users, use_container_width=True, hide_index=True)

    st.divider()
    st.markdown("### ➕ Crear usuario")

    with st.form("create_user", clear_on_submit=True):
        c1, c2, c3 = st.columns(3)
        with c1:
            username = st.text_input("Username", placeholder="tecnico1")
        with c2:
            nombre = st.text_input("Nombre", placeholder="Juan Pérez")
        with c3:
            role = st.selectbox("Rol", ["tecnico", "supervisor", "admin"], index=0)

        password = st.text_input("Contraseña", type="password")
        is_active = st.checkbox("Activo", value=True)

        ok = st.form_submit_button("Crear", type="primary")

    if ok:
        if not username.strip() or not password:
            st.error("Usuario y contraseña son obligatorios.")
            return
        try:
            u = username.strip().lower()
            pw_hash = pwd_context.hash(password)
            db_execute(
                """
                insert into public.users (username, password_hash, role, nombre, is_active, created_at)
                values (%s,%s,%s,%s,%s, now())
                """,
                (u, pw_hash, role, nombre, is_active),
            )
            st.success("✅ Usuario creado.")
            st.rerun()
        except Exception as e:
            st.error(f"Error creando usuario: {e}")

    st.divider()
    st.markdown("### 🔁 Reset contraseña de usuario")

    with st.form("reset_pw", clear_on_submit=True):
        user_to_reset = st.text_input("Username a resetear", placeholder="cristian")
        new_pw = st.text_input("Nueva contraseña", type="password")
        ok2 = st.form_submit_button("Actualizar", type="primary")

    if ok2:
        if not user_to_reset.strip() or not new_pw:
            st.error("Completa username y nueva contraseña.")
            return
        try:
            u = user_to_reset.strip().lower()
            pw_hash = pwd_context.hash(new_pw)
            db_execute("update public.users set password_hash=%s where username=%s", (pw_hash, u))
            st.success("✅ Contraseña actualizada.")
            st.rerun()
        except Exception as e:
            st.error(f"Error actualizando: {e}")

# =========================
# MAIN
# =========================
st.title(APP_TITLE)

if "page" not in st.session_state:
    st.session_state["page"] = "Login"
if "user" not in st.session_state:
    st.session_state["user"] = None

render_sidebar()

page = st.session_state.get("page", "Login")

if page != "Login" and not is_logged_in():
    st.session_state["page"] = "Login"
    page = "Login"

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
    st.session_state["page"] = "Login"
    st.rerun()
