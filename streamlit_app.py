import streamlit as st
import psycopg2
from psycopg2.extras import RealDictCursor
import pandas as pd
import bcrypt
from datetime import date

# =========================
# CONFIG UI
# =========================
st.set_page_config(page_title="KR_TGM • Mantenciones", page_icon="🛠️", layout="wide")
st.title("🛠️ KR_TGM • Mantenciones e Historial")

# =========================
# DB HELPERS
# =========================
def get_db_url() -> str:
    if "DB_URL" not in st.secrets:
        st.error("❌ Falta DB_URL en Secrets.")
        st.stop()
    return st.secrets["DB_URL"]

def db_conn():
    return psycopg2.connect(get_db_url(), cursor_factory=RealDictCursor)

def db_fetchall(sql, params=None):
    params = params or ()
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()

def db_fetchone(sql, params=None):
    params = params or ()
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()

def db_execute(sql, params=None):
    params = params or ()
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            conn.commit()

def tables_exist() -> bool:
    try:
        r = db_fetchone("""
            select
              to_regclass('public.users') as u,
              to_regclass('public.machines') as m,
              to_regclass('public.maintenance') as t
        """)
        # Debug temporal (puedes borrar luego)
        st.sidebar.caption(f"DEBUG to_regclass: {r}")
        return bool(r and r.get("u") and r.get("m") and r.get("t"))
    except Exception as e:
        st.sidebar.error(f"DEBUG tables_exist error: {e}")
        return False

# =========================
# AUTH
# =========================
def hash_password(p):
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()

def verify_password(p, h):
    return bcrypt.checkpw(p.encode(), h.encode())

def current_user():
    return st.session_state.get("user")

def require_login():
    if not current_user():
        show_login()
        st.stop()

def is_admin():
    u = current_user()
    return u and u["role"] == "admin"

def is_supervisor():
    u = current_user()
    return u and u["role"] in ("admin", "supervisor")

# =========================
# FIRST ADMIN
# =========================
def count_users():
    r = db_fetchone("select count(*)::int as c from public.users;")
    return r["c"]

def first_admin_setup():
    st.warning("No hay usuarios. Crea el primer ADMIN.")
    setup_key = st.secrets.get("SETUP_KEY")
    if not setup_key:
        st.error("Falta SETUP_KEY en Secrets.")
        st.stop()

    with st.form("first_admin"):
        k = st.text_input("SETUP_KEY", type="password")
        u = st.text_input("Usuario")
        n = st.text_input("Nombre")
        p1 = st.text_input("Contraseña", type="password")
        p2 = st.text_input("Repite contraseña", type="password")
        ok = st.form_submit_button("Crear ADMIN")

    if ok:
        if k != setup_key:
            st.error("SETUP_KEY incorrecta"); return
        if not u or not p1 or p1 != p2:
            st.error("Datos inválidos"); return

        db_execute(
            "insert into public.users (username,password_hash,role,nombre,is_active) values (%s,%s,'admin',%s,true);",
            (u.lower(), hash_password(p1), n)
        )
        st.success("Admin creado. Inicia sesión.")
        st.rerun()

# =========================
# LOGIN
# =========================
def show_login():
    st.subheader("🔐 Login")
    with st.form("login"):
        u = st.text_input("Usuario")
        p = st.text_input("Contraseña", type="password")
        ok = st.form_submit_button("Ingresar")

    if ok:
        r = db_fetchone("select * from public.users where username=%s and is_active=true;", (u.lower(),))
        if not r or not verify_password(p, r["password_hash"]):
            st.error("Credenciales incorrectas"); return
        st.session_state["user"] = {
            "id": r["id"], "username": r["username"],
            "role": r["role"], "nombre": r.get("nombre") or r["username"]
        }
        st.rerun()

# =========================
# USERS (ADMIN)
# =========================
def page_users():
    st.subheader("👥 Usuarios")
    if not is_admin():
        st.error("Solo Admin"); return

    df = pd.DataFrame(db_fetchall("select id,username,role,nombre,is_active from public.users order by id;"))
    st.dataframe(df, use_container_width=True, hide_index=True)

    with st.form("new_user"):
        u = st.text_input("Usuario")
        n = st.text_input("Nombre")
        r = st.selectbox("Rol", ["tecnico","supervisor","admin"])
        p = st.text_input("Contraseña", type="password")
        ok = st.form_submit_button("Crear")

    if ok:
        db_execute(
            "insert into public.users (username,password_hash,role,nombre,is_active) values (%s,%s,%s,%s,true);",
            (u.lower(), hash_password(p), r, n)
        )
        st.success("Usuario creado"); st.rerun()

# =========================
# MACHINES
# =========================
def upsert_machine(m):
    db_execute("""
        insert into public.machines (id_maquina,fabricante,modelo,denominacion,ubicacion,sector,estado,notas)
        values (%s,%s,%s,%s,%s,%s,%s,%s)
        on conflict (id_maquina) do update set
        fabricante=excluded.fabricante, modelo=excluded.modelo, denominacion=excluded.denominacion,
        ubicacion=excluded.ubicacion, sector=excluded.sector, estado=excluded.estado, notas=excluded.notas,
        updated_at=now();
    """, (
        m["id_maquina"], m.get("fabricante"), m.get("modelo"), m.get("denominacion"),
        m.get("ubicacion"), m.get("sector"), m.get("estado"), m.get("notas")
    ))

def page_machines():
    st.subheader("🎰 Máquinas")
    can_edit = is_supervisor()

    q = st.text_input("Buscar / ID")
    if q.isdigit():
        rows = db_fetchall("select * from public.machines where id_maquina=%s;", (int(q),))
    else:
        rows = db_fetchall("select * from public.machines order by id_maquina limit 100;")

    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    st.markdown("---")
    st.markdown("### Crear / Editar")
    with st.form("machine"):
        i = st.text_input("ID Máquina", disabled=not can_edit)
        fab = st.text_input("Fabricante", disabled=not can_edit)
        mod = st.text_input("Modelo", disabled=not can_edit)
        den = st.text_input("Juego", disabled=not can_edit)
        ubi = st.text_input("Ubicación", disabled=not can_edit)
        sec = st.text_input("Sector", disabled=not can_edit)
        est = st.selectbox("Estado", ["Operativa","Observación","Fuera de Servicio","Mantención"], disabled=not can_edit)
        nots = st.text_area("Notas", disabled=not can_edit)
        ok = st.form_submit_button("Guardar", disabled=not can_edit)

    if ok:
        upsert_machine({
            "id_maquina": int(i), "fabricante": fab, "modelo": mod, "denominacion": den,
            "ubicacion": ubi, "sector": sec, "estado": est, "notas": nots
        })
        st.success("Guardado"); st.rerun()

# =========================
# MAINTENANCE
# =========================
def page_new_maintenance():
    st.subheader("🧾 Registrar intervención")
    require_login()

    mid = st.text_input("ID Máquina")
    if not mid.isdigit():
        st.info("Ingresa ID"); return
    mid = int(mid)

    with st.form("maint"):
        tipo = st.selectbox("Tipo", ["Preventiva","Correctiva","Inspección","Otro"])
        fecha = st.date_input("Fecha", value=date.today())
        turno = st.selectbox("Turno", ["Día","Tarde","Noche","Otro"])
        falla = st.text_area("Falla")
        diag = st.text_area("Diagnóstico")
        acc = st.text_area("Acción")
        rep = st.text_input("Repuestos")
        est = st.selectbox("Estado final", ["Operativa","Observación","Fuera de Servicio","Escalada"])
        link = st.text_input("Link adjuntos")
        ok = st.form_submit_button("Guardar")

    if ok:
        u = current_user()
        db_execute("""
            insert into public.maintenance
            (id_maquina,tipo,fecha,turno,tecnico_username,tecnico_nombre,falla,diagnostico,accion,repuestos,estado_final,link_adjuntos,created_at)
            values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now());
        """, (mid,tipo,fecha,turno,u["username"],u["nombre"],falla,diag,acc,rep,est,link))
        st.success("Intervención guardada"); st.rerun()

def page_history():
    st.subheader("📚 Historial")

    mid = st.text_input("ID Máquina")
    if not mid.isdigit():
        st.info("Ingresa ID"); return
    mid = int(mid)

    rows = db_fetchall(
        "select * from public.maintenance where id_maquina=%s order by created_at desc limit 200;",
        (mid,)
    )

    if not rows:
        st.warning("Sin registros"); return

    df = pd.DataFrame(rows)

    cols = [
        "created_at","fecha","tipo","turno",
        "tecnico_nombre","tecnico_username",
        "estado_final","falla","diagnostico","accion",
        "repuestos","link_adjuntos"
    ]
    cols = [c for c in cols if c in df.columns]

    st.dataframe(df[cols], use_container_width=True, hide_index=True)

# =========================
# SIDEBAR
# =========================
with st.sidebar:
    st.markdown("### Navegación")

    if not tables_exist():
        st.error("❌ Tablas no existen"); st.stop()

    if count_users() == 0:
        first_admin_setup(); st.stop()

    u = current_user()
    if u:
        st.success(f"{u['nombre']} ({u['role']})")
        if st.button("Cerrar sesión"):
            st.session_state.pop("user"); st.rerun()

    page = st.radio("Ir a:", ["Login","Máquinas","Registrar","Historial","Usuarios"])

# =========================
# ROUTER
# =========================
try:
    if page == "Login":
        show_login()
    elif page == "Máquinas":
        require_login(); page_machines()
    elif page == "Registrar":
        require_login(); page_new_maintenance()
    elif page == "Historial":
        require_login(); page_history()
    elif page == "Usuarios":
        require_login(); page_users()

except Exception as e:
    st.error("Error:")
    st.code(str(e))
