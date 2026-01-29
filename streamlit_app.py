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

APP_TITLE = "🛠️ KR_TGM • Mantenciones e Historial"
st.title(APP_TITLE)

# =========================
# DB HELPERS
# =========================
def get_db_url() -> str:
    if "DB_URL" not in st.secrets:
        st.error("❌ Falta DB_URL en Secrets de Streamlit Cloud. Ve a Settings → Secrets y agrega DB_URL.")
        st.stop()
    return st.secrets["DB_URL"]

def db_conn():
    return psycopg2.connect(get_db_url(), cursor_factory=RealDictCursor)

def db_fetchall(sql: str, params=None):
    params = params or ()
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()

def db_fetchone(sql: str, params=None):
    params = params or ()
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()

def db_execute(sql: str, params=None):
    params = params or ()
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            conn.commit()

def tables_exist() -> bool:
    """
    Verifica EXISTENCIA REAL de las 3 tablas requeridas.
    Además, muestra un debug en sidebar con el resultado de to_regclass.
    """
    try:
        r = db_fetchone(
            """
            select
              to_regclass('public.users') as u,
              to_regclass('public.machines') as m,
              to_regclass('public.maintenance') as t
            """
        )
        # Debug visible (temporal)
        st.sidebar.caption(f"DEBUG to_regclass: {r}")
        return bool(r and r.get("u") and r.get("m") and r.get("t"))
    except Exception as e:
        st.sidebar.error(f"DEBUG tables_exist error: {e}")
        return False

# =========================
# AUTH HELPERS
# =========================
def hash_password(plain: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(plain.encode("utf-8"), salt).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def current_user():
    return st.session_state.get("user")

def require_login():
    if not current_user():
        st.info("🔒 Inicia sesión para continuar.")
        show_login()
        st.stop()

def is_admin() -> bool:
    u = current_user()
    return bool(u and u.get("role") == "admin")

def is_supervisor() -> bool:
    u = current_user()
    return bool(u and u.get("role") in ("admin", "supervisor"))

# =========================
# FIRST RUN SETUP (ADMIN)
# =========================
def count_users() -> int:
    r = db_fetchone("select count(*)::int as c from public.users;")
    return int(r["c"])

def show_first_admin_setup():
    st.warning("⚠️ No hay usuarios creados. Debes crear el primer ADMIN para habilitar el sistema.")
    st.caption("✅ Seguridad: para crear el primer admin debes definir `SETUP_KEY` en Secrets (Streamlit Cloud).")

    setup_key = st.secrets.get("SETUP_KEY", None)
    if not setup_key:
        st.error("Falta `SETUP_KEY` en Secrets. Agrégalo y vuelve a cargar la app.")
        st.stop()

    with st.form("first_admin"):
        k = st.text_input("SETUP_KEY", type="password")
        username = st.text_input("Usuario admin (ej: cristian)", max_chars=50)
        nombre = st.text_input("Nombre (opcional)", max_chars=100)
        password = st.text_input("Contraseña", type="password")
        password2 = st.text_input("Repetir contraseña", type="password")
        ok = st.form_submit_button("Crear ADMIN")

    if ok:
        if k != setup_key:
            st.error("SETUP_KEY incorrecta.")
            st.stop()
        if not username or not password:
            st.error("Usuario y contraseña son obligatorios.")
            st.stop()
        if password != password2:
            st.error("Las contraseñas no coinciden.")
            st.stop()

        ph = hash_password(password)
        try:
            db_execute(
                "insert into public.users (username, password_hash, role, nombre, is_active) values (%s,%s,%s,%s,true);",
                (username.lower().strip(), ph, "admin", nombre.strip() if nombre else None),
            )
            st.success("✅ Admin creado. Ahora inicia sesión.")
            st.rerun()
        except Exception as e:
            st.error(f"Error creando admin: {e}")

# =========================
# LOGIN UI
# =========================
def show_login():
    st.subheader("🔐 Login")

    col1, col2 = st.columns([1, 1])
    with col1:
        with st.form("login_form"):
            username = st.text_input("Usuario", max_chars=50)
            password = st.text_input("Contraseña", type="password")
            ok = st.form_submit_button("Ingresar")

        if ok:
            u = db_fetchone(
                "select id, username, password_hash, role, nombre, is_active from public.users where username=%s;",
                (username.lower().strip(),),
            )
            if not u or not u.get("is_active"):
                st.error("Usuario no existe o está desactivado.")
                return

            if not verify_password(password, u["password_hash"]):
                st.error("Contraseña incorrecta.")
                return

            st.session_state["user"] = {
                "id": u["id"],
                "username": u["username"],
                "role": u["role"],
                "nombre": u.get("nombre") or u["username"],
            }
            st.success("✅ Sesión iniciada.")
            st.rerun()

    with col2:
        st.info(
            "Roles:\n"
            "- **Técnico**: registra mantenciones\n"
            "- **Supervisor**: ve todo + gestiona maestro\n"
            "- **Admin**: todo + crea usuarios"
        )

def logout_button():
    if st.button("🚪 Cerrar sesión"):
        st.session_state.pop("user", None)
        st.rerun()

# =========================
# USERS ADMIN
# =========================
def page_users_admin():
    st.subheader("👥 Usuarios (Admin)")

    if not is_admin():
        st.error("Solo Admin puede gestionar usuarios.")
        return

    users = db_fetchall("select id, username, role, nombre, is_active, created_at from public.users order by id;")
    dfu = pd.DataFrame(users)
    if not dfu.empty:
        st.dataframe(dfu, use_container_width=True, hide_index=True)
    else:
        st.info("No hay usuarios.")

    st.markdown("---")
    st.markdown("### ➕ Crear usuario")

    with st.form("create_user"):
        username = st.text_input("Usuario", max_chars=50)
        nombre = st.text_input("Nombre", max_chars=100)
        role = st.selectbox("Rol", ["tecnico", "supervisor", "admin"])
        password = st.text_input("Contraseña", type="password")
        ok = st.form_submit_button("Crear")

    if ok:
        if not username or not password:
            st.error("Usuario y contraseña son obligatorios.")
            return
        try:
            db_execute(
                "insert into public.users (username, password_hash, role, nombre, is_active) values (%s,%s,%s,%s,true);",
                (username.lower().strip(), hash_password(password), role, nombre.strip() if nombre else None),
            )
            st.success("✅ Usuario creado.")
            st.rerun()
        except Exception as e:
            st.error(f"Error: {e}")

# =========================
# MACHINES
# =========================
def upsert_machine(m):
    db_execute(
        """
        insert into public.machines (id_maquina, fabricante, modelo, denominacion, ubicacion, sector, estado, notas)
        values (%s,%s,%s,%s,%s,%s,%s,%s)
        on conflict (id_maquina) do update set
          fabricante=excluded.fabricante,
          modelo=excluded.modelo,
          denominacion=excluded.denominacion,
          ubicacion=excluded.ubicacion,
          sector=excluded.sector,
          estado=excluded.estado,
          notas=excluded.notas,
          updated_at=now();
        """,
        (
            m["id_maquina"],
            m.get("fabricante"),
            m.get("modelo"),
            m.get("denominacion"),
            m.get("ubicacion"),
            m.get("sector"),
            m.get("estado"),
            m.get("notas"),
        ),
    )

def page_machines():
    st.subheader("🎰 Maestro de Máquinas")

    if not is_supervisor():
        st.info("Modo lectura: solo Supervisor/Admin puede crear o editar máquinas.")
    can_edit = is_supervisor()

    colA, colB = st.columns([1, 2])
    with colA:
        q = st.text_input("Buscar por ID (ej: 32345)", placeholder="32345")
    with colB:
        show_n = st.slider("Cantidad a mostrar", 10, 200, 50)

    if q.strip():
        try:
            mid = int(q.strip())
            machines = db_fetchall("select * from public.machines where id_maquina=%s;", (mid,))
        except:
            machines = db_fetchall(
                "select * from public.machines where (modelo ilike %s or ubicacion ilike %s or sector ilike %s) order by id_maquina limit %s;",
                (f"%{q}%", f"%{q}%", f"%{q}%", show_n),
            )
    else:
        machines = db_fetchall("select * from public.machines order by id_maquina limit %s;", (show_n,))

    dfm = pd.DataFrame(machines)
    if not dfm.empty:
        st.dataframe(dfm, use_container_width=True, hide_index=True)
    else:
        st.info("No hay máquinas cargadas aún.")

    st.markdown("---")
    st.markdown("### ✍️ Crear / Editar máquina")
    st.caption("Si el ID existe, se actualiza. Si no existe, se crea.")

    with st.form("machine_form", clear_on_submit=False):
        id_maquina = st.text_input("ID Máquina (numérico)", placeholder="32345", disabled=not can_edit)
        fabricante = st.text_input("Fabricante", disabled=not can_edit)
        modelo = st.text_input("Modelo", disabled=not can_edit)
        denominacion = st.text_input("Denominación / Juego", disabled=not can_edit)
        ubicacion = st.text_input("Ubicación (banco/posición)", disabled=not can_edit)
        sector = st.text_input("Sector (VIP, Terraza, etc.)", disabled=not can_edit)
        estado = st.selectbox("Estado", ["Operativa", "Fuera de Servicio", "En Observación", "En Mantención"], disabled=not can_edit)
        notas = st.text_area("Notas", disabled=not can_edit)

        ok = st.form_submit_button("Guardar máquina", disabled=not can_edit)

    if ok:
        try:
            mid = int(id_maquina.strip())
        except:
            st.error("ID Máquina debe ser numérico (ej: 32345).")
            return

        try:
            upsert_machine(
                {
                    "id_maquina": mid,
                    "fabricante": fabricante.strip() or None,
                    "modelo": modelo.strip() or None,
                    "denominacion": denominacion.strip() or None,
                    "ubicacion": ubicacion.strip() or None,
                    "sector": sector.strip() or None,
                    "estado": estado,
                    "notas": notas.strip() or None,
                }
            )
            st.success("✅ Máquina guardada.")
            st.rerun()
        except Exception as e:
            st.error(f"Error: {e}")

# =========================
# MAINTENANCE
# =========================
def page_new_maintenance():
    st.subheader("🧾 Registrar Mantención / Intervención")
    require_login()

    col1, col2 = st.columns([1, 2])
    with col1:
        id_str = st.text_input("ID Máquina", placeholder="32345")
    with col2:
        st.caption("Tip: primero carga la máquina en el Maestro para que salga la ficha completa.")

    if not id_str.strip():
        st.info("Ingresa un ID de máquina para continuar.")
        return

    try:
        mid = int(id_str.strip())
    except:
        st.error("ID Máquina debe ser numérico.")
        return

    m = db_fetchone("select * from public.machines where id_maquina=%s;", (mid,))
    if m:
        st.success(f"✅ Máquina encontrada: {mid} • {m.get('modelo','')} • {m.get('ubicacion','')}")
        with st.expander("Ver ficha máquina"):
            st.json(m)
    else:
        st.warning("⚠️ Máquina no existe en Maestro. Puedes registrar igual, pero te conviene crearla primero.")

    with st.form("maint_form"):
        tipo = st.selectbox("Tipo", ["Preventiva", "Correctiva", "Inspección", "Otro"])
        fecha = st.date_input("Fecha", value=date.today())
        turno = st.selectbox("Turno", ["Día", "Tarde", "Noche", "Otro"])
        falla = st.text_area("Falla / Motivo (si aplica)")
        diagnostico = st.text_area("Diagnóstico")
        accion = st.text_area("Acción realizada / Trabajo efectuado")
        repuestos = st.text_input("Repuestos (separados por coma)", placeholder="Ej: sensor, bill validator, cable")
        estado_final = st.selectbox("Estado final", ["Operativa", "Queda en Observación", "Fuera de Servicio", "Escalado a Proveedor"])
        link_adjuntos = st.text_input("Link adjuntos (Drive/SharePoint/etc.)", placeholder="https://... (opcional)")
        ok = st.form_submit_button("Guardar intervención")

    if ok:
        u = current_user()
        try:
            db_execute(
                """
                insert into public.maintenance
                (id_maquina, tipo, fecha, turno, tecnico_username, tecnico_nombre, falla, diagnostico, accion, repuestos, estado_final, link_adjuntos, created_at)
                values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now());
                """,
                (
                    mid,
                    tipo,
                    fecha,
                    turno,
                    u["username"],
                    u["nombre"],
                    falla.strip() or None,
                    diagnostico.strip() or None,
                    accion.strip() or None,
                    repuestos.strip() or None,
                    estado_final,
                    link_adjuntos.strip() or None,
                ),
            )
            st.success("✅ Intervención guardada.")
            st.rerun()
        except Exception as e:
            st.error(f"Error guardando: {e}")

def page_history():
    st.subheader("📚 Historial por Máquina")

    colA, colB, colC = st.columns([1, 1, 2])
    with colA:
        id_str = st.text_input("ID Máquina", placeholder="32345")
    with colB:
        tipo = st.selectbox("Filtrar tipo", ["(Todos)", "Preventiva", "Correctiva", "Inspección", "Otro"])
    with colC:
        limit = st.slider("Máximo de registros", 10, 500, 100)

    if not id_str.strip():
        st.info("Ingresa un ID de máquina para ver historial.")
        return

    try:
        mid = int(id_str.strip())
    except:
        st.error("ID Máquina debe ser numérico.")
        return

    m = db_fetchone("select * from public.machines where id_maquina=%s;", (mid,))
    if m:
        st.caption(f"🎰 {mid} • {m.get('modelo','')} • {m.get('ubicacion','')} • {m.get('sector','')}")
    else:
        st.caption(f"🎰 {mid} (no existe en Maestro)")

    if tipo == "(Todos)":
        rows = db_fetchall(
            "select * from public.maintenance where id_maquina=%s order by created_at desc limit %s;",
            (mid, limit),
        )
    else:
        rows = db_fetchall(
            "select * from public.maintenance where id_maquina=%s and tipo=%s order by created_at desc limit %s;",
            (mid, tipo, limit),
        )

    if not rows:
        st.warning("No hay intervenciones registradas para esta máquina.")
        return

    df = pd.DataFrame(rows)
    cols = [
        "created_at", "fecha", "tipo", "turno",
        "tecnico_nombre", "tecnico_username",
        "estado_final",_attach", "falla", "diagnostico", "accion", "repuestos", "link_adjuntos"
    ]
    cols = [c for c in cols if c in df.columns]
    st.dataframe(df[cols], use_container_width=True, hide_index=True)

    with st.expander("Ver últimos registros en formato “timeline”"):
        for r in rows[:30]:
            st.markdown(
                f"**{r.get('fecha')} • {r.get('tipo')} • {r.get('estado_final','')}**  \n"
                f"👤 {r.get('tecnico_nombre','')} ({r.get('tecnico_username','')}) • 🕒 {r.get('created_at')}"
            )
            if r.get("falla"):
                st.write("🧩 Falla:", r["falla"])
            if r.get("diagnostico"):
                st.write("🔎 Diagnóstico:", r["diagnostico"])
            if r.get("accion"):
                st.write("🛠️ Acción:", r["accion"])
            if r.get("repuestos"):
                st.write("📦 Repuestos:", r["repuestos"])
            if r.get("link_adjuntos"):
                st.write("📎 Adjuntos:", r["link_adjuntos"])
            st.markdown("---")

# =========================
# SIDEBAR NAV
# =========================
with st.sidebar:
    st.markdown("### Navegación")

    # Validación tablas
    if not tables_exist():
        st.error("❌ Tablas no existen todavía en la DB (users/machines/maintenance).")
        st.stop()

    # Primer admin si no hay usuarios
    try:
        if count_users() == 0:
            show_first_admin_setup()
            st.stop()
    except Exception as e:
        st.error(f"Error consultando usuarios: {e}")
        st.stop()

    u = current_user()
    if u:
        st.success(f"Conectado: **{u['nombre']}** ({u['role']})")
        logout_button()
    else:
        st.warning("No has iniciado sesión.")

    page = st.radio(
        "Ir a:",
        ["Login", "Máquinas", "Registrar intervención", "Historial", "Usuarios (Admin)"],
        index=0,
    )

# =========================
# ROUTER
# =========================
try:
    if page == "Login":
        show_login()
    elif page == "Máquinas":
        require_login()
        page_machines()
    elif page == "Registrar intervención":
        require_login()
        page_new_maintenance()
    elif page == "Historial":
        require_login()
        page_history()
    elif page == "Usuarios (Admin)":
        require_login()
        page_users_admin()

except psycopg2.OperationalError as e:
    st.error("❌ No se pudo conectar a la base de datos.")
    st.code(str(e))
    st.info("Revisa que DB_URL sea el de **Session Pooler** de Supabase (IPv4) y que esté bien en Secrets.")
except Exception as e:
    st.error("❌ Error inesperado:")
    st.code(str(e))
