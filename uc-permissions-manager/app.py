"""
Unity Catalog Permissions Manager
=================================
Databricks App with Streamlit for admins to manage UC permissions
and group membership via Account SCIM API.
"""

import streamlit as st
import pandas as pd
import requests
import os
from databricks.sdk import WorkspaceClient
from databricks.sdk.service.catalog import (
    SecurableType, PermissionsChange, Privilege,
)

st.set_page_config(page_title="UC Permissions Manager", page_icon="\U0001F510", layout="wide")

@st.cache_resource
def get_client() -> WorkspaceClient:
    return WorkspaceClient()

w = get_client()

# --- Constants ---
SECURABLE_MAP = {
    "Catalog": SecurableType.CATALOG,
    "Schema": SecurableType.SCHEMA,
    "Table/View": SecurableType.TABLE,
}
PRIVILEGE_PROFILES: dict[str, list[Privilege]] = {
    "Read Only  (SELECT)": [Privilege.SELECT],
    "Read & Write  (SELECT + MODIFY)": [Privilege.SELECT, Privilege.MODIFY],
    "Table Creator": [Privilege.CREATE_TABLE, Privilege.USE_SCHEMA, Privilege.USE_CATALOG],
    "Schema Creator": [Privilege.CREATE_SCHEMA, Privilege.USE_CATALOG],
    "Full Admin  (ALL PRIVILEGES)": [Privilege.ALL_PRIVILEGES],
    "Custom": [],
}
ALL_PRIVILEGE_NAMES = [
    "SELECT", "MODIFY", "CREATE_TABLE", "CREATE_SCHEMA", "CREATE_VOLUME",
    "CREATE_FUNCTION", "CREATE_MODEL", "USE_CATALOG", "USE_SCHEMA", "MANAGE", "ALL_PRIVILEGES",
]

def _priv_value(p) -> str:
    if hasattr(p, "privilege") and p.privilege is not None:
        return p.privilege.value
    if hasattr(p, "value"):
        return p.value
    return str(p)

# --- UC Helpers ---
@st.cache_data(ttl=120)
def list_catalogs() -> list[str]:
    try:
        catalogs = sorted(c.name for c in w.catalogs.list() if c.name)
        return catalogs
    except Exception as e:
        st.error(f"Error listing catalogs: {e}")
        return []

@st.cache_data(ttl=120)
def list_schemas(catalog: str) -> list[str]:
    try:
        return sorted(s.name for s in w.schemas.list(catalog_name=catalog) if s.name)
    except Exception as e:
        st.error(f"Error listing schemas: {e}")
        return []

@st.cache_data(ttl=120)
def list_tables(catalog: str, schema: str) -> list[str]:
    try:
        return sorted(t.name for t in w.tables.list(catalog_name=catalog, schema_name=schema) if t.name)
    except Exception as e:
        st.error(f"Error listing tables: {e}")
        return []

def fetch_grants(securable_type, full_name):
    try:
        result = w.grants.get(securable_type=securable_type, full_name=full_name)
        return result.privilege_assignments or []
    except Exception as e:
        st.error(f"Error fetching grants: {e}")
        return []

def apply_changes(securable_type, full_name, principal, privileges, *, grant=True):
    try:
        change = (PermissionsChange(add=privileges, principal=principal) if grant
                  else PermissionsChange(remove=privileges, principal=principal))
        w.grants.update(securable_type=securable_type, full_name=full_name, changes=[change])
        action = "granted" if grant else "revoked"
        return True, f"Privileges {action} on `{full_name}` for **{principal}**."
    except Exception as e:
        return False, str(e)

def grant_parent_access(object_type, catalog, schema, principal):
    msgs = []
    if object_type in ("Table/View", "Schema"):
        ok, _ = apply_changes(SecurableType.CATALOG, catalog, principal, [Privilege.USE_CATALOG], grant=True)
        if ok: msgs.append(f"USE_CATALOG on `{catalog}`")
    if object_type == "Table/View" and schema:
        ok, _ = apply_changes(SecurableType.SCHEMA, f"{catalog}.{schema}", principal, [Privilege.USE_SCHEMA], grant=True)
        if ok: msgs.append(f"USE_SCHEMA on `{catalog}.{schema}`")
    return msgs



def search_permissions_for_principal(principal: str, progress_callback=None):
    """Search all permissions for a given principal (user or group) across all UC objects."""
    results = []
    catalogs = list_catalogs()
    total_steps = len(catalogs)
    
    for cat_idx, catalog in enumerate(catalogs):
        if progress_callback:
            progress_callback((cat_idx + 1) / total_steps, f"Scanning catalog: {catalog}")
        
        # Check catalog permissions
        grants = fetch_grants(SecurableType.CATALOG, catalog)
        for pa in grants:
            if pa.principal == principal and pa.privileges:
                privs = ", ".join(sorted(_priv_value(p) for p in pa.privileges if p))
                results.append({
                    "Object Type": "Catalog",
                    "Full Name": catalog,
                    "Privileges": privs
                })
        
        # Check schemas
        try:
            schemas = list_schemas(catalog)
            for schema in schemas:
                schema_full = f"{catalog}.{schema}"
                grants = fetch_grants(SecurableType.SCHEMA, schema_full)
                for pa in grants:
                    if pa.principal == principal and pa.privileges:
                        privs = ", ".join(sorted(_priv_value(p) for p in pa.privileges if p))
                        results.append({
                            "Object Type": "Schema",
                            "Full Name": schema_full,
                            "Privileges": privs
                        })
                
                # Check tables in this schema
                try:
                    tables = list_tables(catalog, schema)
                    for table in tables:
                        table_full = f"{catalog}.{schema}.{table}"
                        grants = fetch_grants(SecurableType.TABLE, table_full)
                        for pa in grants:
                            if pa.principal == principal and pa.privileges:
                                privs = ", ".join(sorted(_priv_value(p) for p in pa.privileges if p))
                                results.append({
                                    "Object Type": "Table/View",
                                    "Full Name": table_full,
                                    "Privileges": privs
                                })
                except:
                    pass
        except:
            pass
    
    return results

# --- SCIM Helpers ---
def get_scim_token(client_id, client_secret, account_id):
    url = f"https://accounts.cloud.databricks.com/oidc/accounts/{account_id}/v1/token"
    try:
        resp = requests.post(url, data={
            "grant_type": "client_credentials", "client_id": client_id,
            "client_secret": client_secret, "scope": "all-apis"
        }, timeout=15)
        if resp.status_code == 200:
            return resp.json()["access_token"]
        st.error(f"SCIM Auth failed ({resp.status_code}): {resp.text}")
        return None
    except Exception as e:
        st.error(f"SCIM Auth error: {e}")
        return None

def _scim_hdrs(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/scim+json"}

def _scim_base(account_id):
    return f"https://accounts.cloud.databricks.com/api/2.0/accounts/{account_id}/scim/v2"

def scim_find_user(token, account_id, email):
    try:
        resp = requests.get(f"{_scim_base(account_id)}/Users", headers=_scim_hdrs(token),
                            params={"filter": f'userName eq "{email}"'}, timeout=15)
        res = resp.json().get("Resources", [])
        if res:
            u = res[0]
            return {"id": u["id"], "userName": u.get("userName", ""), "displayName": u.get("displayName", "")}
        return None
    except Exception as e:
        st.error(f"Error searching user: {e}")
        return None

def scim_find_group(token, account_id, group_name):
    try:
        resp = requests.get(f"{_scim_base(account_id)}/Groups", headers=_scim_hdrs(token),
                            params={"filter": f'displayName eq "{group_name}"'}, timeout=15)
        res = resp.json().get("Resources", [])
        if res:
            g = res[0]
            return {"id": g["id"], "displayName": g.get("displayName", ""), "members": g.get("members", [])}
        return None
    except Exception as e:
        st.error(f"Error searching group: {e}")
        return None

def scim_add_member(token, account_id, group_id, user_id):
    payload = {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
               "Operations": [{"op": "add", "path": "members", "value": [{"value": user_id}]}]}
    try:
        resp = requests.patch(f"{_scim_base(account_id)}/Groups/{group_id}",
                              headers=_scim_hdrs(token), json=payload, timeout=15)
        if resp.status_code in (200, 204):
            return True, "Success"
        return False, f"HTTP {resp.status_code}: {resp.text}"
    except Exception as e:
        return False, str(e)

def scim_remove_member(token, account_id, group_id, user_id):
    payload = {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
               "Operations": [{"op": "remove", "path": f'members[value eq "{user_id}"]'}]}
    try:
        resp = requests.patch(f"{_scim_base(account_id)}/Groups/{group_id}",
                              headers=_scim_hdrs(token), json=payload, timeout=15)
        if resp.status_code in (200, 204):
            return True, "Success"
        return False, f"HTTP {resp.status_code}: {resp.text}"
    except Exception as e:
        return False, str(e)

def scim_list_groups(token, account_id, prefix):
    try:
        resp = requests.get(f"{_scim_base(account_id)}/Groups", headers=_scim_hdrs(token),
                            params={"filter": f'displayName sw "{prefix}"'}, timeout=15)
        return resp.json().get("Resources", [])
    except Exception as e:
        st.error(f"Error listing groups: {e}")
        return []

# --- Sidebar ---
with st.sidebar:
    st.header("🗂️ UC Object Selector")
    st.caption("For View / Grant / Revoke / Bulk Grant tabs.")
    object_type = st.selectbox("Object type", list(SECURABLE_MAP.keys()))
    catalogs = list_catalogs()
    
    if not catalogs:
        st.warning("No catalogs found.")
        st.stop()
    selected_catalog = st.selectbox("Catalog", catalogs)
    full_name = selected_catalog
    securable_type = SECURABLE_MAP[object_type]
    selected_schema = None
    selected_table = None
    if object_type in ("Schema", "Table/View"):
        schemas = list_schemas(selected_catalog)
        if not schemas:
            st.warning("No schemas found.")
            st.stop()
        selected_schema = st.selectbox("Schema", schemas)
        full_name = f"{selected_catalog}.{selected_schema}"
    if object_type == "Table/View":
        tables = list_tables(selected_catalog, selected_schema)
        if not tables:
            st.warning("No tables/views found.")
            st.stop()
        selected_table = st.selectbox("Table/View", tables)
        full_name = f"{selected_catalog}.{selected_schema}.{selected_table}"
    st.divider()
    st.markdown(f"**Selected:** `{full_name}`")
    if st.button("\U0001F504 Refresh"):
        st.cache_data.clear()
        st.rerun()

    st.divider()
    st.header("\U0001F511 SCIM Credentials")
    st.caption("For Group Management tab.")
    scim_client_id = st.text_input("Client ID", value=os.environ.get("SCIM_CLIENT_ID", ""))
    scim_client_secret = st.text_input("Client Secret", value=os.environ.get("SCIM_CLIENT_SECRET", ""), type="password")
    scim_account_id = st.text_input("Account ID", value=os.environ.get("DATABRICKS_ACCOUNT_ID", ""))

# --- Main ---
st.title("\U0001F510 Unity Catalog Permissions Manager")
st.caption("Manage UC permissions and group membership from a single interface.")

tab_view, tab_grant, tab_revoke, tab_bulk, tab_search, tab_groups = st.tabs(
    ["\U0001F4CB View", "\u2705 Grant", "\u274C Revoke", "\U0001F4E6 Bulk Grant", "\U0001F50D Search Permissions", "\U0001F465 Groups"]
)

# ---- View ----
with tab_view:
    st.subheader(f"Permissions on `{full_name}`")
    grants = fetch_grants(securable_type, full_name)
    if grants:
        rows = []
        for pa in grants:
            if pa.privileges:
                privs = ", ".join(sorted(_priv_value(p) for p in pa.privileges if p))
                rows.append({"Principal": pa.principal, "Privileges": privs})
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        else:
            st.info("No explicit permissions found.")
    else:
        st.info("No explicit permissions found.")

# ---- Grant ----
with tab_grant:
    st.subheader("Grant Permissions")
    with st.form("grant_form"):
        principal = st.text_input("User / Group", placeholder="user@example.com or group-name")
        profile = st.selectbox("Profile", list(PRIVILEGE_PROFILES.keys()))
        if profile == "Custom":
            sel = st.multiselect("Privileges", ALL_PRIVILEGE_NAMES)
            privileges = [Privilege(p) for p in sel]
        else:
            privileges = PRIVILEGE_PROFILES[profile]
            st.caption(f"Includes: {', '.join(p.value for p in privileges)}")
        auto_parent = st.checkbox("Auto-grant USE_CATALOG / USE_SCHEMA", value=True)
        submitted = st.form_submit_button("\u2705 Grant", type="primary")
    if submitted:
        if not principal:
            st.error("Enter a user or group.")
        elif not privileges:
            st.error("Select at least one privilege.")
        else:
            ok, msg = apply_changes(securable_type, full_name, principal, privileges, grant=True)
            if ok:
                st.success(msg)
                if auto_parent and Privilege.ALL_PRIVILEGES not in privileges:
                    pm = grant_parent_access(object_type, selected_catalog, selected_schema, principal)
                    if pm:
                        st.info("Also granted: " + ", ".join(pm))
                st.cache_data.clear()
            else:
                st.error(msg)

# ---- Revoke ----
with tab_revoke:
    st.subheader("Revoke Permissions")
    grants = fetch_grants(securable_type, full_name)
    if not grants:
        st.info("No permissions to revoke.")
    else:
        principals = [pa.principal for pa in grants if pa.principal]
        if not principals:
            st.info("No principals with explicit grants.")
        else:
            with st.form("revoke_form"):
                target = st.selectbox("Principal", principals)
                current_privs = []
                for pa in grants:
                    if pa.principal == target and pa.privileges:
                        current_privs = sorted(_priv_value(p) for p in pa.privileges if p)
                to_revoke = st.multiselect("Privileges to revoke", current_privs, default=current_privs)
                submitted = st.form_submit_button("\u274C Revoke", type="primary")
            if submitted:
                if not to_revoke:
                    st.error("Select at least one privilege.")
                else:
                    ok, msg = apply_changes(securable_type, full_name, target, [Privilege(p) for p in to_revoke], grant=False)
                    if ok:
                        st.success(msg)
                        st.cache_data.clear()
                    else:
                        st.error(msg)

# ---- Bulk Grant ----
with tab_bulk:
    st.subheader("Bulk Grant")
    with st.form("bulk_form"):
        principals_text = st.text_area("Users / Groups (one per line)", height=150)
        profile_b = st.selectbox("Profile", [k for k in PRIVILEGE_PROFILES if k != "Custom"], key="bp")
        privs_b = PRIVILEGE_PROFILES[profile_b]
        st.caption(f"Includes: {', '.join(p.value for p in privs_b)}")
        auto_b = st.checkbox("Auto-grant parent permissions", value=True, key="ba")
        submitted_b = st.form_submit_button("\U0001F4E6 Grant to all", type="primary")
    if submitted_b:
        plist = [l.strip() for l in principals_text.splitlines() if l.strip()]
        if not plist:
            st.error("Enter at least one user or group.")
        else:
            prog = st.progress(0)
            res = []
            for i, p in enumerate(plist):
                ok, msg = apply_changes(securable_type, full_name, p, privs_b, grant=True)
                res.append({"Principal": p, "Status": "\u2705" if ok else "\u274C", "Details": msg})
                if ok and auto_b and Privilege.ALL_PRIVILEGES not in privs_b:
                    grant_parent_access(object_type, selected_catalog, selected_schema, p)
                prog.progress((i + 1) / len(plist))
            st.dataframe(pd.DataFrame(res), use_container_width=True, hide_index=True)
            st.cache_data.clear()



# ---- Search Permissions ----
with tab_search:
    st.subheader("🔍 Search Permissions by User or Group")
    st.caption("Find all permissions for a specific user or group across all catalogs, schemas, and tables/views.")
    
    with st.form("search_form"):
        search_principal = st.text_input(
            "User email or Group name",
            placeholder="user@example.com or group-name",
            help="Enter the exact email or group name to search for"
        )
        submitted_search = st.form_submit_button("🔍 Search", type="primary")
    
    if submitted_search:
        if not search_principal:
            st.error("Please enter a user email or group name.")
        else:
            with st.spinner(f"Searching permissions for {search_principal}..."):
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                def update_progress(value, message):
                    progress_bar.progress(value)
                    status_text.text(message)
                
                results = search_permissions_for_principal(search_principal, update_progress)
                
                progress_bar.empty()
                status_text.empty()
            
            if results:
                st.success(f"Found {len(results)} permission(s) for **{search_principal}**")
                df = pd.DataFrame(results)
                st.dataframe(df, use_container_width=True, hide_index=True)
                
                # Summary statistics
                st.divider()
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Permissions", len(results))
                with col2:
                    catalogs_count = len([r for r in results if r["Object Type"] == "Catalog"])
                    st.metric("Catalogs", catalogs_count)
                with col3:
                    schemas_count = len([r for r in results if r["Object Type"] == "Schema"])
                    tables_count = len([r for r in results if r["Object Type"] == "Table/View"])
                    st.metric("Schemas / Tables/Views", f"{schemas_count} / {tables_count}")
            else:
                st.info(f"No explicit permissions found for **{search_principal}**.\n\nThis could mean:\n- The principal doesn't exist\n- No explicit permissions are granted\n- Permissions are inherited from groups")

# ---- Group Management ----
with tab_groups:
    st.subheader("\U0001F465 Group Management (Account SCIM)")
    st.caption("Manage group membership using convention: gr_dtb_{catalog}_{schema}_{table}_{access_type}")

    if not scim_client_id or not scim_client_secret or not scim_account_id:
        st.warning("Configure SCIM credentials in the sidebar (or set env vars: SCIM_CLIENT_ID, SCIM_CLIENT_SECRET, DATABRICKS_ACCOUNT_ID).")
    else:
        # Auth
        creds_key = (scim_client_id, scim_account_id)
        if "scim_token" not in st.session_state or st.session_state.get("_creds") != creds_key:
            with st.spinner("Authenticating with SCIM API..."):
                tok = get_scim_token(scim_client_id, scim_client_secret, scim_account_id)
                if tok:
                    st.session_state["scim_token"] = tok
                    st.session_state["_creds"] = creds_key
                else:
                    st.stop()
        scim_token = st.session_state["scim_token"]

        grp_add, grp_search, grp_remove = st.tabs(["\u2795 Add to Groups", "\U0001F50D Search Groups", "\u2796 Remove from Groups"])

        with grp_add:
            st.markdown("##### Add user to table-level groups")
            with st.form("scim_add"):
                c1, c2 = st.columns(2)
                with c1:
                    add_email = st.text_input("User email", placeholder="user@example.com")
                    add_cat = st.text_input("Catalog", value="prd")
                    add_schema = st.text_input("Schema", placeholder="schema_name")
                with c2:
                    add_access = st.selectbox("Access type", ["p", "c"], help="p = read, c = write")
                    add_tables = st.text_area("Tables (one per line)", height=200,
                                              placeholder="table_1\ntable_2\ntable_3")
                btn = st.form_submit_button("\U0001F50D Scan & Add User", type="primary")
            if btn:
                if not add_email or not add_cat or not add_schema or not add_tables.strip():
                    st.error("Fill all fields.")
                else:
                    tlist = [t.strip() for t in add_tables.splitlines() if t.strip()]
                    with st.spinner(f"Searching user: {add_email}..."):
                        user = scim_find_user(scim_token, scim_account_id, add_email)
                    if not user:
                        st.error(f"User **{add_email}** not found.")
                    else:
                        st.success(f"User: **{user['displayName']}** (ID: {user['id']})")
                        prog = st.progress(0)
                        res = []
                        for i, tn in enumerate(tlist):
                            gn = f"gr_dtb_{add_cat}_{add_schema}_{tn}_{add_access}"
                            gi = scim_find_group(scim_token, scim_account_id, gn)
                            if not gi:
                                res.append({"Group": gn, "Status": "\u26A0\uFE0F Not found", "Action": "Skipped"})
                            else:
                                is_m = any(m.get("value") == user["id"] for m in gi["members"])
                                if is_m:
                                    res.append({"Group": gn, "Status": "\u2705 Found", "Action": "Already member"})
                                else:
                                    ok, msg = scim_add_member(scim_token, scim_account_id, gi["id"], user["id"])
                                    res.append({"Group": gn, "Status": "\u2705 Found",
                                                "Action": "\u2705 Added" if ok else f"\u274C {msg}"})
                            prog.progress((i+1)/len(tlist))
                        st.dataframe(pd.DataFrame(res), use_container_width=True, hide_index=True)
                        added = sum(1 for r in res if "Added" in r["Action"])
                        already = sum(1 for r in res if "Already" in r["Action"])
                        nf = sum(1 for r in res if "Not found" in r["Status"])
                        st.info(f"**{added}** added, **{already}** already members, **{nf}** groups not found.")

        with grp_search:
            st.markdown("##### Search groups by prefix")
            with st.form("scim_search"):
                prefix = st.text_input("Group prefix", placeholder="gr_dtb_prd_schema_name")
                btn_s = st.form_submit_button("\U0001F50D Search", type="primary")
            if btn_s and prefix:
                with st.spinner("Searching..."):
                    groups = scim_list_groups(scim_token, scim_account_id, prefix)
                if groups:
                    rows = []
                    for g in groups:
                        mc = len(g["members"])
                        mn = ", ".join(m.get("display", m.get("value", "?")) for m in g["members"][:10])
                        if mc > 10: mn += f" ... (+{mc-10} more)"
                        rows.append({"Group": g["displayName"], "Members": mc, "Member List": mn})
                    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
                else:
                    st.info(f"No groups found with prefix `{prefix}`.")

        with grp_remove:
            st.markdown("##### Remove user from table-level groups")
            with st.form("scim_rm"):
                c1, c2 = st.columns(2)
                with c1:
                    rm_email = st.text_input("User email", placeholder="user@example.com", key="rme")
                    rm_cat = st.text_input("Catalog", value="prd", key="rmc")
                    rm_schema = st.text_input("Schema", placeholder="schema_name", key="rms")
                with c2:
                    rm_access = st.selectbox("Access type", ["p", "c"], key="rma")
                    rm_tables = st.text_area("Tables (one per line)", height=200, key="rmt")
                btn_r = st.form_submit_button("\u274C Remove User", type="primary")
            if btn_r:
                if not rm_email or not rm_cat or not rm_schema or not rm_tables.strip():
                    st.error("Fill all fields.")
                else:
                    tlist = [t.strip() for t in rm_tables.splitlines() if t.strip()]
                    with st.spinner(f"Searching user: {rm_email}..."):
                        user = scim_find_user(scim_token, scim_account_id, rm_email)
                    if not user:
                        st.error(f"User **{rm_email}** not found.")
                    else:
                        st.success(f"User: **{user['displayName']}** (ID: {user['id']})")
                        prog = st.progress(0)
                        res = []
                        for i, tn in enumerate(tlist):
                            gn = f"gr_dtb_{rm_cat}_{rm_schema}_{tn}_{rm_access}"
                            gi = scim_find_group(scim_token, scim_account_id, gn)
                            if not gi:
                                res.append({"Group": gn, "Status": "\u26A0\uFE0F Not found", "Action": "Skipped"})
                            else:
                                is_m = any(m.get("value") == user["id"] for m in gi["members"])
                                if not is_m:
                                    res.append({"Group": gn, "Status": "\u2705 Found", "Action": "Not a member"})
                                else:
                                    ok, msg = scim_remove_member(scim_token, scim_account_id, gi["id"], user["id"])
                                    res.append({"Group": gn, "Status": "\u2705 Found",
                                                "Action": "\u2705 Removed" if ok else f"\u274C {msg}"})
                            prog.progress((i+1)/len(tlist))
                        st.dataframe(pd.DataFrame(res), use_container_width=True, hide_index=True)

st.divider()
st.caption("UC Permissions Manager • Powered by Databricks Apps + Streamlit")
