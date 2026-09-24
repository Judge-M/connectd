"""Tenant visibility for owned and explicitly shared registry resources."""


def visible_to(db, owner_org_id: str, target_org_id: str,
               resource_kind: str, resource_id: str) -> bool:
    if resource_kind not in {"tool", "node"}:
        raise ValueError("unsupported registry resource kind")
    if owner_org_id == target_org_id:
        return True
    row = db.execute("""SELECT 1 FROM registry_shares WHERE owner_org_id=?
        AND target_org_id=? AND resource_kind=? AND resource_id IN (?, '*')
        LIMIT 1""", (owner_org_id, target_org_id, resource_kind, resource_id)).fetchone()
    return row is not None


def resource_owned_by(db, owner_org_id: str, resource_kind: str,
                      resource_id: str) -> bool:
    if resource_kind not in {"tool", "node"}:
        raise ValueError("unsupported registry resource kind")
    if resource_id == "*":
        return db.execute("SELECT 1 FROM organizations WHERE org_id=?",
                          (owner_org_id,)).fetchone() is not None
    if not resource_id:
        return False
    table, key = (("tool_registry", "tool_id") if resource_kind == "tool"
                  else ("compute_nodes", "node_id"))
    row = db.execute(f"SELECT owner_org_id FROM {table} WHERE {key}=?",
                     (resource_id,)).fetchone()
    return row is not None and row["owner_org_id"] == owner_org_id


def grant_share(db, owner_org_id: str, target_org_id: str, resource_kind: str,
                resource_id: str, created_by: str, created_at: str) -> None:
    if owner_org_id == target_org_id or not target_org_id or not created_by:
        raise ValueError("sharing requires a distinct target organization and operator")
    if not resource_owned_by(db, owner_org_id, resource_kind, resource_id):
        raise ValueError("resource is not owned by the organization")
    if db.execute("SELECT 1 FROM organizations WHERE org_id=?",
                  (target_org_id,)).fetchone() is None:
        raise ValueError("target organization does not exist")
    db.execute("""INSERT INTO registry_shares(owner_org_id,target_org_id,resource_kind,
        resource_id,created_by,created_at) VALUES (?,?,?,?,?,?)
        ON CONFLICT (owner_org_id,target_org_id,resource_kind,resource_id)
        DO NOTHING""", (owner_org_id, target_org_id, resource_kind, resource_id,
                        created_by, created_at))


def revoke_share(db, owner_org_id: str, target_org_id: str,
                 resource_kind: str, resource_id: str) -> bool:
    if resource_kind not in {"tool", "node"}:
        raise ValueError("unsupported registry resource kind")
    result = db.execute("""DELETE FROM registry_shares WHERE owner_org_id=?
        AND target_org_id=? AND resource_kind=? AND resource_id=?""",
        (owner_org_id, target_org_id, resource_kind, resource_id))
    return result.rowcount == 1
