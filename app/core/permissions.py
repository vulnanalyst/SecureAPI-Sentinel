from enum import Enum
from typing import Set, Dict


class RoleEnum(str, Enum):
    SUPER_ADMIN = "SUPER_ADMIN"
    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    USER = "USER"


class PermissionEnum(str, Enum):
    # User Permissions
    USER_READ_SELF = "user:read:self"
    USER_UPDATE_SELF = "user:update:self"
    USER_READ_ALL = "user:read:all"
    USER_UPDATE_ALL = "user:update:all"
    USER_DELETE = "user:delete"
    USER_ASSIGN_ROLE = "user:assign_role"

    # Security Telemetry Permissions
    SECURITY_READ_EVENTS = "security:read:events"
    SECURITY_READ_AUDIT = "security:read:audit"
    SECURITY_HEALTH = "security:read:health"

    # Admin Operations
    ADMIN_DASHBOARD = "admin:read:dashboard"
    ADMIN_SYSTEM_STATUS = "admin:read:system_status"


# Role-to-Permissions Mapping (Defense-in-depth Role Based Access Control)
ROLE_PERMISSIONS: Dict[RoleEnum, Set[PermissionEnum]] = {
    RoleEnum.USER: {
        PermissionEnum.USER_READ_SELF,
        PermissionEnum.USER_UPDATE_SELF,
        PermissionEnum.SECURITY_HEALTH,
    },
    RoleEnum.SECURITY_ANALYST: {
        PermissionEnum.USER_READ_SELF,
        PermissionEnum.USER_UPDATE_SELF,
        PermissionEnum.SECURITY_READ_EVENTS,
        PermissionEnum.SECURITY_READ_AUDIT,
        PermissionEnum.SECURITY_HEALTH,
    },
    RoleEnum.ADMIN: {
        PermissionEnum.USER_READ_SELF,
        PermissionEnum.USER_UPDATE_SELF,
        PermissionEnum.USER_READ_ALL,
        PermissionEnum.USER_UPDATE_ALL,
        PermissionEnum.ADMIN_DASHBOARD,
        PermissionEnum.SECURITY_READ_EVENTS,
        PermissionEnum.SECURITY_READ_AUDIT,
        PermissionEnum.SECURITY_HEALTH,
    },
    RoleEnum.SUPER_ADMIN: {
        PermissionEnum.USER_READ_SELF,
        PermissionEnum.USER_UPDATE_SELF,
        PermissionEnum.USER_READ_ALL,
        PermissionEnum.USER_UPDATE_ALL,
        PermissionEnum.USER_DELETE,
        PermissionEnum.USER_ASSIGN_ROLE,
        PermissionEnum.ADMIN_DASHBOARD,
        PermissionEnum.ADMIN_SYSTEM_STATUS,
        PermissionEnum.SECURITY_READ_EVENTS,
        PermissionEnum.SECURITY_READ_AUDIT,
        PermissionEnum.SECURITY_HEALTH,
    },
}


def has_permission(user_roles: list[str], required_permission: PermissionEnum) -> bool:
    """Verifies whether any of the user's assigned roles contains the required permission."""
    for role_name in user_roles:
        try:
            role_enum = RoleEnum(role_name)
            if required_permission in ROLE_PERMISSIONS.get(role_enum, set()):
                return True
        except ValueError:
            continue
    return False
