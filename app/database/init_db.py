from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone

import app.models
from app.database.session import engine, async_session_maker
from app.database.base import Base
from app.models.user import User
from app.models.role import Role, Permission, UserRole, RolePermission
from app.core.permissions import RoleEnum, PermissionEnum, ROLE_PERMISSIONS
from app.core.security import hash_password
from app.core.logging import logger


async def init_db():
    """Initializes tables and seeds default roles, permissions, and baseline users."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session_maker() as db:
        # 1. Seed Roles
        role_map = {}
        for role_enum in RoleEnum:
            res = await db.execute(select(Role).where(Role.name == role_enum.value))
            role_obj = res.scalar_one_or_none()
            if not role_obj:
                role_obj = Role(
                    name=role_enum.value,
                    description=f"{role_enum.value} system role",
                    created_at=datetime.now(timezone.utc),
                )
                db.add(role_obj)
                await db.flush()
                logger.info(f"Seeded role: {role_enum.value}")
            role_map[role_enum.value] = role_obj

        # 2. Seed Permissions
        perm_map = {}
        for perm_enum in PermissionEnum:
            res = await db.execute(select(Permission).where(Permission.name == perm_enum.value))
            perm_obj = res.scalar_one_or_none()
            if not perm_obj:
                resource, action = perm_enum.value.split(":")[:2]
                perm_obj = Permission(
                    name=perm_enum.value,
                    resource=resource,
                    action=action,
                    description=f"Permission for {perm_enum.value}",
                )
                db.add(perm_obj)
                await db.flush()
            perm_map[perm_enum.value] = perm_obj

        # 3. Associate Permissions with Roles
        for role_enum, perms in ROLE_PERMISSIONS.items():
            role_obj = role_map[role_enum.value]
            for p in perms:
                perm_obj = perm_map[p.value]
                check = await db.execute(
                    select(RolePermission).where(
                        RolePermission.role_id == role_obj.id,
                        RolePermission.permission_id == perm_obj.id,
                    )
                )
                if not check.scalar_one_or_none():
                    rp = RolePermission(role_id=role_obj.id, permission_id=perm_obj.id)
                    db.add(rp)

        # 4. Seed Seed Baseline Accounts
        seed_users = [
            ("superadmin@sentinel.org", "SuperAdmin#2026!Sec", "Sentinel Super Admin", RoleEnum.SUPER_ADMIN),
            ("admin@sentinel.org", "Admin#2026!Sec", "Sentinel Admin", RoleEnum.ADMIN),
            ("analyst@sentinel.org", "Analyst#2026!Sec", "Security Analyst", RoleEnum.SECURITY_ANALYST),
            ("user@sentinel.org", "Standard#2026!Sec", "Standard User", RoleEnum.USER),
        ]

        for email, password, full_name, role_enum in seed_users:
            u_res = await db.execute(select(User).where(User.email == email))
            existing_user = u_res.scalar_one_or_none()
            if not existing_user:
                new_u = User(
                    email=email,
                    hashed_password=hash_password(password),
                    full_name=full_name,
                    is_active=True,
                    is_verified=True,
                    is_locked=False,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
                db.add(new_u)
                await db.flush()

                assoc = UserRole(user_id=new_u.id, role_id=role_map[role_enum.value].id)
                db.add(assoc)
                logger.info(f"Seeded user account: {email} with role {role_enum.value}")

        await db.commit()
