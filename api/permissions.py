# In api/permissions.py
from rest_framework.permissions import BasePermission
from django.db.models import Q

class HasPrivilege(BasePermission):
    """
    Checks if a user's roles grant them the required privilege for a specific view action.
    Can handle a single privilege string or a list of privilege strings (requiring any one).
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        # --- THIS IS THE FIX ---
        # The superuser check has been removed. Now, ALL users, including superusers,
        # must have the explicit privilege assigned to their role to perform an action.
        # if request.user.is_superuser:
        #     return True

        required_privileges_map = getattr(view, 'required_privileges', {})
        required_privilege_or_list = required_privileges_map.get(view.action)

        if not required_privilege_or_list:
            # Deny access by default if no privilege is specified for an action.
            return False

        if isinstance(required_privilege_or_list, list):
            # If it's a list, check if the user has ANY of the privileges in the list.
            if not required_privilege_or_list:
                return False

            # Build an OR query to check for any of the required privileges.
            q_objects = Q()
            for privilege_name in required_privilege_or_list:
                q_objects |= Q(profile__privileges__name=privilege_name)

            return request.user.groups.filter(q_objects).exists()
        else:
            # If it's a single string, perform the original check.
            return request.user.groups.filter(profile__privileges__name=required_privilege_or_list).exists()