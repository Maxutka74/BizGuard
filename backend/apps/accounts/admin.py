from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User

# @admin.register(User)
# class UserAdmin(BaseUserAdmin):
#     list_display = ["email", "name", "gmail_connected", "last_scan_at", "created_at"]
#     list_filter = ["gmail_connected"]
#     search_fields = ["email", "name"]
#     fieldsets = BaseUserAdmin.fieldsets + (
#         ("BizGuard", {"fields": ["name", "avatar_url", "google_id", "gmail_connected", "last_scan_at"]}),
#     )
