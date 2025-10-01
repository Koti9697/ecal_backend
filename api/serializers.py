# In api/serializers.py

from rest_framework import serializers
from django.contrib.auth.models import User, Group
from django.utils import timezone
from datetime import timedelta
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.contrib.auth.hashers import check_password


from .models import (
    Template, Record, RecordData, AuditLog, ElectronicSignature, Privilege,
    SystemSettings, GroupProfile, UserProfile, PasswordHistory
)
from .validators import GxPPasswordValidator, GxPUsernameValidator


class PrivilegeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Privilege
        fields = ['id', 'name', 'description']

class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ['id', 'name']

class UserReadOnlySerializer(serializers.ModelSerializer):
    groups = GroupSerializer(many=True, read_only=True)
    full_name = serializers.CharField(source='get_full_name', read_only=True)
    class Meta:
        model = User
        fields = ['id', 'username', 'full_name', 'first_name', 'last_name', 'email', 'is_active', 'groups']

class MyProfileSerializer(UserReadOnlySerializer):
    settings = serializers.SerializerMethodField()

    class Meta(UserReadOnlySerializer.Meta):
        fields = UserReadOnlySerializer.Meta.fields + ['settings']

    def get_settings(self, obj):
        settings, _ = SystemSettings.objects.get_or_create(pk=1)
        return {
            'allow_user_account_closure': settings.allow_user_account_closure
        }

class TemplateListSerializer(serializers.ModelSerializer):
    created_by = serializers.CharField(source='created_by.username', read_only=True)
    updated_by = serializers.CharField(source='updated_by.username', read_only=True, default='')

    class Meta:
        model = Template
        fields = ['id', 'template_id', 'name', 'version', 'status', 'created_by', 'updated_at', 'updated_by', 'approved_at']


class RecordReportSerializer(serializers.ModelSerializer):
    template_name = serializers.CharField(source='template.name', read_only=True)
    template_version = serializers.CharField(source='template.version', read_only=True)
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)

    class Meta:
        model = Record
        fields = [
            'id',
            'record_id_display',
            'status',
            'created_at',
            'template_name',
            'template_version',
            'created_by_username'
        ]

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        if user.is_superuser:
            privileges = Privilege.objects.all().values_list('name', flat=True)
        else:
            privileges = Privilege.objects.filter(groupprofile__group__user=user).values_list('name', flat=True).distinct()

        token['user'] = { 'id': user.id, 'username': user.username, 'full_name': user.get_full_name(), 'roles': [group.name for group in user.groups.all()], 'privileges': list(privileges) }
        return token

    def validate(self, attrs):
        username = attrs.get('username')
        try:
            user = User.objects.get(username=username)
            profile = user.profile
        except (User.DoesNotExist, UserProfile.DoesNotExist):
            raise AuthenticationFailed('No active account found with the given credentials', 'no_active_account')

        settings, _ = SystemSettings.objects.get_or_create(pk=1)
        if profile.lockout_until and profile.lockout_until > timezone.now():
            raise AuthenticationFailed(f"Account is locked. Try again later.", "account_locked")
        try:
            data = super().validate(attrs)
        except AuthenticationFailed as e:
            profile.failed_login_attempts += 1
            if profile.failed_login_attempts >= settings.password_lockout_attempts:
                profile.lockout_until = timezone.now() + timedelta(minutes=settings.password_lockout_duration)
            profile.save()
            raise e
        expiry_date = profile.password_last_changed + timedelta(days=settings.password_expiry_days)
        if timezone.now() > expiry_date:
            raise AuthenticationFailed("Your password has expired. Please contact an administrator to reset it.", "password_expired")
        profile.failed_login_attempts = 0
        profile.lockout_until = None
        profile.save()
        refresh = self.get_token(self.user)
        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)
        data['user'] = refresh['user']
        return data


class SignatureSerializer(serializers.Serializer):
    password = serializers.CharField(style={'input_type': 'password'}, trim_whitespace=False, write_only=True)
    reason = serializers.CharField(max_length=255, required=True)

class ElectronicSignatureSerializer(serializers.ModelSerializer):
    signed_by = UserReadOnlySerializer(read_only=True)
    class Meta:
        model = ElectronicSignature
        fields = ['signed_by', 'signed_at', 'meaning']

class AuditLogSerializer(serializers.ModelSerializer):
    user = UserReadOnlySerializer(read_only=True)
    class Meta:
        model = AuditLog
        fields = ['id', 'timestamp', 'user', 'action', 'details', 'reason_for_change', 'previous_value', 'new_value']

class TemplateVerificationSerializer(serializers.Serializer):
    verification_data = serializers.JSONField()
    password = serializers.CharField(write_only=True, required=True)
    reason = serializers.CharField(required=True, max_length=255)
    meaning = serializers.CharField(required=True, max_length=100)

class TemplateDetailSerializer(serializers.ModelSerializer):
    created_by = UserReadOnlySerializer(read_only=True)
    signatures = serializers.SerializerMethodField(read_only=True)
    audit_trail = serializers.SerializerMethodField(read_only=True)
    version = serializers.CharField(read_only=True)
    reason_for_change = serializers.CharField(write_only=True, required=True, max_length=255)
    admin_password = serializers.CharField(write_only=True, required=True)
    class Meta:
        model = Template
        fields = ['id', 'template_id', 'name', 'version', 'major_version', 'minor_version', 'status', 'created_at', 'created_by', 'document_data', 'signatures', 'audit_trail', 'reason_for_change', 'admin_password']
        read_only_fields = ['status', 'created_by', 'created_at', 'signatures', 'version', 'audit_trail']

    def get_signatures(self, obj):
        signatures = ElectronicSignature.objects.filter(content_type=ContentType.objects.get_for_model(obj), object_id=obj.id).order_by('signed_at')
        return ElectronicSignatureSerializer(signatures, many=True).data

    def get_audit_trail(self, obj):
        audit_logs = AuditLog.objects.filter(content_type=ContentType.objects.get_for_model(obj), object_id=obj.id).order_by('-timestamp')
        return AuditLogSerializer(audit_logs, many=True).data

    def validate(self, data):
        if not self.instance:
            template_id = data.get('template_id')
            if Template.objects.filter(template_id=template_id).exists():
                raise ValidationError(f"A template with the ID '{template_id}' already exists.")
        return data

    def create(self, validated_data):
        validated_data.pop('reason_for_change', None)
        validated_data.pop('admin_password', None)
        return super().create(validated_data)

    def update(self, instance, validated_data):
        validated_data.pop('reason_for_change', None)
        validated_data.pop('admin_password', None)
        return super().update(instance, validated_data)


class UserWriteSerializer(serializers.ModelSerializer):
    groups = serializers.PrimaryKeyRelatedField(many=True, queryset=Group.objects.all(), required=True, allow_empty=False)
    reason_for_change = serializers.CharField(write_only=True, required=True, max_length=255)
    admin_password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name', 'email', 'password', 'groups', 'reason_for_change', 'admin_password']
        extra_kwargs = {
            'username': {'validators': [GxPUsernameValidator()]},
            'password': {'write_only': True, 'required': False, 'validators': [GxPPasswordValidator()]}
        }

class GroupReadSerializer(serializers.ModelSerializer):
    privileges = PrivilegeSerializer(many=True, read_only=True, source='profile.privileges')
    class Meta:
        model = Group
        fields = ['id', 'name', 'privileges']

class GroupWriteSerializer(serializers.ModelSerializer):
    privileges = serializers.PrimaryKeyRelatedField(many=True, queryset=Privilege.objects.all(), required=False)
    reason_for_change = serializers.CharField(write_only=True, required=True, max_length=255)
    admin_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = Group
        fields = ['id', 'name', 'privileges', 'reason_for_change', 'admin_password']

    @transaction.atomic
    def create(self, validated_data):
        privileges_data = validated_data.pop('privileges', [])
        validated_data.pop('reason_for_change', None)
        validated_data.pop('admin_password', None)

        group = super().create(validated_data)
        group.profile.privileges.set(privileges_data)
        return group

    @transaction.atomic
    def update(self, instance, validated_data):
        privileges_data = validated_data.pop('privileges', None)
        validated_data.pop('reason_for_change', None)
        validated_data.pop('admin_password', None)

        instance = super().update(instance, validated_data)

        if privileges_data is not None:
            instance.profile.privileges.set(privileges_data)

        return instance

class SystemSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = SystemSettings
        fields = '__all__'

class AdminAuthSerializer(serializers.Serializer):
    admin_password = serializers.CharField(write_only=True, required=True)
    reason = serializers.CharField(required=True, max_length=255)

class RecordDataEntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = RecordData
        fields = ['cell_id', 'cell_value']

class RecordDataUpdateSerializer(serializers.Serializer):
    data_entries = RecordDataEntrySerializer(many=True)
    reason_for_change = serializers.CharField(required=True, max_length=255)
    password = serializers.CharField(write_only=True, required=True)

class RecordListSerializer(serializers.ModelSerializer):
    template = TemplateListSerializer(read_only=True)
    created_by = UserReadOnlySerializer(read_only=True)
    class Meta:
        model = Record
        fields = ['id', 'record_id_display', 'template', 'status', 'created_at', 'created_by']

class RecordDetailSerializer(serializers.ModelSerializer):
    template = TemplateDetailSerializer(read_only=True)
    created_by = UserReadOnlySerializer(read_only=True)
    data_entries = RecordDataEntrySerializer(many=True, read_only=True, source='data_entries.all')
    signatures = serializers.SerializerMethodField(read_only=True)
    audit_trail = serializers.SerializerMethodField(read_only=True)
    template_id = serializers.PrimaryKeyRelatedField(queryset=Template.objects.filter(status='APPROVED'), write_only=True, source='template', label="Template")
    class Meta:
        model = Record
        fields = ['id', 'record_id_display', 'template', 'template_id', 'status', 'created_at', 'created_by', 'signatures', 'data_entries', 'audit_trail']
        read_only_fields = ['record_id_display', 'status', 'created_at', 'created_by', 'signatures', 'data_entries', 'audit_trail', 'template']
    def get_signatures(self, obj):
        signatures = ElectronicSignature.objects.filter(content_type=ContentType.objects.get_for_model(obj), object_id=obj.id).order_by('signed_at')
        return ElectronicSignatureSerializer(signatures, many=True).data
    def get_audit_trail(self, obj):
        audit_logs = AuditLog.objects.filter(content_type=ContentType.objects.get_for_model(obj), object_id=obj.id).order_by('-timestamp')
        return AuditLogSerializer(audit_logs, many=True).data

class UserProfileUpdateSerializer(serializers.ModelSerializer):
    current_password = serializers.CharField(write_only=True, required=True)
    reason = serializers.CharField(write_only=True, required=True)
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'current_password', 'reason']

class UserPasswordChangeSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only=True, required=True)
    new_password = serializers.CharField(write_only=True, required=True)
    reason = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        user = self.context['user']
        if not user.check_password(data['current_password']):
            raise ValidationError("Current password is not correct.")

        validator = GxPPasswordValidator(user=user)
        validator(data['new_password'])

        # --- THIS IS THE ENHANCEMENT ---
        settings, _ = SystemSettings.objects.get_or_create(pk=1)
        if settings.password_history_count > 0:
            recent_passwords = user.password_history.all()[:settings.password_history_count]
            for record in recent_passwords:
                if check_password(data['new_password'], record.password_hash):
                    raise ValidationError("This password has been used recently and cannot be reused.")
        # --- END OF ENHANCEMENT ---

        return data