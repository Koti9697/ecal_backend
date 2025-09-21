# In api/views.py

from django.utils import timezone
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import User, Group
from django.db import transaction, IntegrityError
from django.shortcuts import get_object_or_404
from django.db.models import Q
import json

from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.exceptions import PermissionDenied, ValidationError

from .models import (
    Template, Record, AuditLog, ElectronicSignature, RecordData,
    SystemSettings, Privilege, PasswordHistory, GroupProfile
)
from . import serializers
from .filters import AuditLogFilter, RecordReportFilter, TemplateFilter
from .permissions import HasPrivilege

def _create_audit_log(user, action, content_object, details, reason, previous_value=None, new_value=None):
    AuditLog.objects.create(
        user=user,
        action=action,
        content_object=content_object,
        details=details,
        reason_for_change=reason,
        previous_value=str(previous_value) if previous_value is not None else None,
        new_value=str(new_value) if new_value is not None else None
    )

def _create_e_signature(user, content_object, meaning):
    ElectronicSignature.objects.create(signed_by=user, content_object=content_object, meaning=meaning)

def _compare_and_log_document_changes(user, instance, old_doc, new_doc, reason):
    old_doc = old_doc or {}
    new_doc = new_doc or {}

    def compare_fields(field_list_old, field_list_new, section_name):
        old_fields = {f['id']: f for f in field_list_old}
        new_fields = {f['id']: f for f in field_list_new}

        for field_id, new_field in new_fields.items():
            if field_id not in old_fields:
                _create_audit_log(user, "Template Design Change", instance, f"Field '{new_field.get('label', 'N/A')}' added to {section_name}.", reason, None, new_field.get('label'))
            else:
                old_field = old_fields[field_id]
                for key in new_field:
                    if key != 'id' and old_field.get(key) != new_field.get(key):
                        _create_audit_log(user, "Template Design Change", instance, f"Field '{old_field.get('label', 'N/A')}' in {section_name} had property '{key}' changed.", reason, old_field.get(key), new_field.get(key))

        for field_id, old_field in old_fields.items():
            if field_id not in new_fields:
                _create_audit_log(user, "Template Design Change", instance, f"Field '{old_field.get('label', 'N/A')}' removed from {section_name}.", reason, old_field.get('label'), None)

    for section_key, section_name in [('header', 'Template Information'), ('sampleInfo', 'Analysis Information'), ('calculation', 'Results Section')]:
        old_section_fields = old_doc.get(section_key, {}).get('fields', [])
        new_section_fields = new_doc.get(section_key, {}).get('fields', [])
        compare_fields(old_section_fields, new_section_fields, section_name)

    old_data_sections = {s['id']: s for s in old_doc.get('dataInputs', {}).get('sections', [])}
    new_data_sections = {s['id']: s for s in new_doc.get('dataInputs', {}).get('sections', [])}

    for section_id, new_section in new_data_sections.items():
        if section_id not in old_data_sections:
            _create_audit_log(user, "Template Design Change", instance, f"Section '{new_section['title']}' added to Data Inputs.", reason, None, new_section['title'])
            compare_fields([], new_section.get('fields', []), new_section['title'])
        else:
            old_section = old_data_sections[section_id]
            if old_section['title'] != new_section['title']:
                _create_audit_log(user, "Template Design Change", instance, f"Section title changed in Data Inputs.", reason, old_section['title'], new_section['title'])
            compare_fields(old_section.get('fields', []), new_section.get('fields', []), new_section['title'])

    for section_id, old_section in old_data_sections.items():
        if section_id not in new_data_sections:
            _create_audit_log(user, "Template Design Change", instance, f"Section '{old_section['title']}' removed from Data Inputs.", reason, old_section['title'], None)


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = serializers.MyTokenObtainPairSerializer

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all().order_by('username')
    permission_classes = [HasPrivilege]
    required_privileges = {
        'create': 'MANAGE_USERS_AND_ROLES', 'update': 'MANAGE_USERS_AND_ROLES',
        'partial_update': 'MANAGE_USERS_AND_ROLES', 'list': 'MANAGE_USERS_AND_ROLES',
        'retrieve': 'MANAGE_USERS_AND_ROLES', 'set_status': 'MANAGE_USERS_AND_ROLES',
    }
    def get_serializer_class(self):
        if self.action in ['list', 'retrieve']: return serializers.UserReadOnlySerializer
        return serializers.UserWriteSerializer

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        admin_user = request.user
        password = serializer.validated_data.get('admin_password')
        reason = serializer.validated_data.get('reason_for_change')

        if not password or not admin_user.check_password(password):
            raise PermissionDenied("Your password is required and must be correct to perform this action.")

        user_password = serializer.validated_data.get('password')
        if not user_password:
            raise ValidationError({'password': 'A password is required for new users.'})

        try:
            user = User.objects.create_user(
                username=serializer.validated_data['username'],
                password=user_password,
                first_name=serializer.validated_data.get('first_name', ''),
                last_name=serializer.validated_data.get('last_name', ''),
                email=serializer.validated_data.get('email', '')
            )
            user.groups.set(serializer.validated_data['groups'])
            PasswordHistory.objects.create(user=user, password_hash=user.password)

        except IntegrityError:
            raise ValidationError({'username': 'A user with that username already exists.'})

        details = f"User account '{user.username}' created. Assigned roles: {[g.name for g in user.groups.all()]}."
        _create_audit_log(admin_user, "User Creation", user, details, reason)

        return Response(serializers.UserReadOnlySerializer(user).data, status=status.HTTP_201_CREATED)

    @transaction.atomic
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=kwargs.get('partial', False))
        serializer.is_valid(raise_exception=True)

        admin_user = request.user
        password = serializer.validated_data.get('admin_password')
        reason = serializer.validated_data.get('reason_for_change')

        if not password or not admin_user.check_password(password):
            raise PermissionDenied("Your password is required and must be correct to perform this action.")

        for attr, value in serializer.validated_data.items():
            if attr in ['first_name', 'last_name', 'email']:
                old_value = getattr(instance, attr)
                if old_value != value:
                    _create_audit_log(admin_user, "User Update", instance, f"User field '{attr}' changed.", reason, old_value, value)

        old_groups = set(instance.groups.all())
        new_groups = set(serializer.validated_data.get('groups', old_groups))
        if old_groups != new_groups:
             _create_audit_log(admin_user, "User Update", instance, "User roles changed.", reason, [g.name for g in old_groups], [g.name for g in new_groups])

        user = serializer.save()

        if 'password' in serializer.validated_data and serializer.validated_data['password']:
            user.set_password(serializer.validated_data['password'])
            user.save()
            PasswordHistory.objects.create(user=user, password_hash=user.password)
            _create_audit_log(admin_user, "User Update", instance, "User password changed.", reason)

        return Response(serializers.UserReadOnlySerializer(user).data)

    @action(detail=True, methods=['post'], url_path='set-status')
    def set_status(self, request, pk=None):
        user_to_modify = self.get_object()
        admin_user = request.user
        password = request.data.get('password')
        reason = request.data.get('reason_for_change')
        new_status = request.data.get('is_active')

        if not reason or not password:
            return Response({'detail': 'Password and reason are required.'}, status=status.HTTP_400_BAD_REQUEST)

        if not admin_user.check_password(password):
            raise PermissionDenied('Incorrect administrator password provided.')

        if new_status not in [True, False]:
            return Response({'detail': 'A valid status (true or false) must be provided.'}, status=status.HTTP_400_BAD_REQUEST)

        previous_status = user_to_modify.is_active
        user_to_modify.is_active = new_status
        user_to_modify.save()

        status_text = "activated" if new_status else "deactivated"
        details = f"User account for '{user_to_modify.username}' {status_text}."
        _create_audit_log(admin_user, "User Management", user_to_modify, details, reason, previous_status, new_status)

        return Response({'status': f'User {status_text} successfully'}, status=status.HTTP_200_OK)


class TemplateViewSet(viewsets.ModelViewSet):
    permission_classes = [HasPrivilege]
    filter_backends = [DjangoFilterBackend]
    filterset_class = TemplateFilter
    required_privileges = {
        'create': 'MANAGE_TEMPLATES', 'update': 'MANAGE_TEMPLATES', 'list': 'VIEW_ALL_RECORDS_TEMPLATES',
        'retrieve': 'VIEW_ALL_RECORDS_TEMPLATES', 'submit': 'MANAGE_TEMPLATES', 'review': 'PERFORM_REVIEW',
        'approve': 'PERFORM_APPROVAL', 'revise': 'MANAGE_TEMPLATES',
        'reject': ['PERFORM_REVIEW', 'PERFORM_APPROVAL'],
        'acknowledge_rejection': 'MANAGE_TEMPLATES',
        'verify': 'MANAGE_TEMPLATES',
    }

    def get_serializer_class(self):
        if self.action == 'list': return serializers.TemplateListSerializer
        elif self.action == 'verify': return serializers.TemplateVerificationSerializer
        return serializers.TemplateDetailSerializer

    def get_queryset(self):
        user = self.request.user
        user_privileges = set(user.groups.filter(profile__privileges__name__isnull=False).values_list('profile__privileges__name', flat=True))

        if user.is_superuser or 'MANAGE_SYSTEM_SETTINGS' in user_privileges:
            return Template.objects.all().order_by('name', '-major_version', '-minor_version')

        view_only_privileges = {'VIEW_ALL_RECORDS_TEMPLATES', 'VIEW_RECORD_SPECIFIC_AUDIT_TRAIL', 'VIEW_SYSTEM_WIDE_AUDIT_TRAIL', 'GENERATE_REPORTS_FOR_RECORDS'}
        if user_privileges.issubset(view_only_privileges):
            return Template.objects.filter(status='APPROVED').order_by('name', '-major_version', '-minor_version')

        query = Q(status__in=['APPROVED', 'RETIRED'])
        if 'MANAGE_TEMPLATES' in user_privileges:
            query |= Q(created_by=user) | Q(status='REJECTED')
        if 'PERFORM_REVIEW' in user_privileges:
            query |= Q(status='SUBMITTED_FOR_REVIEW')
        if 'PERFORM_APPROVAL' in user_privileges:
            query |= Q(status='REVIEWED')

        return Template.objects.filter(query).distinct().order_by('name', '-major_version', '-minor_version')

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        admin_password = serializer.validated_data.get('admin_password')
        reason = serializer.validated_data.get('reason_for_change')
        if admin_password and not request.user.check_password(admin_password):
            raise PermissionDenied("Incorrect administrator password provided.")
        template = serializer.save(created_by=request.user)
        details = f"Template '{template.name}' version {template.version} created."
        _create_audit_log(request.user, "Template Creation", template, details, reason or "Initial Draft Creation")
        headers = self.get_success_headers(serializer.data)
        return Response(serializers.TemplateDetailSerializer(template).data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=kwargs.get('partial', False))
        serializer.is_valid(raise_exception=True)

        reason = serializer.validated_data.get('reason_for_change')
        admin_password = serializer.validated_data.get('admin_password')

        if not reason or not admin_password:
            raise ValidationError("Password and reason for change are mandatory for updates.")
        if not request.user.check_password(admin_password):
            raise PermissionDenied("Incorrect administrator password provided.")

        validated_data = serializer.validated_data

        for attr in ['name', 'major_version', 'minor_version']:
            if attr in validated_data and getattr(instance, attr) != validated_data[attr]:
                _create_audit_log(
                    request.user, "Template Edit", instance, f"Template {attr.replace('_', ' ')} changed.",
                    reason, getattr(instance, attr), validated_data[attr]
                )

        if 'document_data' in validated_data:
            _compare_and_log_document_changes(request.user, instance, instance.document_data or {}, validated_data['document_data'], reason)

        self.perform_update(serializer)
        return Response(serializer.data)

    def _handle_workflow_action(self, request, pk, new_status, meaning):
        template = self.get_object()
        serializer = serializers.SignatureSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if not request.user.check_password(serializer.validated_data['password']):
            raise PermissionDenied("Incorrect password.")

        previous_status = template.status
        template.status = new_status

        if new_status == 'APPROVED':
            template.approved_at = timezone.now()

        template.save()
        reason = serializer.validated_data['reason']
        _create_e_signature(request.user, template, meaning)
        _create_audit_log(request.user, "Template Workflow", template, f"Template status changed to {new_status}.", reason, previous_status, new_status)

        if new_status == 'APPROVED' and template.parent_template:
            template.parent_template.status = 'RETIRED'
            template.parent_template.save()
            _create_audit_log(request.user, "Template Workflow", template.parent_template, f"Template retired, superseded by v{template.version}.", "Automatic retirement")

        return Response(serializers.TemplateDetailSerializer(template).data)

    @action(detail=True, methods=['post'])
    def submit(self, request, pk=None):
        return self._handle_workflow_action(request, pk, 'SUBMITTED_FOR_REVIEW', "Submitted")
    @action(detail=True, methods=['post'])
    def review(self, request, pk=None):
        return self._handle_workflow_action(request, pk, 'REVIEWED', "Reviewed")
    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        return self._handle_workflow_action(request, pk, 'APPROVED', "Approved")
    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        return self._handle_workflow_action(request, pk, 'REJECTED', "Rejected")
    @action(detail=True, methods=['post'])
    def acknowledge_rejection(self, request, pk=None):
        return self._handle_workflow_action(request, pk, 'DRAFT', "Rejection Acknowledged")

    @action(detail=True, methods=['post'])
    @transaction.atomic
    def verify(self, request, pk=None):
        template = self.get_object()
        serializer = serializers.TemplateVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if not request.user.check_password(serializer.validated_data['password']):
            raise PermissionDenied("Incorrect password.")
        template.document_data['verification_data'] = serializer.validated_data['verification_data']
        template.status = 'VERIFIED'
        template.save()
        reason = serializer.validated_data['reason']
        _create_e_signature(request.user, template, "Verified")
        _create_audit_log(request.user, "Template Workflow", template, "Template design and calculations verified.", reason)
        return Response(serializers.TemplateDetailSerializer(template).data)

    @action(detail=True, methods=['post'])
    @transaction.atomic
    def revise(self, request, pk=None):
        original_template = self.get_object()
        serializer = serializers.SignatureSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if not request.user.check_password(serializer.validated_data['password']):
            raise PermissionDenied("Incorrect password.")
        new_template = Template.objects.create(
            name=original_template.name,
            major_version=original_template.major_version,
            minor_version=original_template.minor_version + 1,
            document_data=original_template.document_data,
            created_by=request.user,
            status='DRAFT',
            parent_template=original_template
        )
        reason = serializer.validated_data['reason']
        _create_audit_log(request.user, "Template Revision", new_template, f"Template revised from v{original_template.version} to v{new_template.version}", reason)
        return Response(serializers.TemplateDetailSerializer(new_template).data, status=status.HTTP_201_CREATED)

class RecordViewSet(viewsets.ModelViewSet):
    queryset = Record.objects.all().order_by('-created_at')
    permission_classes = [HasPrivilege]
    required_privileges = {
        'create': 'CREATE_EDIT_DRAFT_RECORDS',
        'list': 'VIEW_ALL_RECORDS_TEMPLATES',
        'retrieve': 'VIEW_ALL_RECORDS_TEMPLATES',
        'save_data': 'CREATE_EDIT_DRAFT_RECORDS',
        'submit': 'SUBMIT_RECORD_FOR_REVIEW',
        'review': 'PERFORM_REVIEW',
        'approve': 'PERFORM_APPROVAL',
        'reject': ['PERFORM_REVIEW', 'PERFORM_APPROVAL'],
        'cancel': 'CREATE_EDIT_DRAFT_RECORDS',
        'acknowledge_rejection': 'CREATE_EDIT_DRAFT_RECORDS',
    }

    def get_serializer_class(self):
        if self.action == 'list': return serializers.RecordListSerializer
        elif self.action == 'save_data': return serializers.RecordDataUpdateSerializer
        return serializers.RecordDetailSerializer

    def get_queryset(self):
        user = self.request.user
        user_privileges = set(user.groups.filter(profile__privileges__name__isnull=False).values_list('profile__privileges__name', flat=True))

        if user.is_superuser or 'MANAGE_SYSTEM_SETTINGS' in user_privileges:
            return Record.objects.all().order_by('-created_at')

        view_only_privileges = {'VIEW_ALL_RECORDS_TEMPLATES', 'VIEW_RECORD_SPECIFIC_AUDIT_TRAIL', 'VIEW_SYSTEM_WIDE_AUDIT_TRAIL', 'GENERATE_REPORTS_FOR_RECORDS'}
        if user_privileges.issubset(view_only_privileges):
            return Record.objects.filter(status='APPROVED').order_by('-created_at')

        query = Q(status='APPROVED')
        if 'CREATE_EDIT_DRAFT_RECORDS' in user_privileges:
            query |= Q(created_by=user) | Q(status__in=['REJECTED', 'CANCELLED'])
        if 'PERFORM_REVIEW' in user_privileges:
             query |= Q(status__in=['SUBMITTED_FOR_REVIEW', 'REJECTED', 'CANCELLED'])
        if 'PERFORM_APPROVAL' in user_privileges:
             query |= Q(status__in=['REVIEWED', 'REJECTED', 'CANCELLED'])

        return Record.objects.filter(query).distinct().order_by('-created_at')


    def perform_create(self, serializer):
        record = serializer.save(created_by=self.request.user)
        _create_audit_log(self.request.user, "Record Creation", record, f"Record '{record.record_id_display}' created in DRAFT status.", "Initial Record Creation")

    @action(detail=True, methods=['patch'], url_path='save-data')
    @transaction.atomic
    def save_data(self, request, pk=None):
        record = self.get_object()
        if record.status != 'DRAFT':
            return Response({'detail': 'Data can only be saved for records in DRAFT status.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = serializers.RecordDataUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if not request.user.check_password(serializer.validated_data['password']):
            raise PermissionDenied("Incorrect password.")

        reason = serializer.validated_data['reason_for_change']

        for entry in serializer.validated_data['data_entries']:
            try:
                data_obj = RecordData.objects.get(record=record, cell_id=entry['cell_id'])
                previous_value = data_obj.cell_value
            except RecordData.DoesNotExist:
                previous_value = None

            new_value = entry['cell_value']

            if previous_value != new_value:
                data_obj, created = RecordData.objects.update_or_create(
                    record=record,
                    cell_id=entry['cell_id'],
                    defaults={'cell_value': new_value, 'previous_value': previous_value}
                )

                details = f"Value for '{entry['cell_id']}' changed."
                _create_audit_log(request.user, "Data Entry", record, details, reason, previous_value, new_value)

        return Response(serializers.RecordDetailSerializer(record).data)

    def _handle_workflow_action(self, request, pk, new_status, meaning):
        record = self.get_object()
        serializer = serializers.SignatureSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if not request.user.check_password(serializer.validated_data['password']):
            raise PermissionDenied("Incorrect password.")

        previous_status = record.status
        record.status = new_status
        record.save()
        reason = serializer.validated_data['reason']
        _create_e_signature(request.user, record, meaning)
        _create_audit_log(request.user, "Record Workflow", record, f"Record status changed to {new_status}.", reason, previous_status, new_status)
        return Response(serializers.RecordDetailSerializer(record).data)

    @action(detail=True, methods=['post'])
    def submit(self, request, pk=None):
        return self._handle_workflow_action(request, pk, 'SUBMITTED_FOR_REVIEW', "Submitted for Review")
    @action(detail=True, methods=['post'])
    def review(self, request, pk=None):
        return self._handle_workflow_action(request, pk, 'REVIEWED', "Reviewed")
    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        return self._handle_workflow_action(request, pk, 'APPROVED', "Approved")
    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        return self._handle_workflow_action(request, pk, 'REJECTED', "Rejected")
    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        return self._handle_workflow_action(request, pk, 'CANCELLED', "Cancelled")
    @action(detail=True, methods=['post'], url_path='acknowledge-rejection')
    def acknowledge_rejection(self, request, pk=None):
        return self._handle_workflow_action(request, pk, 'DRAFT', "Rejection Acknowledged")

class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AuditLog.objects.all().order_by('-timestamp')
    serializer_class = serializers.AuditLogSerializer
    permission_classes = [HasPrivilege]
    required_privileges = {'list': 'VIEW_SYSTEM_WIDE_AUDIT_TRAIL'}
    filter_backends = [DjangoFilterBackend]
    filterset_class = AuditLogFilter

class GroupViewSet(viewsets.ModelViewSet):
    queryset = Group.objects.all().order_by('name')
    permission_classes = [HasPrivilege]
    required_privileges = {
        'create': 'MANAGE_USERS_AND_ROLES', 'update': 'MANAGE_USERS_AND_ROLES',
        'list': 'MANAGE_USERS_AND_ROLES', 'retrieve': 'MANAGE_USERS_AND_ROLES'
    }

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return serializers.GroupWriteSerializer
        return serializers.GroupReadSerializer

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        admin_user = request.user
        password = serializer.validated_data.pop('admin_password')
        reason = serializer.validated_data.pop('reason_for_change')
        privileges_data = serializer.validated_data.pop('privileges', [])

        if not admin_user.check_password(password):
            raise PermissionDenied("Incorrect administrator password provided.")

        group = Group.objects.create(name=serializer.validated_data['name'])
        group.profile.privileges.set(privileges_data)

        details = f"Role '{group.name}' created. Privileges assigned: {[p.name for p in group.profile.privileges.all()]}."
        _create_audit_log(admin_user, "Role Management", group, details, reason)

        return Response(serializers.GroupReadSerializer(group).data, status=status.HTTP_201_CREATED)

    @transaction.atomic
    def update(self, request, *args, **kwargs):
        instance = self.get_object()

        old_name = instance.name
        old_privileges = set(instance.profile.privileges.all())

        serializer = self.get_serializer(instance, data=request.data, partial=kwargs.get('partial', False))
        serializer.is_valid(raise_exception=True)

        admin_user = request.user
        password = serializer.validated_data.pop('admin_password')
        reason = serializer.validated_data.pop('reason_for_change')
        privileges_data = serializer.validated_data.pop('privileges', None)

        if not admin_user.check_password(password):
            raise PermissionDenied("Incorrect administrator password provided.")

        instance.name = serializer.validated_data.get('name', instance.name)
        instance.save()

        if privileges_data is not None:
            instance.profile.privileges.set(privileges_data)

        new_privileges = set(instance.profile.privileges.all())

        if old_privileges != new_privileges:
            _create_audit_log(
                admin_user, "Role Management", instance, "Role privileges updated.", reason,
                [p.name for p in old_privileges], [p.name for p in new_privileges]
            )

        if old_name != instance.name:
            _create_audit_log(admin_user, "Role Management", instance, "Role name changed.", reason, old_name, instance.name)

        return Response(serializers.GroupReadSerializer(instance).data)


class PrivilegeViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Privilege.objects.all().order_by('name')
    serializer_class = serializers.PrivilegeSerializer
    permission_classes = [HasPrivilege]
    required_privileges = {'list': 'MANAGE_USERS_AND_ROLES'}

class RecordReportViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Record.objects.select_related('template', 'created_by').all()
    serializer_class = serializers.RecordReportSerializer
    permission_classes = [HasPrivilege]
    required_privileges = {'list': 'GENERATE_REPORTS_FOR_RECORDS'}
    filter_backends = [DjangoFilterBackend]
    filterset_class = RecordReportFilter

class SystemSettingsViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def get_permissions(self):
        if self.action == 'update_settings':
            return [HasPrivilege()]
        return super().get_permissions()

    required_privileges = {
        'update_settings': 'MANAGE_SYSTEM_SETTINGS'
    }

    def list(self, request):
        settings, created = SystemSettings.objects.get_or_create(pk=1)
        serializer = serializers.SystemSettingsSerializer(settings)
        return Response(serializer.data)

    @action(detail=False, methods=['put'], url_path='update-settings')
    @transaction.atomic
    def update_settings(self, request):
        settings = SystemSettings.objects.get(pk=1)
        serializer = serializers.SystemSettingsSerializer(instance=settings, data=request.data)
        serializer.is_valid(raise_exception=True)

        admin_user = request.user
        password = request.data.get('admin_password')
        reason = request.data.get('reason')

        if not reason or not password:
            return Response({'detail': 'Password and reason are required.'}, status=status.HTTP_400_BAD_REQUEST)
        if not admin_user.check_password(password):
            raise PermissionDenied("Incorrect administrator password provided.")

        validated_data = serializer.validated_data
        for key, value in validated_data.items():
            old_value = getattr(settings, key)
            if old_value != value:
                _create_audit_log(
                    admin_user, "System Settings", None, f"System setting '{key}' changed.",
                    reason, old_value, value
                )

        serializer.save()
        return Response(serializer.data)

class MyProfileViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request):
        """Get the current user's profile information."""
        serializer = serializers.MyProfileSerializer(request.user)
        return Response(serializer.data)

    @action(detail=False, methods=['put'], url_path='update-details')
    def update_details(self, request):
        """Update the user's first name, last name, and email."""
        user = request.user
        serializer = serializers.UserProfileUpdateSerializer(user, data=request.data)
        serializer.is_valid(raise_exception=True)

        reason = serializer.validated_data.get('reason')
        password = serializer.validated_data.get('current_password')

        if not user.check_password(password):
            raise PermissionDenied("Incorrect password.")

        for attr in ['first_name', 'last_name', 'email']:
            if attr in serializer.validated_data:
                old_value = getattr(user, attr)
                new_value = serializer.validated_data[attr]
                if old_value != new_value:
                    _create_audit_log(user, "Profile Update", user, f"User updated their own {attr.replace('_', ' ')}.", reason, old_value, new_value)

        serializer.save()
        return Response(serializers.UserReadOnlySerializer(user).data)

    @action(detail=False, methods=['post'], url_path='change-password')
    def change_password(self, request):
        """Change the user's password."""
        user = request.user
        serializer = serializers.UserPasswordChangeSerializer(data=request.data, context={'user': user})
        serializer.is_valid(raise_exception=True)

        user.set_password(serializer.validated_data['new_password'])
        user.save()
        PasswordHistory.objects.create(user=user, password_hash=user.password)

        _create_audit_log(user, "Profile Update", user, "User changed their own password.", serializer.validated_data['reason'])
        return Response({"status": "password set successfully"})

    @action(detail=False, methods=['post'], url_path='close-account')
    def close_account(self, request):
        """Allow a user to deactivate their own account."""
        user = request.user
        settings, _ = SystemSettings.objects.get_or_create(pk=1)
        if not settings.allow_user_account_closure:
            raise PermissionDenied("Users are not permitted to close their own accounts.")

        serializer = serializers.SignatureSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if not user.check_password(serializer.validated_data['password']):
            raise PermissionDenied("Incorrect password.")

        user.is_active = False
        user.save()
        _create_audit_log(user, "Profile Update", user, "User closed their own account.", serializer.validated_data['reason'], True, False)
        return Response({"status": "Account closed."})