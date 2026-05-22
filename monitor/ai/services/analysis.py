import hashlib
import json
import logging

from django.conf import settings
from django.utils import timezone

from monitor.ai.prompts.builders import (
    build_ai_instructions,
    build_error_upload_prompt,
    build_incident_prompt,
    build_report_prompt,
    sanitize_text,
)
from monitor.ai.providers.base import AIProviderError, AIProviderUnavailable
from monitor.ai.providers.registry import get_default_provider
from monitor.models import AIAnalysisCache, Alert, Incident, MonitorLog
from monitor.utils import get_site_status, normalize_domain_display


logger = logging.getLogger(__name__)


DEFAULT_CONTENT = {
    'summary': '',
    'outage_narrative': '',
    'availability_interpretation': '',
    'latency_interpretation': '',
    'suggested_fixes': [],
    'trends': [],
    'frequent_issues': [],
    'likely_causes': [],
    'recurring_patterns': [],
    'risk_indicators': [],
    'root_cause_hints': [],
}


def normalize_ai_content(content):
    normalized = DEFAULT_CONTENT.copy()
    if isinstance(content, dict):
        normalized.update({key: content.get(key, default) for key, default in DEFAULT_CONTENT.items()})

    if not normalized.get('recurring_patterns') and normalized.get('frequent_issues'):
        normalized['recurring_patterns'] = normalized.get('frequent_issues', [])
    if not normalized.get('root_cause_hints') and normalized.get('likely_causes'):
        normalized['root_cause_hints'] = normalized.get('likely_causes', [])

    for key in (
        'suggested_fixes',
        'trends',
        'frequent_issues',
        'likely_causes',
        'recurring_patterns',
        'risk_indicators',
        'root_cause_hints',
    ):
        value = normalized.get(key)
        if not isinstance(value, list):
            value = [value] if value else []
        normalized[key] = [sanitize_text(item, limit=260) for item in value if sanitize_text(item, limit=260)][:6]

    for key in ('summary', 'outage_narrative', 'availability_interpretation', 'latency_interpretation'):
        normalized[key] = sanitize_text(normalized.get(key), limit=520)

    return normalized


def hash_payload(payload):
    serialized = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode('utf-8')).hexdigest()


def get_ai_features_enabled():
    return bool(getattr(settings, 'AI_FEATURES_ENABLED', False))


def get_ai_status_for_display(cache, input_hash):
    if not get_ai_features_enabled():
        return {
            'available': False,
            'cache': cache,
            'is_stale': False,
            'message': 'AI operational intelligence is disabled for this environment.',
        }
    if cache is None:
        return {
            'available': True,
            'cache': None,
            'is_stale': False,
            'message': 'AI insights have not been generated for this data yet.',
        }
    return {
        'available': True,
        'cache': cache,
        'is_stale': cache.input_hash != input_hash,
        'message': '',
    }


def build_report_ai_payload(context):
    distribution = [
        {'label': row['label'], 'count': row['count'], 'percentage': row.get('percentage', 0)}
        for row in context.get('distribution_rows', [])
    ]
    return {
        'range': context.get('selected_range'),
        'logs_count': context.get('logs_count'),
        'total_issues_today': context.get('total_issues_today'),
        'average_uptime': context.get('average_uptime'),
        'average_response_time_ms': context.get('average_response_time'),
        'ssl_failures': context.get('ssl_failures'),
        'alert_counts': context.get('alert_counts'),
        'distribution': distribution,
        'slowest_websites': [
            {
                'domain': sanitize_text(item.get('display_domain')),
                'average_response_time_ms': item.get('average_response_time'),
            }
            for item in context.get('slowest_websites', [])[:5]
        ],
        'most_incidents': [
            {'domain': sanitize_text(item.get('display_domain')), 'total': item.get('total')}
            for item in context.get('most_incidents', [])[:5]
        ],
        'recent_outages': [
            {
                'domain': sanitize_text(getattr(incident.website, 'display_domain', normalize_domain_display(incident.website.url))),
                'status': incident.status_label,
                'type': incident.incident_type,
                'started_at': incident.started_at.isoformat(),
                'duration': incident.duration_display,
            }
            for incident in context.get('recent_outages', [])[:5]
        ],
        'error_analytics': {
            'has_data': context.get('error_analytics', {}).get('has_data', False),
            'total_occurrences': context.get('error_analytics', {}).get('total_occurrences', 0),
            'top_errors': [
                {
                    'error_type': sanitize_text(getattr(item, 'error_type', '')),
                    'category': getattr(item, 'category_label', ''),
                    'severity': getattr(item, 'severity_label', ''),
                    'count': getattr(item, 'count', 0),
                    'line': sanitize_text(getattr(item, 'raw_line', '')),
                }
                for item in context.get('error_analytics', {}).get('top_errors', [])[:6]
            ],
        },
    }


def build_error_upload_ai_payload(uploaded_log, summary):
    return {
        'filename': sanitize_text(uploaded_log.filename),
        'uploaded_at': uploaded_log.uploaded_at.isoformat(),
        'total_detected_errors': summary.get('total_detected_errors'),
        'recurring_errors_count': summary.get('recurring_errors_count'),
        'most_common_error': sanitize_text(getattr(summary.get('most_common_error'), 'error_type', '')),
        'severity_rows': summary.get('severity_rows'),
        'category_rows': summary.get('category_rows'),
        'top_errors': [
            {
                'error_type': sanitize_text(item.error_type),
                'category': item.category_label,
                'severity': item.severity_label,
                'count': item.count,
                'line_range': item.line_range_display,
                'line': sanitize_text(item.raw_line),
            }
            for item in summary.get('top_recurring_errors', [])[:8]
        ],
    }


def build_incident_ai_payload(incident):
    return {
        'incident_code': incident.incident_code,
        'website': sanitize_text(normalize_domain_display(incident.website.url)),
        'incident_type': incident.incident_type,
        'status': incident.status_label,
        'started_at': incident.started_at.isoformat(),
        'resolved_at': incident.resolved_at.isoformat() if incident.resolved_at else '',
        'duration': incident.duration_display,
        'latest_response_time_ms': incident.latest_response_time,
        'events': [
            {
                'type': event.event_type,
                'created_at': event.created_at.isoformat(),
                'message': sanitize_text(event.message),
            }
            for event in incident.events.all()[:8]
        ],
    }


def get_report_ai_state(user, context):
    payload = build_report_ai_payload(context)
    scope_key = f"range:{context.get('selected_range', '7d')}"
    input_hash = hash_payload(payload)
    cache = AIAnalysisCache.objects.filter(
        user=user,
        scope=AIAnalysisCache.SCOPE_REPORT,
        scope_key=scope_key,
    ).first()
    return get_ai_status_for_display(cache, input_hash) | {
        'input_hash': input_hash,
        'scope_key': scope_key,
    }


def get_error_upload_ai_state(user, uploaded_log, summary):
    payload = build_error_upload_ai_payload(uploaded_log, summary)
    scope_key = f"upload:{uploaded_log.id}"
    input_hash = hash_payload(payload)
    cache = AIAnalysisCache.objects.filter(
        user=user,
        scope=AIAnalysisCache.SCOPE_ERROR_UPLOAD,
        scope_key=scope_key,
    ).first()
    return get_ai_status_for_display(cache, input_hash) | {
        'input_hash': input_hash,
        'scope_key': scope_key,
    }


def get_incident_ai_state(user, incident, cache=None):
    payload = build_incident_ai_payload(incident)
    scope_key = f"incident:{incident.id}"
    input_hash = hash_payload(payload)
    if cache is None:
        cache = AIAnalysisCache.objects.filter(
            user=user,
            scope=AIAnalysisCache.SCOPE_INCIDENT,
            scope_key=scope_key,
        ).first()
    return get_ai_status_for_display(cache, input_hash) | {
        'input_hash': input_hash,
        'scope_key': scope_key,
    }


def generate_report_analysis(user, context, *, force=False):
    payload = build_report_ai_payload(context)
    return _generate_analysis(
        user=user,
        scope=AIAnalysisCache.SCOPE_REPORT,
        scope_key=f"range:{context.get('selected_range', '7d')}",
        input_hash=hash_payload(payload),
        prompt=build_report_prompt(payload),
        force=force,
    )


def generate_error_upload_analysis(user, uploaded_log, summary, *, force=False):
    payload = build_error_upload_ai_payload(uploaded_log, summary)
    return _generate_analysis(
        user=user,
        scope=AIAnalysisCache.SCOPE_ERROR_UPLOAD,
        scope_key=f"upload:{uploaded_log.id}",
        input_hash=hash_payload(payload),
        prompt=build_error_upload_prompt(payload),
        force=force,
    )


def generate_incident_analysis(user, incident, *, force=False):
    payload = build_incident_ai_payload(incident)
    return _generate_analysis(
        user=user,
        scope=AIAnalysisCache.SCOPE_INCIDENT,
        scope_key=f"incident:{incident.id}",
        input_hash=hash_payload(payload),
        prompt=build_incident_prompt(payload),
        force=force,
    )


def _generate_analysis(*, user, scope, scope_key, input_hash, prompt, force=False):
    cache = AIAnalysisCache.objects.filter(user=user, scope=scope, scope_key=scope_key).first()
    if cache and cache.input_hash == input_hash and cache.status == AIAnalysisCache.STATUS_READY and not force:
        return cache

    if not get_ai_features_enabled():
        return _store_cache(
            cache=cache,
            user=user,
            scope=scope,
            scope_key=scope_key,
            input_hash=input_hash,
            status=AIAnalysisCache.STATUS_DISABLED,
            content={},
            provider='none',
            model_name='',
            error_message='AI operational intelligence is disabled.',
        )

    provider = get_default_provider()
    try:
        content = provider.generate_json(
            instructions=build_ai_instructions(),
            input_text=prompt,
        )
    except (AIProviderUnavailable, AIProviderError) as exc:
        provider_name = getattr(provider, 'provider_name', 'unknown')
        model_name = getattr(provider, 'model', '')
        logger.warning(
            "AI analysis generation failed: %s",
            sanitize_text(str(exc), limit=180),
            extra={
                'ai_scope': scope,
                'scope_key': scope_key,
                'provider': provider_name,
                'model': model_name,
            },
        )
        if cache and cache.status == AIAnalysisCache.STATUS_READY:
            return cache
        return _store_cache(
            cache=cache,
            user=user,
            scope=scope,
            scope_key=scope_key,
            input_hash=input_hash,
            status=AIAnalysisCache.STATUS_FAILED,
            content={},
            provider=provider_name,
            model_name=model_name,
            error_message=sanitize_text(str(exc), limit=520),
        )

    return _store_cache(
        cache=cache,
        user=user,
        scope=scope,
        scope_key=scope_key,
        input_hash=input_hash,
        status=AIAnalysisCache.STATUS_READY,
        content=normalize_ai_content(content),
        provider=getattr(provider, 'provider_name', 'unknown'),
        model_name=getattr(provider, 'model', ''),
        error_message='',
    )


def _store_cache(*, cache, user, scope, scope_key, input_hash, status, content, provider, model_name, error_message):
    if cache is None:
        cache = AIAnalysisCache(user=user, scope=scope, scope_key=scope_key)
    cache.input_hash = input_hash
    cache.status = status
    cache.content = normalize_ai_content(content) if content else {}
    cache.provider = provider
    cache.model_name = model_name
    cache.error_message = error_message
    cache.generated_at = timezone.now()
    cache.save()
    return cache
