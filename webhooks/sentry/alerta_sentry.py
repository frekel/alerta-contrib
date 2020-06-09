
from alerta.models.alert import Alert
from alerta.webhooks import WebhookBase


class SentryWebhook(WebhookBase):

    def incoming(self, query_string, payload):

        # For Sentry v9
        # Defaults to value before Sentry v9
        if 'request' in payload.get('event'):
            key = 'request'
        else:
            key = 'sentry.interfaces.Http'

        if 'env' in payload.get('event')[key]:
            if payload.get('event')[key]['env']['ENV'] == 'prod':
                environment = 'Production'
            else:
                environment = 'Development'
        else:
            environment = 'Production'

        if 'modules' in payload['event']:
            modules = ['{}=={}'.format(k, v) for k, v in payload['event']['modules'].items()]
        else:
            modules = []

        if payload['level'] == 'error':
            severity = 'critical'
        else:
            severity = 'ok'

        if payload['message'] == '':
            if 'title' in payload['event']:
              message = payload['event']['title']
            else:
              message = payload['url']
        else:
            message = payload['message']

        return Alert(
            resource=payload['culprit'],
            event=payload['id'],
            environment=environment,
            severity=severity,
            service=[payload['project']],
            group='Application',
            value=payload['level'],
            text=message,
            tags=['{}={}'.format(k, v) for k, v in payload['event']['tags']],
            attributes={'modules': modules, 'eventId': payload['event']['event_id'], sentryLink: '<a href="%s" target="_blank">Sentry URL</a>' % payload['url']},
            origin='sentry.io',
            raw_data=str(payload)
        )
