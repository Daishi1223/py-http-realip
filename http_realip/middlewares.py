from django.conf import settings
from .func import (check_if_trusted,
                  get_from_X_FORWARDED_FOR as _get_from_xff,
                  get_from_X_REAL_IP)

trusted_list = (settings.REAL_IP_TRUSTED_LIST
                if hasattr(settings, 'REAL_IP_TRUSTED_LIST')
                else [])

def get_from_X_FORWARDED_FOR(header):
    return _get_from_xff(header, trusted_list)

func_map = {'HTTP_X_REAL_IP': get_from_X_REAL_IP,
            'HTTP_X_FORWARDED_FOR': get_from_X_FORWARDED_FOR}

real_ip_headers = (settings.REAL_IP_HEADERS
                   if hasattr(settings, 'REAL_IP_HEADERS')
                   else ['HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR'])


class DjangoRealIPMiddleware(object):
    def process_request(self, request):
        if not check_if_trusted(request.META['REMOTE_ADDR'], trusted_list):
            # Only header from trusted ip can be used
            return

        for header_name in real_ip_headers:
            try:
                # Get the parsing function
                func = func_map[header_name]
                # Get the header value
                header = request.META[header_name]
            except KeyError:
                continue

            # Parse the real ip
            real_ip = func(header)
            if real_ip:
                request.META['REMOTE_ADDR'] = real_ip
                break
