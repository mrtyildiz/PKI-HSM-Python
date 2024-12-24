from django.http import Http404
from django.utils.deprecation import MiddlewareMixin
from tenant_schemas.utils import get_tenant_model
from .models import Client  # Kullanılan modeli dahil edin

class ClientMiddleware(MiddlewareMixin):
    def process_request(self, request):
        hostname = request.get_host()
        parts = request.path_info.strip('/').split('/')
        
        # Kiracıyı çıkarmak için özel bir URL örüntüsüne göre ayarlayabilirsiniz.
        # Örneğin, "/tenants/mytenant/" URL'sinden kiracıyı alabiliriz.
        if len(parts) >= 2 and parts[0] == 'tenants':
            tenant_slug = parts[1]
            try:
                # Kiracıyı veritabanından alın.
                tenant = get_tenant_model().objects.get(domain_url=hostname, schema_name=tenant_slug)
                print(tenant)
                # Kiracıyı request nesnesine ekleyin.
                request.tenant = tenant
                # İstemci (Client) nesnelerini sorgulamak için kullanabilirsiniz.
                clients = Client.objects.filter(tenant=tenant)
                request.clients = clients
            except get_tenant_model().DoesNotExist:
                raise Http404("Tenant not found")
