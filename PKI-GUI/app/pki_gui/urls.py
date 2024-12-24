from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('tenants/<slug:tenant_slug>/', include('app.urls')),  # Kiracıya özgü URL'ler
    path('', include('app.urls'))
]
