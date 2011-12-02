from django.contrib import admin
from oauth2.models import *

class AuthorizationInline(admin.TabularInline):
    model = Authorization

class AuthorizationTokenInline(admin.TabularInline):
    model = AuthorizationToken

class AccessTokenInline(admin.TabularInline):
    model = AccessToken

class RefreshTokenInline(admin.TabularInline):
    model = RefreshToken

class ClientApplicationAdmin(admin.ModelAdmin):
    inlines = [AuthorizationInline]
    exclude = ('client_id', 'client_secret')
    list_display = ('name', 'client_id', 'website_url', 'callback_url', 'description')
    list_display_links = ('name', 'client_id')
    readonly_fields = ('client_id', 'client_secret')
    search_fields = ('name', 'description')

class AuthorizationAdmin(admin.ModelAdmin):
    list_display = ('client', 'user', 'scope')
    inlines = [AuthorizationTokenInline, AccessTokenInline, RefreshTokenInline]

class TokenAdmin(admin.ModelAdmin):
    exclude = ('token',)
    readonly_fields = ('token',)

class ExpirableTokenAdmin(TokenAdmin):
    exclude = TokenAdmin.exclude + ('expires_at',)
    readonly_fields = TokenAdmin.readonly_fields + ('expires_at',)

admin.site.register(ClientApplication, ClientApplicationAdmin)
admin.site.register(Authorization, AuthorizationAdmin)
admin.site.register(AuthorizationToken, ExpirableTokenAdmin)
admin.site.register(AccessToken, ExpirableTokenAdmin)
admin.site.register(RefreshToken, TokenAdmin)
