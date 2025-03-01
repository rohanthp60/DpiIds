from django.apps import AppConfig


class AdmindashConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'admindash'

    def ready(self):
        import admindash.signals
