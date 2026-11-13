"""Gunicorn logging. The start script waits until /dev/log exists."""

logconfig_dict = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"msg": {"format": "dns-api: %(message)s"}},
    "handlers": {
        "syslog": {
            "class": "logging.handlers.SysLogHandler",
            "address": "/dev/log",
            "formatter": "msg",
        }
    },
    "loggers": {
        "gunicorn.error": {"level": "INFO", "handlers": ["syslog"], "propagate": False},
        "gunicorn.access": {"level": "INFO", "handlers": ["syslog"], "propagate": False},
    },
    "root": {"level": "INFO", "handlers": ["syslog"]},
}
accesslog = None
errorlog = None
capture_output = False
