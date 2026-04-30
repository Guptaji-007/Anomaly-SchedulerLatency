"""ml_model package

This package exposes the ML pipeline components but performs lazy imports
so that importing the package itself doesn't execute heavy dependencies
(pandas/scikit-learn) at import time. Consumers should import specific
symbols (for example ``from ml_model.realtime_detector import RealtimeDetector``)
which will load modules as needed.
"""

__version__ = "1.0.0"
__author__ = "OELP Project"

# Map public names -> module that defines them. We import lazily on access.
_IMPORT_MAP = {
    'DatasetGenerator': 'ml_model.dataset_generator',
    'AnomalyDetector': 'ml_model.model_trainer',
    'CauseClassifier': 'ml_model.model_trainer',
    'ModelEvaluator': 'ml_model.model_trainer',
    'RealtimeDetector': 'ml_model.realtime_detector',
    'DetectionLogger': 'ml_model.realtime_detector',
    'MLPipeline': 'ml_model.ml_pipeline',
    'Config': 'ml_model.config',
    'get_config': 'ml_model.config',
    'update_config': 'ml_model.config',
    'CollectorIntegration': 'ml_model.utils',
    'ValidationTest': 'ml_model.utils',
    'PerformanceProfiler': 'ml_model.utils',
    'ReportGenerator': 'ml_model.utils',
}

__all__ = list(_IMPORT_MAP.keys())


def __getattr__(name: str):
    """Lazily import and return requested attribute from its module."""
    if name in _IMPORT_MAP:
        module_name = _IMPORT_MAP[name]
        module = __import__(module_name, fromlist=[name])
        attr = getattr(module, name)
        globals()[name] = attr
        return attr
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(list(globals().keys()) + list(_IMPORT_MAP.keys()))
