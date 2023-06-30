
import logging
import yaml

from ghascompliance.policies.models.base import PolicyV3

logger = logging.getLogger("ghascompliance.policies")


def loadPolicy(path: str) -> PolicyV3:
    # TODO: check schemas
    logging.debug(f"Loading Policy from file :: {path}")

    with open(path, "r") as handle:
        data = yaml.safe_load(handle)
    print(data)
    model = _dataclass_from_dict(PolicyV3, data)

    return model


def _dataclass_from_dict(klass, dikt):
    try:
        fieldtypes = klass.__annotations__
        return klass(**{f: _dataclass_from_dict(fieldtypes[f], dikt[f]) for f in dikt})
    except KeyError as err:
        if issubclass(klass, dict):
            return dict(dikt)
        raise Exception(f"Unknown key being set in configuration file : {err}")
    except AttributeError as err:
        if isinstance(dikt, (tuple, list)):
            return [_dataclass_from_dict(klass.__args__[0], f) for f in dikt]
        return dikt


