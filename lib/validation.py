from pysros.wrappers import Container


def safe_get(data, *keys):
    try:
        for key in keys:
            if type(data) != dict and type(data) != Container:
                return None
            data = data.get(key)
    except KeyError:
        return None
    return data
