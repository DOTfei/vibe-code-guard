def synthetic_handler(value):
    # Safe fixture marker: this function is not executed by the tests.
    return {"value": value, "fixture": True}
