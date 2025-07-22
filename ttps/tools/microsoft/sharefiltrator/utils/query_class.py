class Query:
    def __init__(self, querytext, refinementfilters, enablefql, queryname=None):
        self.querytext = querytext
        self.refinementfilters = refinementfilters
        self.enablefql = enablefql
        self.queryname = queryname

    @classmethod
    def from_json(cls, json_data):
        normalized_data = {k.lower(): v for k, v in json_data.items()}
        querytext = normalized_data.get("querytext", "")
        refinementfilters = normalized_data.get("refinementfilters", None)
        enablefql = normalized_data.get("enablefql", False)
        queryname = normalized_data.get("name", None)
        return cls(querytext, refinementfilters, enablefql, queryname)

    def __str__(self):
        return f"QueryText: {self.querytext}, RefinementFilters: {self.refinementfilters}, EnableFQL: {self.enablefql}"
