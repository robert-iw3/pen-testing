class Options:
    def __init__(
        self,
        domain,
        rtfa,
        fedauth,
        query,
        output_file,
        save_files,
        max_threads,
        max_size,
        preset,
        headers,
        cookies,
        refinement_filters,
    ):
        self.domain = domain
        self.rtfa = rtfa
        self.fedauth = fedauth
        self.query = query
        self.output_file = output_file
        self.save_files = save_files
        self.max_threads = max_threads
        self.max_size = max_size
        self.preset = preset
        self.headers = headers
        self.cookies = cookies
        self.refinement_filters = refinement_filters
