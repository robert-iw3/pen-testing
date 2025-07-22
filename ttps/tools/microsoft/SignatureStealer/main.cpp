#include "steal.h"

int main(int argc, char* argv[]) {

    if (argc != 3) {
        std::fprintf(stderr,
            "Usage: %s <signed_src> <target>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const std::string src = argv[1];
    const std::string dst = argv[2];

    hook_registry();

    if (!steal(src, dst)) {
        std::fprintf(stderr,
            "Failed to steal certificate from \"%s\" to \"%s\"\n",
            src.c_str(), dst.c_str());
        return EXIT_FAILURE;
    }

    std::printf("Certificate successfully copied from \"%s\" to \"%s\"\n",
        src.c_str(), dst.c_str());
    return EXIT_SUCCESS;
}