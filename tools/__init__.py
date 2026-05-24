
# use this to check whether or not real vs mock tools are called


import os
from config import MODE

# MODE = os.getenv("MODE", "real").lower()

if MODE == "mock":
    from tools.mock.network_tools import (
        scan_network,
        grab_banner,
        check_rtsp,
        test_credentials,
        capture_frame,
    )
else:
    from tools.real.network_tools import (
        scan_network,
        grab_banner,
        check_rtsp,
        test_credentials,
        capture_frame,
    )


