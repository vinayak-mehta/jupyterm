import json

from jupyter_client import KernelManager


def start_kernel():
    manager = KernelManager()
    manager.start_kernel()

    port_names = ["shell", "stdin", "iopub", "hb", "control"]
    ports = dict(list(zip(port_names, manager.ports)))

    kernel_info = {
        "key": manager.session.key.decode("utf-8"),
        "ports": ports,
    }

    return json.dumps(kernel_info)


if __name__ == "__main__":
    main()
