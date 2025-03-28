# Ghidra Galore

This repo contains scaffolding to run the same analysis script in multiple
versions of Ghidra through Docker.

## Installation

Install Python3 dependencies using `pip install -r requirements.txt`.

## Usage

To build containers for all releases:

```bash
python3 run.py build-releases
```

To build a container for a specific release:

```bash
python3 run.py build-releases \
    --version 10.2
```

To import a file and create a project using a specific release:

```bash
python3 run.py import-file \
   --version 10.2 \
   /path/to/binary \
   output/
```

To run a script on a project from a specific release:

```
python3 run.py run-script \
   --version 10.2 \
   ghidra_scripts/ \
   output/ \
   PrintMetrics.java
```

In addition to the "equality" filters for versions, users may supply one or
more version expressions such as '>10.0,<11.0'.

See `python3 run.py --help` for more usage information.

## License

Copyright 2025 National Technology & Engineering Solutions of Sandia, LLC (NTESS).

Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain rights in this software.

Licensed under the [Apache License Version 2.0](LICENSE).
