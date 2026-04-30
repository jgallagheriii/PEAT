Changelog
*********

All notable changes to this project will be documented in this file.

The format is based on `Keep a Changelog <https://keepachangelog.com/en/1.1.0/>`__, and this project uses Calendar Versioning.


.. _known-issues:

Known Issues
============

- ``peat parse`` may have odd results when run with empty files (0 bytes)
- ControlLogix: IP, MAC, services, and other data from multiple communication modules on a single ControlLogix PLC aren't being added to ``host.module`` properly when de-duplication and merging occurs. Additionally, the module that gets selected as the "primary" to represent the device isn't fully deterministic and relies on whatever gets checked first. This issue occurs if a device has 2 or more communication modules *that are queried by PEAT*. For example, if a device has a EWEB at ``192.168.0.10`` and a EN2TR at ``192.168.0.11`` and both are interrogated by PEAT, then some data from the two modules may not be merged properly during the de-duplication process.
- ION module: Sometimes the ION module will mis-parse data scraped from Telnet. This results in a corrupted MAC address with a value that similar to ``"19:2.:16:8.:0.:10:05"`` and a IP that isn't an IP (e.g. ``"Settings"``). It's not consistently reproducible and occurs rarely, but when it occurs, the effects are quite obvious. If it occurs, the issue will be obvious in the following fields: ``interface.*``, ``related.ip``, ``related.mac``.

Resolved issues
---------------

None yet after open-sourcing!


Releases
========

TBD
---

Added
^^^^^

- ``peat/protocols/mysql.py``: New ``MySQL`` protocol class wrapping PyMySQL. Provides unauthenticated server fingerprinting via the MySQL initial handshake packet (``read_greeting``), authenticated connection and query helpers (``get_databases``, ``get_tables``, ``get_table_row_count``, ``get_users``, ``get_grants``, ``get_global_variables``, ``get_process_list``), and subclass hooks (``on_connected``, ``enumerate``) for device-specific extensions.
- ``peat pull --skip-scan``: New CLI flag that bypasses the scan phase and pulls directly from hosts defined in the config file. Per-host ``peat_module`` mappings in the ``hosts`` list are respected; a single ``-d`` device type can be used as a fallback. The ``-i``/``-f`` argument is no longer required when a config file with a ``hosts`` list is supplied.
- ``pull_skip_scan`` setting added to ``Configuration`` and both example config files.
- PyMySQL (``>=1.1.0``) added as a project dependency.

Changed
^^^^^^^

Removed
^^^^^^^

Other
^^^^^
