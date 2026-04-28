"""PEAT module for MySQL/MariaDB database servers."""

from __future__ import annotations

import configparser
from pathlib import Path

from peat import DeviceData, DeviceModule, datastore
from peat.api.identify_methods import IPMethod
from peat.data.models import Service
from peat.protocols.mysql import MySQL


class MySQLServer(DeviceModule):
    """
    MySQL and MariaDB database servers.

    Connects to a live MySQL/MariaDB instance to enumerate server version,
    databases, table schemas, user accounts, and key global variables.
    Also supports parsing MySQL config files (my.cnf / my.ini / mysqld.cnf).
    """

    device_type = "Database"
    vendor_id = "MySQL"
    vendor_name = "Oracle Corporation"
    brand = "MySQL"
    supported_models = ["MySQL", "MariaDB"]
    module_aliases = ["mysql", "mariadb", "mysql-server", "mariadb-server"]
    filename_patterns = ["my.cnf", "my.ini", "mysqld.cnf", "*mysql*.cnf", "*mysql*.ini"]

    default_options = {
        "mysql": {
            "port": 3306,
            "timeout": 10.0,
            "pull_schema": True,
            "pull_users": True,
            "pull_variables": True,
            "exclude_system_dbs": True,
        },
        "credentials": {
            "user": "root",
            "pass": "",
        },
    }

    _SYSTEM_DATABASES: frozenset[str] = frozenset(
        {"information_schema", "mysql", "performance_schema", "sys"}
    )

    # Global variables that are forensically interesting for OT/ICS context
    _INTERESTING_VARIABLES: tuple[str, ...] = (
        "version",
        "version_comment",
        "hostname",
        "datadir",
        "max_connections",
        "character_set_server",
        "collation_server",
        "sql_mode",
        "bind_address",
        "port",
        "log_error",
        "general_log_file",
        "slow_query_log_file",
    )

    @classmethod
    def _verify_mysql(cls, dev: DeviceData) -> bool:
        """Identify a MySQL/MariaDB server by reading its TCP greeting packet (no credentials needed)."""
        opts = dev.options.get("mysql", {})

        server_info = MySQL.read_greeting(
            ip=dev.ip,
            port=opts.get("port", 3306),
            timeout=opts.get("timeout", 10.0),
        )
        if server_info is None:
            return False

        dev._cache["mysql_server_info"] = server_info
        dev._cache["mysql_brand"] = (
            "MariaDB" if "mariadb" in server_info.lower() else "MySQL"
        )
        return True

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        """Enumerate server info, databases, schema, users, and global variables."""
        opts = dev.options.get("mysql", {})
        creds = dev.options.get("credentials", {})

        conn: MySQL | None = dev._cache.get("mysql_conn")
        if conn is None:
            conn = MySQL(
                ip=dev.ip,
                port=opts.get("port", 3306),
                username=creds.get("user", "root"),
                password=creds.get("pass", ""),
                timeout=opts.get("timeout", 10.0),
            )
            if not conn.connect():
                cls.log.error(f"Cannot connect to MySQL server at {dev.ip}")
                return False
            dev._cache["mysql_conn"] = conn

        brand: str = dev._cache.get("mysql_brand",
            "MariaDB" if "mariadb" in conn.server_info.lower() else "MySQL"
        )

        # Populate device identity fields
        dev.os.name = brand
        dev.os.version = conn.server_info
        if brand == "MariaDB":
            dev.description.vendor.name = "MariaDB Foundation"
            dev.description.brand = "MariaDB"
        else:
            dev.description.vendor.name = "Oracle Corporation"
            dev.description.brand = "MySQL"

        port = opts.get("port", 3306)
        svc = Service(
            port=port,
            protocol="mysql",
            transport="tcp",
            status="verified",
        )
        dev.store("service", svc, lookup="port")

        server_info = dev._cache.get("mysql_server_info") or conn.server_info
        result: dict = {"server_info": server_info, "brand": brand}

        if opts.get("pull_variables", True):
            variables: dict[str, str] = {}
            for var in cls._INTERESTING_VARIABLES:
                variables.update(conn.get_global_variables(like=var))
            result["variables"] = variables
            if not dev.hostname and "hostname" in variables:
                dev.hostname = variables["hostname"]

        if opts.get("pull_schema", True) or opts.get("pull_users", True):
            all_dbs = conn.get_databases()
            result["all_databases"] = all_dbs

            if opts.get("pull_schema", True):
                exclude = (
                    cls._SYSTEM_DATABASES
                    if opts.get("exclude_system_dbs", True)
                    else frozenset()
                )
                databases: dict = {}
                for db_name in all_dbs:
                    if db_name.lower() in exclude:
                        continue
                    tables: dict = {}
                    for table in conn.get_tables(db_name):
                        tables[table] = {
                            "approx_rows": conn.get_table_row_count(db_name, table)
                        }
                    databases[db_name] = {"tables": tables}
                result["databases"] = databases

        if opts.get("pull_users", True):
            users = conn.get_users()
            for u in users:
                u["grants"] = conn.get_grants(u["user"], u["host"])
                dev.related.user.add(u["user"])
            result["users"] = users

        result["process_list"] = conn.get_process_list()

        extra = conn.enumerate()
        if extra:
            result["extra_enumeration"] = extra

        dev.extra["mysql"] = result
        dev.write_file(result, "mysql_enumeration.json")

        cls.update_dev(dev)
        conn.disconnect()
        dev._cache.pop("mysql_conn", None)
        return True

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData | None:
        """Parse a MySQL server config file (my.cnf, my.ini, mysqld.cnf)."""
        if dev is None:
            dev = DeviceData()
            datastore.objects.append(dev)

        cfg = configparser.ConfigParser(strict=False)
        try:
            # Prepend a dummy section so options above the first header are captured
            cfg.read_string("[DEFAULT]\n" + file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return None

        mysqld = (
            {k: v for k, v in cfg.items("mysqld") if k not in cfg.defaults()}
            if "mysqld" in cfg.sections()
            else {}
        )
        result: dict = {"source_file": str(file), "mysqld": mysqld}

        if "bind-address" in mysqld and not dev.ip:
            dev.ip = mysqld["bind-address"]
        if "port" in mysqld:
            try:
                svc = Service(
                    port=int(mysqld["port"]),
                    configured_port=int(mysqld["port"]),
                    protocol="mysql",
                    transport="tcp",
                )
                dev.store("service", svc, lookup="port")
            except (ValueError, TypeError):
                pass

        dev.extra["mysql_config"] = result
        dev.write_file(result, "mysql_config.json")
        cls.update_dev(dev)
        return dev


MySQLServer.ip_methods = [
    IPMethod(
        name="MySQL server connect",
        description=str(MySQLServer._verify_mysql.__doc__).strip(),
        type="unicast_ip",
        identify_function=MySQLServer._verify_mysql,
        reliability=9,
        protocol="mysql",
        transport="tcp",
        default_port=3306,
    ),
]

__all__ = ["MySQLServer"]
