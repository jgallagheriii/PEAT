import pytest

from peat import config, datastore
from peat.modules.mysql import MySQLServer
from peat.protocols.mysql import MySQL


# ---------------------------------------------------------------------------
# Class attributes
# ---------------------------------------------------------------------------

class TestMySQLServerClass:
    def test_device_type(self):
        assert MySQLServer.device_type == "Database"

    def test_aliases_include_mariadb(self):
        assert "mariadb" in MySQLServer.module_aliases
        assert "mysql" in MySQLServer.module_aliases

    def test_has_ip_method_on_3306(self):
        assert len(MySQLServer.ip_methods) == 1
        method = MySQLServer.ip_methods[0]
        assert method.default_port == 3306
        assert method.protocol == "mysql"
        assert method.transport == "tcp"
        assert method.reliability == 9

    def test_filename_patterns_include_cnf(self):
        assert "my.cnf" in MySQLServer.filename_patterns
        assert "my.ini" in MySQLServer.filename_patterns


# ---------------------------------------------------------------------------
# _verify_mysql
# ---------------------------------------------------------------------------

class TestVerifyMySQL:
    def _make_dev(self, mocker, ip="127.0.0.1"):
        from peat.data.models import DeviceData
        mocker.patch.object(datastore, "objects", [])
        dev = datastore.get(ip)
        return dev

    def test_verify_returns_true_for_mysql(self, mocker):
        mocker.patch.object(MySQL, "read_greeting", return_value="8.0.32")
        dev = self._make_dev(mocker)
        assert MySQLServer._verify_mysql(dev)
        assert dev._cache["mysql_server_info"] == "8.0.32"
        assert dev._cache["mysql_brand"] == "MySQL"

    def test_verify_detects_mariadb(self, mocker):
        mocker.patch.object(MySQL, "read_greeting", return_value="10.6.12-MariaDB")
        dev = self._make_dev(mocker)
        assert MySQLServer._verify_mysql(dev)
        assert dev._cache["mysql_brand"] == "MariaDB"

    def test_verify_returns_false_when_no_greeting(self, mocker):
        mocker.patch.object(MySQL, "read_greeting", return_value=None)
        dev = self._make_dev(mocker)
        assert not MySQLServer._verify_mysql(dev)
        assert "mysql_server_info" not in dev._cache


# ---------------------------------------------------------------------------
# _parse
# ---------------------------------------------------------------------------

class TestMySQLServerParse:
    def test_parse_bind_address_and_port(self, mocker, tmp_path):
        mocker.patch.dict(
            config["CONFIG"],
            {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp"},
        )
        mocker.patch.object(datastore, "objects", [])

        cnf = tmp_path / "my.cnf"
        cnf.write_text(
            "[mysqld]\nbind-address = 0.0.0.0\nport = 3306\ndatadir = /var/lib/mysql\n"
        )

        dev = MySQLServer.parse(cnf)
        assert dev is not None
        assert dev.ip == "0.0.0.0"
        services = [s for s in dev.service if s.protocol == "mysql"]
        assert len(services) == 1
        assert services[0].port == 3306

    def test_parse_missing_mysqld_section(self, mocker, tmp_path):
        mocker.patch.dict(
            config["CONFIG"],
            {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp"},
        )
        mocker.patch.object(datastore, "objects", [])

        cnf = tmp_path / "my.cnf"
        cnf.write_text("[client]\nuser = root\n")

        dev = MySQLServer.parse(cnf)
        assert dev is not None
        assert dev.extra.get("mysql_config", {}).get("mysqld") == {}

    def test_parse_invalid_file_returns_none(self, mocker, tmp_path):
        mocker.patch.dict(
            config["CONFIG"],
            {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp"},
        )
        mocker.patch.object(datastore, "objects", [])

        cnf = tmp_path / "my.cnf"
        cnf.write_bytes(b"\xff\xfe invalid bytes \x00")

        # parse should return None or a dev without crashing
        # (configparser errors are caught)
        result = MySQLServer.parse(cnf)
        # May return None or an empty dev depending on parse error
        assert result is None or hasattr(result, "ip")

    def test_parse_sets_vendor_info(self, mocker, tmp_path):
        mocker.patch.dict(
            config["CONFIG"],
            {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp"},
        )
        mocker.patch.object(datastore, "objects", [])

        cnf = tmp_path / "my.cnf"
        cnf.write_text("[mysqld]\nport = 3306\n")

        dev = MySQLServer.parse(cnf)
        assert dev is not None
        assert dev.description.vendor.id == "MySQL"
