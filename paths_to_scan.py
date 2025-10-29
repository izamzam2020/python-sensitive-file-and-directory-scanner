
paths_to_scan = [
    # Admin panels
    "admin", "admin/", "administrator", "administrator/", "admin1", "admin1/", "admin2", "admin2/", "admin_area", "admin_area/", "admin_panel", "admin_panel/",
    "admin/login", "admin/login/", "adminconsole", "adminconsole/", "admincontrol", "admincontrol/", "cpanel", "cpanel/", "backend", "backend/", "admincp", "admincp/",
    "admin-console", "admin-console/", "cmsadmin", "cmsadmin/", "root", "root/", "superuser", "superuser/", "system_admin", "system_admin/", "dashboard", "dashboard/",

    # Config & environment files
    ".env", "config.php", "config.json", "config.yml", "web.config", "dbconfig.php",
    "appsettings.json", "settings.py", "local.settings.json", "config.inc.php", "env.php",

    # Source control / internal folders
    ".git/", ".git/config", ".svn/", ".hg/", ".bzr/", ".idea/", ".vscode/", "CVS/", ".DS_Store",

    # Backup & archive files
    "backup", "backup/", "backups", "backups/", "db_backup", "db_backup/", "database.sql", "backup.sql", "dump.sql",
    "backup.tar.gz", "backup.zip", "db.sql", "site-backup", "site-backup/", "website_backup", "website_backup/", "backup.bk", "database_backup.sql",

    # Logs & debug output
    "debug.log", "error.log", "access.log", "server.log", "phpinfo.php", "logs/", "log/",

    # Uploads and temporary storage
    "uploads", "uploads/", "upload", "upload/", "tmp", "tmp/", "temp", "temp/", "files", "files/", "public_files", "public_files/", "private_files", "private_files/", "old", "old/",
      "secret", "secret/", "private", "private/", "old_site", "old_site/", "bk", "bk/","img", "img/", "images", "images/",

    # CMS specific files
    "wp-login.php", "wp-admin/", "wp-content/debug.log", "wp-config.php", "joomla/",
    "drupal/", "magento/", "prestashop/",

    # Credentials & keys
    "apikey.txt", "api_keys.json", "secrets.yml", "secret.key", "private.key", "id_rsa",
    "id_rsa.pub", "credentials.json", ".aws/credentials", ".npmrc", ".docker/config.json",

    # CI/CD / deployment
    ".gitlab-ci.yml", ".github/workflows/", ".travis.yml", "circle.yml", "jenkinsfile",
    "docker-compose.yml", "Procfile", "deploy.sh", "build.xml",

    # Dev & test
    "test/", "tests/", "testing/", "dev/", "development/", "staging/", "sandbox/", "demo/",
    "example/", "examples/", "docs/", "documentation/", "doc/",

    # Database & dumps
    "mysql/", "sql/", "db/", "database/", "dump/", "sqlite.db", "data.sql",

    # Misconfigurations
    ".htaccess", ".htpasswd", "crossdomain.xml", "clientaccesspolicy.xml", "index/",

    # Common leak patterns
    "passwords.txt", "pass.txt", "user.txt", "users.csv", "users.sql", "admin.txt",
    "account.txt", "account.db", "members/", "userlist.txt", "confidential/",

    # Rare but valid
    "old/", "old_site/", "bak/", "config~", "site.old", "archive/", "temp_site/", "v1/",
    "v2/", "final/", "final_backup/", "prod/", "production/", "live/", "new/"
]
