
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

    # Dotfiles and variants
    ".gitignore", ".editorconfig", ".env.example", ".env.local", ".env.production", ".env.development", ".env.backup", ".env.bak", ".env.old",

    # PHP/Laravel
    "server.php", "storage/logs/", "storage/app/", "storage/framework/", "bootstrap/cache/",

    # Symfony
    "var/log/", ".env.local.php",

    # Node / modern JS frameworks
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "node_modules/", ".next/", ".nuxt/", ".vercel/", "dist/", "build/",

    # PHP admin tools
    "phpmyadmin/", "adminer.php", "phppgadmin/",

    # Composer and artifacts
    "composer.json", "composer.lock", "vendor/", "sitemap.xml", "robots.txt",

    # API docs / debug endpoints
    "swagger", "swagger/", "api-docs", "api-docs/", "openapi.json", "openapi.yaml", "graphql", "graphql/", "_debugbar", "_debugbar/",

    # Well-known
    ".well-known/security.txt", ".well-known/openid-configuration", ".well-known/assetlinks.json", "apple-app-site-association",

    # Backup/file patterns (common names without wildcards)
    "db.bak", "site.bak", "config.bak", "index.php.bak", "database.tar.gz", "dump.tar.gz", "dump.zip", "backup_old.zip", "backup-old.zip",

    # Web server info endpoints
    "server-status", "server-info",
]
