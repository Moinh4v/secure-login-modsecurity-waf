# Assignment: Secure Login Form with ModSecurity WAF

## Part 1: Setup and Exploitable Form

### Objective
1. Spin up an EC2 instance and install Nginx.
2. Create a login form with one input field and a submit button.
3. Ensure the form is exploitable via SQL injection.

### Steps

#### 1. Create an EC2 Instance
- Launch a **t2.micro** instance using AWS Free Tier.
- Use Ubuntu as the operating system.
- Open ports 80 (HTTP) and 22 (SSH) in the security group.

#### 2. Install Required Packages

**Install Nginx:**
```bash
sudo apt update
sudo apt install nginx -y
```

**Install PHP and MySQL:**
```bash
sudo apt install php php-fpm php-mysql -y
sudo apt install mysql-server -y
```

#### 3. Create a Login Form
- Place the form in the Nginx web directory (`/var/www/html/`).
- Sample vulnerable form (`page.html`):

```php
<?php
$servername = "localhost";
$username = "root";
$password = "test@123";
$dbname = "test_db";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$user_input = $_POST['username'];
$sql = "SELECT * FROM users WHERE username = '$user_input'";
$result = $conn->query($sql);

if ($result->num_rows > 0) {
    echo "Welcome, " . $user_input;
} else {
    echo "Invalid username.";
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerable Login</title>
</head>
<body>
    <h1>Login</h1>
    <form action="process_login_p1.php" method="POST">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>
        <button type="submit">Login</button>
    </form>
</body>
</html>

```

#### 4. Test the Vulnerability
- Populate the `test_db` database with a `users` table.
```
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL
);
```
- Exploit using an SQL injection payload like `' OR '1'='1` in the username field.

---

## Part 2: Mitigation with ModSecurity WAF

### Objective
Mitigate the SQL injection attack by configuring ModSecurity rules.

### Steps

#### 1. Install ModSecurity

**Install Dependencies:**
```bash
sudo apt update
sudo apt install -y apt-utils autoconf automake build-essential git libcurl4-openssl-dev libgeoip-dev liblmdb-dev libpcre++-dev libtool libxml2-dev libyajl-dev pkgconf wget zlib1g-dev
```

**Clone ModSecurity Repository:**
```bash
cd /usr/local/src/
sudo git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity
cd ModSecurity
sudo git submodule init
sudo git submodule update
sudo ./build.sh
sudo ./configure
sudo make
sudo make install
```

#### 2. Integrate ModSecurity with Nginx

**Clone ModSecurity-Nginx Connector:**
```bash
cd /usr/local/src/
sudo git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git
```

**Prepare for Nginx Module Build:**
```bash
nginx_version=$(nginx -v 2>&1 | sed 's/nginx version: nginx\///' | awk {'print $1'})
sudo wget http://nginx.org/download/nginx-$nginx_version.tar.gz
sudo tar zxvf nginx-$nginx_version.tar.gz
cd nginx-$nginx_version
sudo ./configure --with-compat --add-dynamic-module=../ModSecurity-nginx
sudo make modules
sudo cp objs/ngx_http_modsecurity_module.so /usr/lib/nginx/modules/
```

**Load ModSecurity Module in Nginx:**
```bash
echo 'load_module modules/ngx_http_modsecurity_module.so;' | sudo tee /etc/nginx/modules-available/modsecurity.conf
sudo ln -s /etc/nginx/modules-available/modsecurity.conf /etc/nginx/modules-enabled/modsecurity.conf
sudo mkdir -p /etc/nginx/modsecurity
```

**Configure ModSecurity:**
```bash
cd /usr/local/src/ModSecurity
sudo cp modsecurity.conf-recommended /etc/nginx/modsecurity/modsecurity.conf
sudo cp unicode.mapping /etc/nginx/modsecurity/
# NOTE: For ModSecurity to block the attacks, we need to enable `SecRuleEngine DetectionOnly` to `SecRuleEngine On` under `/etc/nginx/modsecurity/modsecurity.conf`
sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsecurity/modsecurity.conf
```

**Configure location-specific ModSecurity settings**
```
server {

    # Turn off ModSecurity for page1
    location = /process_login_p1.php { 
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
    }

    # Keep ModSecurity on for page2
    location = /process_login_p2.php {
        modsecurity on;
        modsecurity_rules_file /etc/nginx/modsecurity/modsecurity.conf;
        modsecurity_rules_file /etc/nginx/modsecurity.d/sql-injection.conf;
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
    }
}
```

### ModSecurity Rule Options

We can choose either **OWASP CRS Setup** or **Custom SQL Injection Rules:**

#### Option 1: OWASP CRS Setup
```bash
# Clone OWASP CRS
cd /etc/nginx/modsecurity/
sudo git clone https://github.com/coreruleset/coreruleset.git crs
cd crs
sudo cp crs-setup.conf.example crs-setup.conf

# Configure CRS in modsecurity.conf
echo 'Include /etc/nginx/modsecurity/crs/crs-setup.conf
Include /etc/nginx/modsecurity/crs/rules/*.conf' | sudo tee -a /etc/nginx/modsecurity/modsecurity.conf
```

Update Nginx configuration:
```nginx
location = /process_login_p2.php {
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsecurity/modsecurity.conf;
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
}
```

#### Option 2: Custom SQL Injection Rules
Create `mysql-injection.conf` under `/etc/nginx/modsecurity.d/`:
```bash
# Basic SQL Injection Protection
SecRule ARGS_NAMES|ARGS|XML:/* "@detectSQLi" \
    "id:942100,\
    phase:2,\
    deny,\
    status:403,\
    msg:'SQL Injection Attack Detected',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score=+%{tx.critical_anomaly_score}'"
```
Update Nginx configuration:
```nginx
location = /process_login_p2.php {
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsecurity/modsecurity.conf;
    modsecurity_rules_file /etc/nginx/modsecurity.d/sql-injection.conf;
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
}
```

#### 4. Restart Nginx
```bash
sudo nginx -t
sudo systemctl restart nginx
```


#### 5. Test the Mitigation
- **Vulnerable Page:** Test `page1.html` with payloads like:
  ```
  ' OR '1'='1
  admin' --
  admin' #
  ' UNION SELECT * FROM users --
  ```
  Observe SQL injection exploitation or failure.

- **Protected Page:** Test `page2.html` with the same payloads. Verify 403 responses and logged blocks in `/var/log/modsec_audit.log`.

modsecurity blocks and shows 403 error page

---