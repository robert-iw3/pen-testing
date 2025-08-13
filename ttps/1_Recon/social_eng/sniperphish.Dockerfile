FROM docker.io/ubuntu:jammy

RUN \
    apt-get install -y \
        bash \
        apache2 \
        php \
        libapache2-mod-php\
        php-mysql \
        php-imap \
        php-gd \
        mysql-server \
        git \
        gawk; \
    service apache2 start; \
    phpenmod mysqli; \
    phpenmod imap; \
    a2enmod rewrite; \
    touch /etc/apache2/sites-enabled/000-default.conf; \
    echo -e $'<Directory /var/www/html>\n    AllowOverride All\n</Directory>' | tee -a /etc/apache2/sites-enabled/000-default.conf; \
    service apache2 restart; \
    mysql_secure_installation; \
    echo -e $"create database sniperphish;\n\
        use sniperphish;\n\
        CREATE USER 'sp'@'localhost' IDENTIFIED BY 'pass123';\n\
        GRANT ALL PRIVILEGES ON sniperphish.* TO 'sp'@'localhost';\n\
        FLUSH PRIVILEGES;\n\
        exit" | mysql -u root -p ; \
    cd /var/www/html ; \
    git clone https://github.com/GemGeorge/SniperPhish.git . ; \
    chmod -R 644 *.* ; \
    chmod -R 777 spear ; \
    chmod 644 spear/*.*

EXPOSE 80/tcp
CMD [ "bash" ]
# http://localhost/install
# https://docs.sniperphish.com/
