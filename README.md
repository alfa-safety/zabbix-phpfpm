# Zabbix template et scripts client pour php-fpm



Voici comment sont organisé les configuration des différents php-fpm

    /etc/php-fpm54.d
    ├── tatasite.conf
    ├── totoweb.conf
    ├── tyty.conf
    └── vide54.conf
    /etc/php-fpm55.d
    ├── phpmyadmin.conf
    ├── titi.conf
    └── vide55.conf
    /etc/php-fpm56.d
    ├── tutu.conf
    └── vide56.conf



## Installation

### Coté serveur Serveur

Il suffit d'importer le template template-php-fpm.xml

## Coté client (serveur php-fpm)

Nous faisons la découverte gràce à la liste des Vhosts configurés dans virtualmin. Dans le cas où vous n'utiliser pas virtualmin à vous d'adapter la phase de discovery

Ajouter le fichier zabbix-zabbix-php-fpm.conf dans `/etc/zabbix/zabbix_agentd.d/`

Copie du fichier zabbix-php-fpm.py dans /usr/local/bin et un petit chmod +x et c'est parti.


Dans certains cas spécifique il est possible de mettre un fichier de configuration : `/etc/as/zabbix-php-fpm.json`



```
usage: zabbix-php-fpm.py [-h] [--discovery] [--port] [--host HOST] [--url URL]
                         [config] [command]

php-fpm status requester

positional arguments:
  config       config/port keyword
  command      config/port keyword

optional arguments:
  -h, --help   show this help message and exit
  --discovery  parse config
  --port       specify port instead of config name
  --host HOST  specify php-fpm host
  --url URL    defaut is /php-fpm-[port-number]

```

## ToDos

* Améliorer la doc.
* deposer le playbook ansible



##
