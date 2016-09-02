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


## ToDos

* Mettre un petit fichier de conf
* Améliorer la doc.
* deposer le playbook ansible



##
